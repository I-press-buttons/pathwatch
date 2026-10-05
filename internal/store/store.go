// Package store is the SQLite persistence layer: schema migrations, a single batching
// writer goroutine, continuous 1-minute aggregation, hourly rollups, retention and queries.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Options configure Open.
type Options struct {
	// Retention periods; 0 keeps data forever.
	RawRetention      time.Duration
	Rollup1mRetention time.Duration
	Rollup1hRetention time.Duration
	Logger            *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
	// FlushInterval is the writer's batch flush interval (default 1s).
	FlushInterval time.Duration
	// NoBackground disables the aggregation flush loop and retention job (tests drive them).
	NoBackground bool
}

type op struct {
	fn   func(tx *sql.Tx) error
	done chan error
}

// Store owns the database, the writer goroutine and the aggregator.
type Store struct {
	wdb  *sql.DB // single connection, used only by the writer goroutine (and vacuum)
	rdb  *sql.DB // read pool
	opts Options
	log  *slog.Logger
	now  func() time.Time

	ops       chan op
	quit      chan struct{}
	wdone     chan struct{}
	bgdone    chan struct{}
	retCancel context.CancelFunc // cancelled when Close begins; stops retention between chunks
	retdone   chan struct{}
	closeMu   sync.Once
	dropped   atomic.Int64
	lastWrit  atomic.Int64 // unix nanos of last successful writer commit

	// writer-goroutine state: only the writer's transactions (op closures) touch these
	stmts stmtCache // prepared statements of the writer connection
	hacc  hourAcc   // running 1h rollup of the current hour

	agg *Aggregator

	subMu sync.RWMutex
	subs  []func(MinuteBatch)

	pathMu sync.Mutex // guards destTTL cache

	certMu  sync.Mutex // guards the newest-certificate cache (certcache.go)
	certs   map[int64]certEntry
	certGen uint64 // bumped whenever entries are forgotten, so an in-flight lookup cannot resurrect one
}

// Open opens (creating if needed) the database at path, applies migrations and starts the
// writer. Call Close to flush and stop.
func Open(path string, o Options) (*Store, error) {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.FlushInterval == 0 {
		o.FlushInterval = time.Second
	}
	// The parent directory must exist; the caller creates it. Create the file owner-only
	// ourselves: SQLite gives the -wal and -shm files the mode of the main file, and would
	// otherwise create it 0644 & ~umask. An existing file keeps its mode.
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600); err == nil {
		f.Close()
	}
	dsn := func(readonly bool) string {
		q := url.Values{}
		// busy_timeout goes first so the pragmas below wait for locks instead of
		// failing with SQLITE_BUSY while the writer holds one.
		q.Add("_pragma", "busy_timeout(10000)")
		if readonly {
			// WAL mode and auto_vacuum are persistent and set by the writer
			// connection; re-issuing them here would need a write lock.
			q.Add("_pragma", "query_only(1)")
		} else {
			// auto_vacuum must be set before the first table is created; it is a no-op afterwards.
			q.Add("_pragma", "auto_vacuum(2)")
			q.Add("_pragma", "journal_mode(WAL)")
		}
		q.Add("_pragma", "synchronous(NORMAL)")
		q.Add("_pragma", "foreign_keys(0)")
		return "file:" + filepath.ToSlash(path) + "?" + q.Encode()
	}
	wdb, err := sql.Open("sqlite", dsn(false))
	if err != nil {
		return nil, err
	}
	wdb.SetMaxOpenConns(1)
	if err := wdb.Ping(); err != nil {
		wdb.Close()
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}
	if err := migrate(wdb); err != nil {
		wdb.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	rdb, err := sql.Open("sqlite", dsn(true))
	if err != nil {
		wdb.Close()
		return nil, err
	}
	// keep every pooled connection open: with the default of 2 idle ones, the UI's parallel
	// requests would keep closing and reopening connections
	rdb.SetMaxOpenConns(4)
	rdb.SetMaxIdleConns(4)
	retCtx, retCancel := context.WithCancel(context.Background())
	s := &Store{
		wdb: wdb, rdb: rdb, opts: o, log: o.Logger, now: o.Now,
		ops:       make(chan op, 8192),
		quit:      make(chan struct{}),
		wdone:     make(chan struct{}),
		bgdone:    make(chan struct{}),
		retCancel: retCancel,
		retdone:   make(chan struct{}),
		agg:       NewAggregator(),
		certs:     make(map[int64]certEntry),
	}
	s.lastWrit.Store(time.Now().UnixNano())
	go s.writer()
	if o.NoBackground {
		close(s.bgdone)
		close(s.retdone)
	} else {
		go s.background()
		go s.retention(retCtx)
	}
	return s, nil
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var cur int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_version`).Scan(&cur); err != nil {
		return err
	}
	for _, name := range names {
		ver, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("bad migration name %q", name)
		}
		if ver <= cur {
			continue
		}
		body, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version(version, applied_at) VALUES (?, ?)`, ver, time.Now().UnixMicro()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion returns the applied schema version.
func (s *Store) SchemaVersion() (int, error) {
	var v int
	err := s.rdb.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_version`).Scan(&v)
	return v, err
}

// Close stops background work, flushes the aggregator and the write queue and closes the DB.
func (s *Store) Close() error {
	var err error
	s.closeMu.Do(func() {
		close(s.quit)
		s.retCancel()
		<-s.bgdone
		<-s.retdone // retention deletes go through the writer, which must outlive them
		// flush everything still in memory, then stop the writer
		for _, mb := range s.agg.FlushAll() {
			s.persistMinute(mb)
		}
		close(s.ops)
		<-s.wdone
		s.stmts.close()
		err = errors.Join(s.rdb.Close(), s.wdb.Close())
	})
	return err
}

// Aggregator exposes the in-memory aggregator (tests).
func (s *Store) Aggregator() *Aggregator { return s.agg }

// Dropped reports how many queued writes were dropped because the writer fell behind.
func (s *Store) Dropped() int64 { return s.dropped.Load() }

// WriterAlive reports whether the writer committed (or was idle) recently.
func (s *Store) WriterAlive() bool {
	select {
	case <-s.wdone:
		return false
	default:
	}
	return time.Since(time.Unix(0, s.lastWrit.Load())) < 30*time.Second
}

// SubscribeMinutes registers fn to be called (from the aggregation goroutine) with every
// completed 1-minute batch. This is the seam for the analyzer and the alert engine.
func (s *Store) SubscribeMinutes(fn func(MinuteBatch)) {
	s.subMu.Lock()
	s.subs = append(s.subs, fn)
	s.subMu.Unlock()
}

// ---------------------------------------------------------------------------
// writer

const maxBatch = 500

func (s *Store) writer() {
	defer close(s.wdone)
	t := time.NewTicker(s.opts.FlushInterval)
	defer t.Stop()
	var batch []op
	flush := func() {
		if len(batch) == 0 {
			s.lastWrit.Store(time.Now().UnixNano())
			return
		}
		if err := s.runTx(batch); err != nil {
			s.log.Error("database write failed", "err", err, "ops", len(batch))
		} else {
			s.lastWrit.Store(time.Now().UnixNano())
		}
		batch = batch[:0]
	}
	for {
		select {
		case o, ok := <-s.ops:
			if !ok {
				flush()
				return
			}
			if o.done != nil {
				flush()
				err := s.runTx([]op{o})
				if err == nil {
					s.lastWrit.Store(time.Now().UnixNano())
				}
				o.done <- err
				continue
			}
			batch = append(batch, o)
			if len(batch) >= maxBatch {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

func (s *Store) runTx(batch []op) error {
	s.stmts.prepare(s.wdb) // outside the transaction: it would hold the only connection
	tx, err := s.wdb.Begin()
	if err != nil {
		return err
	}
	var first error
	for _, o := range batch {
		if err := o.fn(tx); err != nil {
			if first == nil {
				first = err
			}
			if o.done != nil {
				tx.Rollback()
				return err // reported to the synchronous caller
			}
			s.log.Warn("database statement failed", "err", err)
		}
	}
	if err := tx.Commit(); err != nil {
		s.hacc.reset() // everything it folded in was lost with the transaction
		return err
	}
	return nil
}

// enqueue queues a write to be batched. It never blocks the probing hot path: when the
// writer is badly behind the write is dropped and counted.
func (s *Store) enqueue(fn func(tx *sql.Tx) error) {
	defer func() { _ = recover() }() // send on closed channel during shutdown
	select {
	case s.ops <- op{fn: fn}:
	default:
		if s.dropped.Add(1)%100 == 1 {
			s.log.Error("database writer is behind; dropping writes", "dropped", s.dropped.Load())
		}
	}
}

// exec runs fn synchronously on the writer goroutine in its own transaction.
func (s *Store) exec(fn func(tx *sql.Tx) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("store closed")
		}
	}()
	done := make(chan error, 1)
	s.ops <- op{fn: fn, done: done}
	return <-done
}

// ---------------------------------------------------------------------------
// background loops

func (s *Store) background() {
	defer close(s.bgdone)
	flushT := time.NewTicker(time.Second)
	defer flushT.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-flushT.C:
			s.FlushDue(s.now())
		}
	}
}

// retentionFirstRun is the delay before the first retention run (a variable for tests).
var retentionFirstRun = 30 * time.Second

// retention runs the expiry job on its own goroutine, first retentionFirstRun after start and
// then hourly, so a long run never stalls the flush loop (minute rollups, hop classification,
// alerts).
func (s *Store) retention(ctx context.Context) {
	defer close(s.retdone)
	t := time.NewTimer(retentionFirstRun)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.Retain(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("retention failed", "err", err)
		}
		t.Reset(time.Hour)
	}
}

// graceBeforeFlush leaves time for slow probes (timeouts) to land in their minute.
const graceBeforeFlush = 5 * time.Second

// FlushDue persists and publishes every minute bucket that ended before now-grace.
func (s *Store) FlushDue(now time.Time) {
	for _, mb := range s.agg.Flush(now.Add(-graceBeforeFlush)) {
		s.persistMinute(mb)
		s.publishMinute(mb)
	}
}

func (s *Store) publishMinute(mb MinuteBatch) {
	s.subMu.RLock()
	subs := append([]func(MinuteBatch){}, s.subs...)
	s.subMu.RUnlock()
	for _, fn := range subs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Error("minute subscriber panicked", "panic", r)
				}
			}()
			fn(mb)
		}()
	}
}

// Sync blocks until every write queued so far has been committed.
func (s *Store) Sync() error { return s.exec(func(*sql.Tx) error { return nil }) }

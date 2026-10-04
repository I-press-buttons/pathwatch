package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ErrDuplicate is returned when a target name already exists.
var ErrDuplicate = errors.New("duplicate name")

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return us(t)
}

// ---------------------------------------------------------------------------
// raw samples

// RecordRound stores one round (one packed row) and folds it into the 1-minute aggregates.
func (s *Store) RecordRound(r Round) {
	if len(r.Hops) == 0 {
		return
	}
	s.agg.AddRound(r)
	blob := EncodeHops(r.Hops)
	n := len(r.Hops)
	s.enqueue(func(tx *sql.Tx) error {
		_, err := s.stmts.exec(tx, sqlInsertRound, r.TargetID, us(r.TS), r.PathID, n, blob)
		return err
	})
}

// RecordHTTP stores one HTTP sample.
func (s *Store) RecordHTTP(h HTTPSample) {
	s.agg.AddHTTP(h)
	s.noteCert(h)
	s.enqueue(func(tx *sql.Tx) error {
		_, err := s.stmts.exec(tx, sqlInsertHTTP,
			h.ProbeID, us(h.TS), nullStr(h.ResolvedIP), h.Status, h.DNS.Microseconds(), h.Connect.Microseconds(), h.TLS.Microseconds(),
			h.TTFB.Microseconds(), h.Transfer.Microseconds(), h.Total.Microseconds(), h.Redirects, nullTime(h.CertNotAfter), nullStr(h.Error))
		return err
	})
}

// RecordTCP stores one TCP connect sample.
func (s *Store) RecordTCP(t TCPSample) {
	s.agg.AddTCP(t)
	s.enqueue(func(tx *sql.Tx) error {
		_, err := s.stmts.exec(tx, sqlInsertTCP,
			t.ProbeID, us(t.TS), nullStr(t.ResolvedIP), t.Connect.Microseconds(), nullStr(t.Error))
		return err
	})
}

// RecordDNS stores one DNS probe sample.
func (s *Store) RecordDNS(d DNSSample) {
	s.agg.AddDNS(d)
	s.enqueue(func(tx *sql.Tx) error {
		_, err := s.stmts.exec(tx, sqlInsertDNS,
			d.ProbeID, us(d.TS), d.RCode, d.RTT.Microseconds(), nullStr(d.Error))
		return err
	})
}

// RecordGap stores a monitor gap ("no data") plus a matching event, and resets jitter state.
func (s *Store) RecordGap(targetID int64, from, to time.Time, reason string) {
	s.agg.ResetJitter(targetID)
	details, _ := json.Marshal(map[string]string{"reason": reason})
	s.enqueue(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO gaps(target_id, started_at, ended_at, reason) VALUES (?,?,?,?)`, targetID, us(from), us(to), reason); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO events(target_id, kind, ttl, started_at, ended_at, details) VALUES (?,?,?,?,?,?)`,
			targetID, "gap", nil, us(from), us(to), string(details))
		return err
	})
}

// ---------------------------------------------------------------------------
// writer statements

// The hot, repeated statements. database/sql does not cache prepared statements, so a plain
// tx.Exec parses its SQL every time; stmtCache prepares these once on the writer DB.
const (
	sqlInsertRound     = `INSERT OR REPLACE INTO icmp_rounds(target_id, ts, path_id, hop_count, results) VALUES (?,?,?,?,?)`
	sqlInsertHTTP      = `INSERT OR REPLACE INTO http_samples(probe_id, ts, resolved_ip, status, dns_us, connect_us, tls_us, ttfb_us, transfer_us, total_us, redirects, cert_not_after, error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
	sqlInsertTCP       = `INSERT OR REPLACE INTO tcp_samples(probe_id, ts, resolved_ip, connect_us, error) VALUES (?,?,?,?,?)`
	sqlInsertDNS       = `INSERT OR REPLACE INTO dns_samples(probe_id, ts, rcode, rtt_us, error) VALUES (?,?,?,?,?)`
	sqlInsertPathHop   = `INSERT OR REPLACE INTO path_hops(path_id, ttl, idx, address, share) VALUES (?,?,?,?,COALESCE((SELECT share FROM path_hops WHERE path_id=? AND ttl=? AND idx=?),1))`
	sqlUpdatePathShare = `UPDATE path_hops SET share=? WHERE path_id=? AND ttl=? AND idx=?`

	sqlInsertICMP1m  = `INSERT OR REPLACE INTO icmp_rollup_1m(target_id, bucket, ttl, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter, hist) VALUES (?,?,?,?,?,?,?,?,?,?,?)`
	sqlInsertICMP1h  = `INSERT OR REPLACE INTO icmp_rollup_1h(target_id, bucket, ttl, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter, hist) VALUES (?,?,?,?,?,?,?,?,?,?,?)`
	sqlInsertProbe1m = `INSERT OR REPLACE INTO probe_rollup_1m(probe_id, bucket, n, errors, dns_avg, connect_avg, tls_avg, ttfb_avg, transfer_avg, total_min, total_avg, total_max, hist, cert_not_after) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	sqlInsertProbe1h = `INSERT OR REPLACE INTO probe_rollup_1h(probe_id, bucket, n, errors, dns_avg, connect_avg, tls_avg, ttfb_avg, transfer_avg, total_min, total_avg, total_max, hist, cert_not_after) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`

	// one target's / probe's 1m rows of one hour, to seed the hour accumulator
	sqlICMPHourRows  = `SELECT bucket, ttl, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter, hist FROM icmp_rollup_1m WHERE target_id=? AND bucket >= ? AND bucket < ?`
	sqlProbeHourRows = `SELECT bucket, n, errors, dns_avg, connect_avg, tls_avg, ttfb_avg, transfer_avg, total_min, total_avg, total_max, hist, cert_not_after FROM probe_rollup_1m WHERE probe_id=? AND bucket >= ? AND bucket < ? ORDER BY bucket`
)

var writerSQL = []string{
	sqlInsertRound, sqlInsertHTTP, sqlInsertTCP, sqlInsertDNS, sqlInsertPathHop, sqlUpdatePathShare,
	sqlInsertICMP1m, sqlInsertICMP1h, sqlInsertProbe1m, sqlInsertProbe1h, sqlICMPHourRows, sqlProbeHourRows,
}

// stmtCache holds the writer connection's prepared statements. A statement prepared on the
// DB and bound to a transaction with tx.Stmt reuses the driver statement of the same
// connection, which the writer DB has exactly one of. Used only by the writer goroutine.
type stmtCache struct {
	m     map[string]*sql.Stmt // prepared on the DB
	tx    *sql.Tx              // the transaction bound holds statements for
	bound map[string]*sql.Stmt // m's statements bound to tx
}

// prepare prepares the writer statements once. It must run outside a transaction: the
// single writer connection is held by the transaction, so a Prepare inside one would wait forever.
func (c *stmtCache) prepare(db *sql.DB) {
	if c.m != nil {
		return
	}
	c.m = make(map[string]*sql.Stmt, len(writerSQL))
	for _, q := range writerSQL {
		if st, err := db.Prepare(q); err == nil {
			c.m[q] = st
		}
	}
}

// stmt returns q's cached statement bound to tx, or nil if q is not cached (or c is nil).
// tx.Stmt wraps the statement once per transaction, not once per call; database/sql closes
// the wrapper when the transaction ends.
func (c *stmtCache) stmt(tx *sql.Tx, q string) *sql.Stmt {
	if c == nil || c.m[q] == nil {
		return nil
	}
	if c.tx != tx {
		c.tx = tx
		c.bound = make(map[string]*sql.Stmt, len(c.m))
	}
	b := c.bound[q]
	if b == nil {
		b = tx.Stmt(c.m[q])
		c.bound[q] = b
	}
	return b
}

// exec runs q in tx with the cached statement; a statement that is not cached is executed
// directly.
func (c *stmtCache) exec(tx *sql.Tx, q string, args ...any) (sql.Result, error) {
	if st := c.stmt(tx, q); st != nil {
		return st.Exec(args...)
	}
	return tx.Exec(q, args...)
}

// query is exec for reads.
func (c *stmtCache) query(tx *sql.Tx, q string, args ...any) (*sql.Rows, error) {
	if st := c.stmt(tx, q); st != nil {
		return st.Query(args...)
	}
	return tx.Query(q, args...)
}

// close releases the statements; the writer must have stopped.
func (c *stmtCache) close() {
	c.tx, c.bound = nil, nil
	for q, st := range c.m {
		st.Close()
		delete(c.m, q)
	}
}

// ---------------------------------------------------------------------------
// rollups

// icmpCols is the column values of an ICMP rollup row. Min, avg, max and jitter are NULL
// when there are no replies (or no consecutive replies), which reads back as 0.
type icmpCols struct {
	n, lost               int64
	min, avg, max, jitter float64
	hasStats, hasJitter   bool
	hist                  []byte
}

func icmpColsOf(r *Roll) icmpCols {
	c := icmpCols{n: r.N, lost: r.Lost, hist: r.Hist.Encode()}
	if r.Replies() > 0 {
		c.hasStats = true
		c.min, c.max = r.Min, r.Max
		c.avg, _ = r.Avg()
	}
	if r.JitN > 0 {
		c.hasJitter = true
		c.jitter, _ = r.Jitter()
	}
	return c
}

// roll returns the Roll that reading the stored row back yields. The columns are lossy (the
// mean replaces the sum, jitter is rescaled to replies-1 pairs), so the 1h rows are merged
// from this form and not from the in-memory roll.
func (c icmpCols) roll() *Roll {
	return rollFromRow(c.n, c.lost, c.min, c.avg, c.max, c.jitter, c.hist)
}

func (s *Store) insertICMPRollRow(tx *sql.Tx, q string, target int64, bucket int64, ttl int, path int64, c icmpCols) error {
	var min, avg, max, jit any
	if c.hasStats {
		min, avg, max = c.min, c.avg, c.max
	}
	if c.hasJitter {
		jit = c.jitter
	}
	_, err := s.stmts.exec(tx, q, target, bucket, ttl, path, c.n, c.lost, min, avg, max, jit, c.hist)
	return err
}

// probeCols is the column values of a probe rollup row; the phase columns are NULL without
// successful samples.
type probeCols struct {
	n, errors                                           int64
	dns, connect, tls, ttfb, transfer, tmin, tavg, tmax float64
	hasStats                                            bool
	cert                                                int64
	hist                                                []byte
}

func probeColsOf(p *ProbeRoll) probeCols {
	c := probeCols{n: p.N, errors: p.Errors, cert: p.CertNotAfter, hist: p.Hist.Encode()}
	if p.OK() > 0 {
		c.hasStats = true
		c.dns, _ = p.AvgDNS()
		c.connect, _ = p.AvgConnect()
		c.tls, _ = p.AvgTLS()
		c.ttfb, _ = p.AvgTTFB()
		c.transfer, _ = p.AvgTransfer()
		c.tavg, _ = p.AvgTotal()
		c.tmin, c.tmax = p.TotalMin, p.TotalMax
	}
	return c
}

// roll is icmpCols.roll for probes.
func (c probeCols) roll() *ProbeRoll {
	return probeRollFromRow(c.n, c.errors, c.dns, c.connect, c.tls, c.ttfb, c.transfer, c.tmin, c.tavg, c.tmax, c.hist, c.cert)
}

func (s *Store) insertProbeRollRow(tx *sql.Tx, q string, probe int64, bucket int64, c probeCols) error {
	var dns, conn, tls, ttfb, tr, tmin, tavg, tmax any
	if c.hasStats {
		dns, conn, tls, ttfb, tr = c.dns, c.connect, c.tls, c.ttfb, c.transfer
		tmin, tavg, tmax = c.tmin, c.tavg, c.tmax
	}
	_, err := s.stmts.exec(tx, q, probe, bucket, c.n, c.errors, dns, conn, tls, ttfb, tr, tmin, tavg, tmax, c.hist, nullInt(c.cert))
	return err
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

const hourUs = int64(time.Hour / time.Microsecond)

// hourAcc is the running merge of the current hour's 1m rollup rows, so that persisting a
// minute folds just that minute in instead of re-reading and decoding every 1m row of the hour
// (quadratic over the hour). It is touched only by writer-goroutine closures (persistMinutes,
// DeleteTarget), which run one at a time, so it needs no lock. It is a cache of the 1m table:
// whenever it may disagree with it, reset or reseed it from the table.
type hourAcc struct {
	hour   int64 // µs, start of the accumulated hour
	icmp   map[int64]*icmpAcc
	probes map[int64]*probeAcc
}

// pathTTL identifies one cell (hop on a path) of a target within the hour.
type pathTTL struct {
	path int64
	ttl  int
}

// icmpAcc is one target's hour. It exists only once seeded from the 1m table.
type icmpAcc struct {
	last  int64 // newest 1m bucket (µs) this target has in the table for the hour
	rolls map[pathTTL]*Roll
	dirty map[pathTTL]bool // cells whose 1h row is not written yet
}

// probeAcc is one probe's hour.
type probeAcc struct {
	last  int64
	roll  *ProbeRoll
	dirty bool
}

func (a *hourAcc) reset() { *a = hourAcc{} }

func (a *hourAcc) start(hour int64) {
	a.hour = hour
	a.icmp = map[int64]*icmpAcc{}
	a.probes = map[int64]*probeAcc{}
}

// persistMinute writes a completed minute as 1m rollups and updates the affected 1h rollups.
func (s *Store) persistMinute(mb MinuteBatch) { s.persistMinutes([]MinuteBatch{mb}) }

// persistMinutes writes several minutes in one writer operation, folding each into its hour's
// accumulator and writing the touched 1h rows once per hour, inside the writer so reads see
// consistent data.
func (s *Store) persistMinutes(mbs []MinuteBatch) {
	n := 0
	for _, mb := range mbs {
		if len(mb.ICMP) > 0 || len(mb.Probes) > 0 {
			n++
		}
	}
	if n == 0 {
		return
	}
	s.enqueue(func(tx *sql.Tx) (err error) {
		defer func() {
			if err != nil {
				s.hacc.reset() // may hold minutes this transaction did not write
			}
		}()
		for _, mb := range mbs {
			if len(mb.ICMP) == 0 && len(mb.Probes) == 0 {
				continue
			}
			if err := s.persistMinuteTx(tx, mb); err != nil {
				return err
			}
		}
		return s.flushHour(tx)
	})
}

// persistMinuteTx inserts the minute's 1m rows and brings the hour accumulator up to date.
//
// A target (probe) is folded incrementally when it is seeded and the minute is newer than
// every 1m row it has for the hour: the insert then replaced nothing, and merging the rows in
// bucket order gives exactly what rebuilding the hour from the 1m table would. Otherwise (first
// minute of the hour or process, or a minute persisted again, e.g. after a late sample) it is
// reseeded from the table, which already holds this minute's rows.
func (s *Store) persistMinuteTx(tx *sql.Tx, mb MinuteBatch) error {
	hour := mb.Bucket.Truncate(time.Hour).UnixMicro()
	a := &s.hacc
	if a.icmp == nil || a.hour != hour {
		if err := s.flushHour(tx); err != nil {
			return err
		}
		a.start(hour)
	}
	bucket := mb.Bucket.UnixMicro()
	foldICMP := map[int64]bool{}
	for _, r := range mb.ICMP {
		ok, seen := foldICMP[r.TargetID]
		if !seen {
			t := a.icmp[r.TargetID]
			ok = t != nil && bucket > t.last
		}
		// the Aggregator never emits a cell twice in a minute, so duplicates are not checked
		foldICMP[r.TargetID] = ok && r.Bucket == bucket
	}
	foldProbe := map[int64]bool{}
	for _, p := range mb.Probes {
		_, seen := foldProbe[p.ProbeID]
		t := a.probes[p.ProbeID]
		foldProbe[p.ProbeID] = !seen && t != nil && bucket > t.last && p.Bucket == bucket
	}

	for _, r := range mb.ICMP {
		c := icmpColsOf(r.Roll)
		if err := s.insertICMPRollRow(tx, sqlInsertICMP1m, r.TargetID, r.Bucket, r.TTL, r.PathID, c); err != nil {
			return err
		}
		if foldICMP[r.TargetID] {
			t := a.icmp[r.TargetID]
			k := pathTTL{r.PathID, r.TTL}
			m := t.rolls[k]
			if m == nil {
				m = &Roll{}
				t.rolls[k] = m
			}
			m.Merge(c.roll())
			t.dirty[k] = true
			t.last = bucket
		}
	}
	for _, p := range mb.Probes {
		c := probeColsOf(p.Roll)
		if err := s.insertProbeRollRow(tx, sqlInsertProbe1m, p.ProbeID, p.Bucket, c); err != nil {
			return err
		}
		if foldProbe[p.ProbeID] {
			t := a.probes[p.ProbeID]
			t.roll.Merge(c.roll())
			t.dirty = true
			t.last = bucket
		}
	}

	for id, ok := range foldICMP {
		if !ok {
			if err := s.seedICMP(tx, id); err != nil {
				return err
			}
		}
	}
	for id, ok := range foldProbe {
		if !ok {
			if err := s.seedProbe(tx, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// seedICMP (re)builds one target's accumulator from its 1m rows of the current hour and marks
// all its cells for a 1h write.
func (s *Store) seedICMP(tx *sql.Tx, target int64) error {
	hour := s.hacc.hour
	rows, err := s.stmts.query(tx, sqlICMPHourRows, target, hour, hour+hourUs)
	if err != nil {
		return err
	}
	defer rows.Close()
	t := &icmpAcc{rolls: map[pathTTL]*Roll{}, dirty: map[pathTTL]bool{}}
	for rows.Next() {
		var b, p, n, lost int64
		var ttl int
		var mn, av, mx, jt sql.NullFloat64
		var hist []byte
		if err := rows.Scan(&b, &ttl, &p, &n, &lost, &mn, &av, &mx, &jt, &hist); err != nil {
			return err
		}
		k := pathTTL{p, ttl}
		m := t.rolls[k]
		if m == nil {
			m = &Roll{}
			t.rolls[k] = m
		}
		m.Merge(rollFromRow(n, lost, mn.Float64, av.Float64, mx.Float64, jt.Float64, hist))
		t.dirty[k] = true
		if b > t.last {
			t.last = b
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.hacc.icmp[target] = t
	return nil
}

// seedProbe is seedICMP for one probe.
func (s *Store) seedProbe(tx *sql.Tx, probe int64) error {
	hour := s.hacc.hour
	rows, err := s.stmts.query(tx, sqlProbeHourRows, probe, hour, hour+hourUs)
	if err != nil {
		return err
	}
	defer rows.Close()
	t := &probeAcc{roll: &ProbeRoll{}, dirty: true}
	for rows.Next() {
		var b, n, e int64
		var dns, conn, tls, ttfb, tr, tmin, tavg, tmax sql.NullFloat64
		var hist []byte
		var cert sql.NullInt64
		if err := rows.Scan(&b, &n, &e, &dns, &conn, &tls, &ttfb, &tr, &tmin, &tavg, &tmax, &hist, &cert); err != nil {
			return err
		}
		t.roll.Merge(probeRollFromRow(n, e, dns.Float64, conn.Float64, tls.Float64, ttfb.Float64, tr.Float64, tmin.Float64, tavg.Float64, tmax.Float64, hist, cert.Int64))
		if b > t.last {
			t.last = b
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.hacc.probes[probe] = t
	return nil
}

// flushHour writes the 1h rows of the accumulator's cells that changed since the last flush.
func (s *Store) flushHour(tx *sql.Tx) error {
	a := &s.hacc
	for id, t := range a.icmp {
		for k := range t.dirty {
			if err := s.insertICMPRollRow(tx, sqlInsertICMP1h, id, a.hour, k.ttl, k.path, icmpColsOf(t.rolls[k])); err != nil {
				return err
			}
			delete(t.dirty, k)
		}
	}
	for id, t := range a.probes {
		if !t.dirty {
			continue
		}
		if err := s.insertProbeRollRow(tx, sqlInsertProbe1h, id, a.hour, probeColsOf(t.roll)); err != nil {
			return err
		}
		t.dirty = false
	}
	return nil
}

func inClause(ids []int64) (string, []any) {
	if len(ids) == 0 {
		return "(NULL)", nil
	}
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i] = "?"
		args[i] = id
	}
	return "(" + strings.Join(ph, ",") + ")", args
}

// ---------------------------------------------------------------------------
// targets and probes

// TargetRow is a stored target.
type TargetRow struct {
	ID        int64
	Name      string
	Host      string
	Active    bool // false = removed from config
	Paused    bool
	Source    string // config | ui
	Spec      string // JSON: a UI target's definition, or a config target's UI override ("" = none)
	CreatedAt time.Time
	UpdatedAt time.Time
}

const targetCols = `id, name, host, active, source, paused, COALESCE(spec,''), created_at, updated_at`

func scanTarget(sc interface{ Scan(...any) error }) (TargetRow, error) {
	var t TargetRow
	var active, paused int
	var c, u int64
	if err := sc.Scan(&t.ID, &t.Name, &t.Host, &active, &t.Source, &paused, &t.Spec, &c, &u); err != nil {
		return t, err
	}
	t.Active, t.Paused = active != 0, paused != 0
	t.CreatedAt, t.UpdatedAt = fromUs(c), fromUs(u)
	return t, nil
}

// SyncConfigTarget upserts a config-file target by name. A UI target with the same name is
// taken over (the config wins, and the UI definition is dropped). The paused flag and a config
// target's UI override (spec) are preserved.
func (s *Store) SyncConfigTarget(name, host string) (TargetRow, error) {
	var out TargetRow
	err := s.exec(func(tx *sql.Tx) error {
		now := us(s.now())
		res, err := tx.Exec(`UPDATE targets SET host=?, active=1, spec=CASE WHEN source='ui' THEN NULL ELSE spec END, source='config', updated_at=? WHERE name=?`, host, now, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if _, err := tx.Exec(`INSERT INTO targets(name, host, active, source, paused, created_at, updated_at) VALUES (?,?,1,'config',0,?,?)`, name, host, now, now); err != nil {
				return err
			}
		}
		out, err = scanTarget(tx.QueryRow(`SELECT `+targetCols+` FROM targets WHERE name=?`, name))
		return err
	})
	return out, err
}

// DeactivateConfigTargetsExcept marks config targets that are not in names as removed.
func (s *Store) DeactivateConfigTargetsExcept(names []string) error {
	return s.exec(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT id, name FROM targets WHERE source='config' AND active=1`)
		if err != nil {
			return err
		}
		keep := map[string]bool{}
		for _, n := range names {
			keep[strings.ToLower(n)] = true
		}
		var drop []int64
		for rows.Next() {
			var id int64
			var n string
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return err
			}
			if !keep[strings.ToLower(n)] {
				drop = append(drop, id)
			}
		}
		rows.Close()
		for _, id := range drop {
			if _, err := tx.Exec(`UPDATE targets SET active=0, updated_at=? WHERE id=?`, us(s.now()), id); err != nil {
				return err
			}
		}
		return nil
	})
}

// CreateUITarget inserts a UI-managed target. It returns ErrDuplicate if the name exists.
func (s *Store) CreateUITarget(name, host, spec string) (TargetRow, error) {
	var out TargetRow
	err := s.exec(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM targets WHERE name=?`, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrDuplicate
		}
		now := us(s.now())
		res, err := tx.Exec(`INSERT INTO targets(name, host, active, source, paused, spec, created_at, updated_at) VALUES (?,?,1,'ui',0,?,?,?)`, name, host, spec, now, now)
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		out, err = scanTarget(tx.QueryRow(`SELECT `+targetCols+` FROM targets WHERE id=?`, id))
		return err
	})
	return out, err
}

// UpdateTarget changes the name, host and stored definition (spec, "" = none) of a target. It
// returns ErrDuplicate if another target already has the name, ErrNotFound if id is unknown.
func (s *Store) UpdateTarget(id int64, name, host, spec string) (TargetRow, error) {
	var out TargetRow
	err := s.exec(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM targets WHERE name=? AND id<>?`, name, id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrDuplicate
		}
		var sp any
		if spec != "" {
			sp = spec
		}
		res, err := tx.Exec(`UPDATE targets SET name=?, host=?, spec=?, updated_at=? WHERE id=?`, name, host, sp, us(s.now()), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		out, err = scanTarget(tx.QueryRow(`SELECT `+targetCols+` FROM targets WHERE id=?`, id))
		return err
	})
	return out, err
}

// Settings returns the settings edited in the web UI (key -> JSON).
func (s *Store) Settings() (map[string]string, error) {
	rows, err := s.rdb.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SetSetting stores a setting; an empty value deletes it.
func (s *Store) SetSetting(key, value string) error {
	return s.exec(func(tx *sql.Tx) error {
		if value == "" {
			_, err := tx.Exec(`DELETE FROM settings WHERE key=?`, key)
			return err
		}
		_, err := tx.Exec(`INSERT INTO settings(key, value, updated_at) VALUES (?,?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, value, us(s.now()))
		return err
	})
}

// SetTargetPaused changes the paused flag of a target.
func (s *Store) SetTargetPaused(id int64, paused bool) error {
	return s.exec(func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE targets SET paused=?, updated_at=? WHERE id=?`, boolInt(paused), us(s.now()), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// DeleteTarget removes a target and all of its data.
func (s *Store) DeleteTarget(id int64) error {
	return s.exec(func(tx *sql.Tx) error {
		s.hacc.reset() // target and probe ids can be reused; the hour accumulator must not outlive their rows
		var probeIDs []int64
		rows, err := tx.Query(`SELECT id FROM probes WHERE target_id=?`, id)
		if err != nil {
			return err
		}
		for rows.Next() {
			var p int64
			if err := rows.Scan(&p); err != nil {
				rows.Close()
				return err
			}
			probeIDs = append(probeIDs, p)
		}
		rows.Close()
		s.forgetCerts(probeIDs...) // ids can be reused; EnsureProbe forgets again for a new probe
		for _, p := range probeIDs {
			for _, t := range []string{"http_samples", "tcp_samples", "dns_samples", "probe_rollup_1m", "probe_rollup_1h"} {
				if _, err := tx.Exec(`DELETE FROM `+t+` WHERE probe_id=?`, p); err != nil {
					return err
				}
			}
		}
		stmts := []string{
			`DELETE FROM probes WHERE target_id=?1`,
			`DELETE FROM path_hops WHERE path_id IN (SELECT id FROM paths WHERE target_id=?1)`,
			`DELETE FROM paths WHERE target_id=?1`,
			`DELETE FROM icmp_rounds WHERE target_id=?1`,
			`DELETE FROM icmp_rollup_1m WHERE target_id=?1`,
			`DELETE FROM icmp_rollup_1h WHERE target_id=?1`,
			`DELETE FROM gaps WHERE target_id=?1`,
			`DELETE FROM events WHERE target_id=?1`,
			`DELETE FROM outbox WHERE alert_id IN (SELECT id FROM alerts WHERE target_id=?1)`,
			`DELETE FROM alerts WHERE target_id=?1`,
			`DELETE FROM silences WHERE target_id=?1`,
			`DELETE FROM targets WHERE id=?1`,
		}
		for _, q := range stmts {
			if _, err := tx.Exec(q, id); err != nil {
				return err
			}
		}
		return nil
	})
}

// EnsureProbe returns the id of the probe with (targetID, key), creating it if needed and
// refreshing its label. targetID 0 means "not bound to a target" (DNS probes).
func (s *Store) EnsureProbe(targetID int64, typ, key, label string) (int64, error) {
	var id int64
	err := s.exec(func(tx *sql.Tx) error {
		err := tx.QueryRow(`SELECT id FROM probes WHERE target_id=? AND key=?`, targetID, key).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			res, err := tx.Exec(`INSERT INTO probes(target_id, type, key, label) VALUES (?,?,?,?)`, targetID, typ, key, label)
			if err != nil {
				return err
			}
			id, _ = res.LastInsertId()
			s.forgetCerts(id) // the id may have belonged to a deleted probe
			return nil
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(`UPDATE probes SET label=?, type=? WHERE id=?`, label, typ, id)
		return err
	})
	return id, err
}

// ---------------------------------------------------------------------------
// paths

// NewPath ends the target's current path version (if any) and starts a new one.
func (s *Store) NewPath(targetID int64, ip string, destTTL int, ts time.Time) (int64, error) {
	var id int64
	err := s.exec(func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE paths SET ended_at=? WHERE target_id=? AND ended_at IS NULL`, us(ts), targetID); err != nil {
			return err
		}
		res, err := tx.Exec(`INSERT INTO paths(target_id, resolved_ip, dest_ttl, started_at) VALUES (?,?,?,?)`, targetID, ip, destTTL, us(ts))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// SetPathDestTTL records the destination TTL once it is known.
func (s *Store) SetPathDestTTL(pathID int64, ttl int) {
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE paths SET dest_ttl=? WHERE id=?`, ttl, pathID)
		return err
	})
}

// AddPathHop records a responder for (path, ttl) at a stable idx (0-based, first-seen order).
func (s *Store) AddPathHop(pathID int64, ttl, idx int, addr string) {
	s.enqueue(func(tx *sql.Tx) error {
		_, err := s.stmts.exec(tx, sqlInsertPathHop,
			pathID, ttl, idx, addr, pathID, ttl, idx)
		return err
	})
}

// ShareUpdate is one responder share.
type ShareUpdate struct {
	TTL   int
	Idx   int
	Share float64
}

// UpdatePathShares stores the fraction of replies per responder.
func (s *Store) UpdatePathShares(pathID int64, shares []ShareUpdate) {
	if len(shares) == 0 {
		return
	}
	s.enqueue(func(tx *sql.Tx) error {
		for _, sh := range shares {
			if _, err := s.stmts.exec(tx, sqlUpdatePathShare, sh.Share, pathID, sh.TTL, sh.Idx); err != nil {
				return err
			}
		}
		return nil
	})
}

// ---------------------------------------------------------------------------
// events

// Event is an annotation (state transition).
type Event struct {
	ID       int64
	TargetID *int64
	Kind     string
	TTL      *int
	From     time.Time
	To       *time.Time // nil = instant or still open
	Details  json.RawMessage
}

// Event kinds.
const (
	EventRouteChange      = "route_change"
	EventRateLimited      = "rate_limited"
	EventDegraded         = "degraded"
	EventICMPUnresponsive = "icmp_unresponsive"
	EventGap              = "gap"
	EventLocalOutage      = "local_outage"
)

// InsertEvent stores an event synchronously and returns its id.
func (s *Store) InsertEvent(e Event) (int64, error) {
	var id int64
	err := s.exec(func(tx *sql.Tx) error {
		var tid, ttl, to any
		if e.TargetID != nil {
			tid = *e.TargetID
		}
		if e.TTL != nil {
			ttl = *e.TTL
		}
		if e.To != nil {
			to = us(*e.To)
		}
		var det any
		if len(e.Details) > 0 {
			det = string(e.Details)
		}
		res, err := tx.Exec(`INSERT INTO events(target_id, kind, ttl, started_at, ended_at, details) VALUES (?,?,?,?,?,?)`, tid, e.Kind, ttl, us(e.From), to, det)
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// CloseEvent sets the end time of an open event.
func (s *Store) CloseEvent(id int64, end time.Time) {
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE events SET ended_at=? WHERE id=? AND ended_at IS NULL`, us(end), id)
		return err
	})
}

// ---------------------------------------------------------------------------
// ip_info

// IPInfo is cached enrichment for one address.
type IPInfo struct {
	Address   string
	Hostname  string
	ASN       int
	ASName    string
	UpdatedAt time.Time
}

// PutIPInfo upserts enrichment for an address.
func (s *Store) PutIPInfo(i IPInfo) {
	s.enqueue(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT OR REPLACE INTO ip_info(address, hostname, asn, as_name, updated_at) VALUES (?,?,?,?,?)`,
			i.Address, nullStr(i.Hostname), nullInt(int64(i.ASN)), nullStr(i.ASName), us(i.UpdatedAt))
		return err
	})
}

// LoadIPInfo returns all cached enrichment rows.
func (s *Store) LoadIPInfo() ([]IPInfo, error) {
	rows, err := s.rdb.Query(`SELECT address, COALESCE(hostname,''), COALESCE(asn,0), COALESCE(as_name,''), updated_at FROM ip_info`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPInfo
	for rows.Next() {
		var i IPInfo
		var u int64
		if err := rows.Scan(&i.Address, &i.Hostname, &i.ASN, &i.ASName, &u); err != nil {
			return nil, err
		}
		i.UpdatedAt = fromUs(u)
		out = append(out, i)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// alerts, outbox, silences (the engine itself is a later phase)

// Alert is one row of the alerts table.
type Alert struct {
	ID               int64
	TargetID         *int64
	Rule             string
	RuleType         string
	State            string // firing | resolved | suppressed
	SuppressedReason string // silence | maintenance | local_outage | cooldown
	StartedAt        time.Time
	EndedAt          *time.Time
	Value            *float64
	PeakValue        *float64
	Baseline         *float64
	Message          string
	DetailsJSON      string
}

// SaveAlert inserts the alert (ID == 0, ID is set) or updates it.
func (s *Store) SaveAlert(a *Alert) error {
	return s.exec(func(tx *sql.Tx) error {
		var tid, end, val, peak, base any
		if a.TargetID != nil {
			tid = *a.TargetID
		}
		if a.EndedAt != nil {
			end = us(*a.EndedAt)
		}
		if a.Value != nil {
			val = *a.Value
		}
		if a.PeakValue != nil {
			peak = *a.PeakValue
		}
		if a.Baseline != nil {
			base = *a.Baseline
		}
		if a.ID == 0 {
			res, err := tx.Exec(`INSERT INTO alerts(target_id, rule, rule_type, state, suppressed_reason, started_at, ended_at, value, peak_value, baseline, message, details_json)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, tid, a.Rule, a.RuleType, a.State, nullStr(a.SuppressedReason), us(a.StartedAt), end, val, peak, base, a.Message, nullStr(a.DetailsJSON))
			if err != nil {
				return err
			}
			a.ID, err = res.LastInsertId()
			return err
		}
		_, err := tx.Exec(`UPDATE alerts SET state=?, suppressed_reason=?, ended_at=?, value=?, peak_value=?, baseline=?, message=?, details_json=? WHERE id=?`,
			a.State, nullStr(a.SuppressedReason), end, val, peak, base, a.Message, nullStr(a.DetailsJSON), a.ID)
		return err
	})
}

// CreateSilence inserts a UI silence.
func (s *Store) CreateSilence(x Silence) (Silence, error) {
	err := s.exec(func(tx *sql.Tx) error {
		var tid, rule any
		if x.TargetID != nil {
			tid = *x.TargetID
		}
		if x.Rule != nil {
			rule = *x.Rule
		}
		res, err := tx.Exec(`INSERT INTO silences(target_id, rule, starts_at, ends_at, reason, created_by) VALUES (?,?,?,?,?,?)`,
			tid, rule, us(x.StartsAt), us(x.EndsAt), x.Reason, x.CreatedBy)
		if err != nil {
			return err
		}
		x.ID, err = res.LastInsertId()
		return err
	})
	return x, err
}

// DeleteSilence ends (deletes) a UI silence. It returns ErrNotFound for unknown ids.
func (s *Store) DeleteSilence(id int64) error {
	return s.exec(func(tx *sql.Tx) error {
		res, err := tx.Exec(`DELETE FROM silences WHERE id=?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

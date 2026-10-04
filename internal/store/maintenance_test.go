package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var retainNow = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

// openRetain opens a store that expires every tier: raw after 7 d, 1m rollups after 90 d and
// 1h rollups after 365 d.
func openRetain(t *testing.T, o Options) *Store {
	t.Helper()
	o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	o.Now = func() time.Time { return retainNow }
	o.RawRetention, o.Rollup1mRetention, o.Rollup1hRetention = 7*24*time.Hour, 90*24*time.Hour, 365*24*time.Hour
	s, err := Open(filepath.Join(t.TempDir(), "r.db"), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// planLines returns the EXPLAIN QUERY PLAN detail lines of q.
func planLines(t *testing.T, s *Store, q string, args ...any) []string {
	t.Helper()
	rows, err := s.rdb.Query(`EXPLAIN QUERY PLAN `+q, args...)
	if err != nil {
		t.Fatalf("explain %q: %v", q, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// Every retention statement must be a primary-key SEARCH; a SCAN restarts from the first row of
// the table on every chunk, which took seconds per run on a multi-GB database.
func TestRetainStatementsUsePrimaryKey(t *testing.T) {
	s := openRetain(t, Options{NoBackground: true})
	jobs := s.retainJobs(retainNow)
	if len(jobs) != 8 {
		t.Fatalf("%d retention jobs, want 8", len(jobs))
	}
	for _, j := range jobs {
		for name, q := range map[string]struct {
			sql  string
			args []any
		}{
			"next key": {j.nextKeySQL(), []any{0}},
			"delete":   {j.deleteSQL(), []any{1, 1}},
		} {
			plan := planLines(t, s, q.sql, q.args...)
			searched := false
			for _, line := range plan {
				switch {
				case strings.HasPrefix(line, "SCAN"):
					t.Errorf("%s %s: full scan in plan %q", j.table, name, plan)
				case strings.HasPrefix(line, "SEARCH"):
					searched = true
					if !strings.Contains(line, "USING PRIMARY KEY") {
						t.Errorf("%s %s: search without the primary key in plan %q", j.table, name, plan)
					}
				}
			}
			if !searched {
				t.Errorf("%s %s: no SEARCH in plan %q", j.table, name, plan)
			}
		}
	}
}

// retainSeed describes how rows of one table are inserted for TestRetainExpiresEveryTable.
type retainSeed struct {
	table, key, col string
	retention       time.Duration
	insert          func(tx *sql.Tx, key, ts int64) error
}

func TestRetainExpiresEveryTable(t *testing.T) {
	s := openRetain(t, Options{NoBackground: true})
	exec1 := func(q string, args ...any) func(tx *sql.Tx, key, ts int64) error {
		return func(tx *sql.Tx, key, ts int64) error {
			_, err := tx.Exec(q, append([]any{key, ts}, args...)...)
			return err
		}
	}
	// two rollup rows per bucket (ttl 1 and 2) check that a whole bucket goes at once
	rollup := func(table string) func(tx *sql.Tx, key, ts int64) error {
		return func(tx *sql.Tx, key, ts int64) error {
			for ttl := 1; ttl <= 2; ttl++ {
				if _, err := tx.Exec(`INSERT INTO `+table+`(target_id, bucket, ttl, path_id, n, lost) VALUES (?,?,?,5,1,0)`, key, ts, ttl); err != nil {
					return err
				}
			}
			return nil
		}
	}
	const day = 24 * time.Hour
	seeds := []retainSeed{
		{"icmp_rounds", "target_id", "ts", 7 * day, exec1(`INSERT INTO icmp_rounds(target_id, ts, path_id, hop_count, results) VALUES (?,?,5,0,x'')`)},
		{"http_samples", "probe_id", "ts", 7 * day, exec1(`INSERT INTO http_samples(probe_id, ts) VALUES (?,?)`)},
		{"tcp_samples", "probe_id", "ts", 7 * day, exec1(`INSERT INTO tcp_samples(probe_id, ts) VALUES (?,?)`)},
		{"dns_samples", "probe_id", "ts", 7 * day, exec1(`INSERT INTO dns_samples(probe_id, ts) VALUES (?,?)`)},
		{"icmp_rollup_1m", "target_id", "bucket", 90 * day, rollup("icmp_rollup_1m")},
		{"probe_rollup_1m", "probe_id", "bucket", 90 * day, exec1(`INSERT INTO probe_rollup_1m(probe_id, bucket, n, errors) VALUES (?,?,1,0)`)},
		{"icmp_rollup_1h", "target_id", "bucket", 365 * day, rollup("icmp_rollup_1h")},
		{"probe_rollup_1h", "probe_id", "bucket", 365 * day, exec1(`INSERT INTO probe_rollup_1h(probe_id, bucket, n, errors) VALUES (?,?,1,0)`)},
	}
	// Keys: 1 has expired and fresh rows; 4 only fresh rows; 7 only expired rows (and no target
	// or probe row exists for it, like data left behind by a deleted target); 9 is the one
	// with more expired rows than fit in a chunk. A row exactly at the cutoff is kept.
	type keyRows struct{ expired, fresh int }
	keys := map[int64]keyRows{1: {20, 5}, 4: {0, 5}, 7: {13, 0}, 9: {2*retainChunk + 17, 3}}
	for _, sd := range seeds {
		cutoff := us(retainNow.Add(-sd.retention))
		err := s.exec(func(tx *sql.Tx) error {
			for key, kr := range keys {
				for i := 0; i < kr.expired; i++ {
					if err := sd.insert(tx, key, cutoff-int64(i+1)*1_000_000); err != nil {
						return err
					}
				}
				for i := 0; i < kr.fresh; i++ {
					if err := sd.insert(tx, key, cutoff+int64(i)*1_000_000); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("seed %s: %v", sd.table, err)
		}
	}
	if err := s.Retain(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, sd := range seeds {
		cutoff := us(retainNow.Add(-sd.retention))
		per := 1
		if strings.HasPrefix(sd.table, "icmp_rollup") {
			per = 2
		}
		for key, kr := range keys {
			var expired, fresh int
			q := fmt.Sprintf(`SELECT COALESCE(SUM(%[3]s < ?2), 0), COALESCE(SUM(%[3]s >= ?2), 0) FROM %[1]s WHERE %[2]s = ?1`, sd.table, sd.key, sd.col)
			if err := s.rdb.QueryRow(q, key, cutoff).Scan(&expired, &fresh); err != nil {
				t.Fatalf("%s: %v", sd.table, err)
			}
			if expired != 0 || fresh != kr.fresh*per {
				t.Errorf("%s key %d: %d expired, %d fresh rows left; want 0 and %d", sd.table, key, expired, fresh, kr.fresh*per)
			}
		}
	}
	// a second run has nothing left to do
	if err := s.Retain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRetainCancelled(t *testing.T) {
	s := openRetain(t, Options{NoBackground: true})
	cutoff := us(retainNow.Add(-7 * 24 * time.Hour))
	if err := s.exec(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO icmp_rounds(target_id, ts, path_id, hop_count, results) VALUES (1,?,1,0,x'')`, cutoff-1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Retain(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Retain with a cancelled context: %v, want context.Canceled", err)
	}
	var n int
	s.rdb.QueryRow(`SELECT COUNT(*) FROM icmp_rounds`).Scan(&n)
	if n != 1 {
		t.Errorf("%d rows left, want the expired row untouched by the cancelled run", n)
	}
}

// Retention runs on its own goroutine and Close stops and waits for it.
func TestBackgroundRetentionRunsAndCloseWaits(t *testing.T) {
	old := retentionFirstRun
	retentionFirstRun = 10 * time.Millisecond
	t.Cleanup(func() { retentionFirstRun = old })

	s := openRetain(t, Options{})
	cutoff := us(retainNow.Add(-7 * 24 * time.Hour))
	if err := s.exec(func(tx *sql.Tx) error {
		for i := int64(1); i <= 50; i++ {
			if _, err := tx.Exec(`INSERT INTO icmp_rounds(target_id, ts, path_id, hop_count, results) VALUES (3,?,1,0,x'')`, cutoff-i); err != nil {
				return err
			}
		}
		_, err := tx.Exec(`INSERT INTO icmp_rounds(target_id, ts, path_id, hop_count, results) VALUES (3,?,1,0,x'')`, cutoff)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		s.rdb.QueryRow(`SELECT COUNT(*) FROM icmp_rounds`).Scan(&n)
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("background retention did not run: %d rows", n)
		}
		time.Sleep(10 * time.Millisecond)
	}
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return")
	}
	select {
	case <-s.retdone:
	default:
		t.Error("Close returned before the retention goroutine stopped")
	}
}

// A store that is closed before the first retention run must not wait for the 30 s delay.
func TestCloseDoesNotWaitForPendingRetention(t *testing.T) {
	s := openRetain(t, Options{})
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Close took %v", d)
	}
}

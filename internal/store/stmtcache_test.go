package store

import (
	"database/sql"
	"testing"
	"time"
)

func TestStmtCachePreparesAndCloses(t *testing.T) {
	s := openTest(t, time.Now)
	tr, pid := setupTarget(t, s)
	feed(s, tr.ID, pid, time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC), 5, 10)
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	if len(s.stmts.m) != len(writerSQL) {
		t.Fatalf("%d statements prepared, want %d", len(s.stmts.m), len(writerSQL))
	}
	// a statement that is not in the cache still runs
	err := s.exec(func(tx *sql.Tx) error {
		_, err := s.stmts.exec(tx, `UPDATE paths SET dest_ttl=dest_ttl WHERE id=?`, pid)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if len(s.stmts.m) != 0 {
		t.Errorf("%d statements left after Close", len(s.stmts.m))
	}
}

// Cached statements must keep working across transactions, across rollbacks and when the
// schema changes under them.
func TestStmtCacheAcrossTransactions(t *testing.T) {
	s := openTest(t, time.Now)
	tr, pid := setupTarget(t, s)
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	count := func() (n int) {
		s.rdb.QueryRow(`SELECT COUNT(*) FROM icmp_rounds WHERE target_id=?`, tr.ID).Scan(&n)
		return n
	}
	feed(s, tr.ID, pid, t0, 10, 10)
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	// a synchronous write that fails after using cached statements rolls its bound statements back
	err := s.exec(func(tx *sql.Tx) error {
		if _, err := s.stmts.exec(tx, sqlInsertRound, tr.ID, t0.Add(time.Hour).UnixMicro(), pid, 1, []byte{1, 0, 0}); err != nil {
			return err
		}
		return sql.ErrConnDone
	})
	if err == nil {
		t.Fatal("expected the failing write to report its error")
	}
	if n := count(); n != 10 {
		t.Fatalf("rows after a rolled-back write = %d, want 10", n)
	}
	feed(s, tr.ID, pid, t0.Add(time.Minute), 10, 10)
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 20 {
		t.Fatalf("rows after reusing the statements = %d, want 20", n)
	}
	// DDL invalidates prepared statements; SQLite re-prepares them transparently
	if err := s.exec(func(tx *sql.Tx) error {
		_, err := tx.Exec(`CREATE INDEX icmp_rounds_zz ON icmp_rounds (path_id)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	feed(s, tr.ID, pid, t0.Add(2*time.Minute), 10, 10)
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != 30 {
		t.Fatalf("rows after a schema change = %d, want 30", n)
	}
}

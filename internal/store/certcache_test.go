package store

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func certHTTP(probe int64, ts time.Time, notAfter time.Time) HTTPSample {
	return HTTPSample{ProbeID: probe, TS: ts, Status: 200, Total: 100 * time.Millisecond, CertNotAfter: notAfter}
}

func TestLatestCertCache(t *testing.T) {
	s := openTest(t, nil)
	tr, _ := s.SyncConfigTarget("cert", "cert.example")
	pid, err := s.EnsureProbe(tr.ID, "http", "http|GET|https://cert.example", "GET")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	exp1 := t0.Add(60 * 24 * time.Hour)

	// nothing recorded yet; the "none" answer is cached ...
	if c, ok := s.LatestCert(pid); ok {
		t.Fatalf("cert %v before any sample", c)
	}
	// ... and a recorded certificate becomes visible at once, without waiting for the writer
	s.RecordHTTP(certHTTP(pid, t0, exp1))
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(exp1) {
		t.Fatalf("cert after RecordHTTP: %v %v, want %v", c, ok, exp1)
	}
	// samples without a certificate (plain http, failed handshake) change nothing
	s.RecordHTTP(certHTTP(pid, t0.Add(time.Minute), time.Time{}))
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(exp1) {
		t.Errorf("cert after a sample without one: %v %v", c, ok)
	}
	// a newer sample wins, even with an earlier expiry (the certificate was replaced) ...
	exp2 := t0.Add(30 * 24 * time.Hour)
	s.RecordHTTP(certHTTP(pid, t0.Add(2*time.Minute), exp2))
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(exp2) {
		t.Errorf("cert after a newer sample: %v %v, want %v", c, ok, exp2)
	}
	// ... but one that arrives late does not override it
	s.RecordHTTP(certHTTP(pid, t0.Add(time.Second), exp1))
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(exp2) {
		t.Errorf("cert after an older sample: %v %v, want %v", c, ok, exp2)
	}

	// answered from memory: still there after the rows are gone from the database
	flushW(t, s)
	if err := s.exec(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM http_samples`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(exp2) {
		t.Errorf("cached cert after the rows were deleted: %v %v", c, ok)
	}
}

func TestLatestCertCachesNone(t *testing.T) {
	s := openTest(t, nil)
	tr, _ := s.SyncConfigTarget("plain", "plain.example")
	pid, _ := s.EnsureProbe(tr.ID, "http", "http|GET|http://plain.example", "GET")
	if _, ok := s.LatestCert(pid); ok {
		t.Fatal("cert for a probe without samples")
	}
	// a row that bypasses RecordHTTP is not seen: the database is asked once per probe
	if err := s.exec(func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO http_samples(probe_id, ts, cert_not_after) VALUES (?,1,2)`, pid)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if c, ok := s.LatestCert(pid); ok {
		t.Errorf("cert %v: the lookup was not cached", c)
	}
}

// A fresh process has an empty cache: it falls back to the raw samples, then to the 1-minute
// rollups once the raw samples have expired.
func TestLatestCertLoadsFromDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.db")
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := t0.Add(time.Hour)
	open := func() *Store {
		s, err := Open(path, Options{NoBackground: true, FlushInterval: 20 * time.Millisecond, Now: func() time.Time { return clock }})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := open()
	tr, _ := s.SyncConfigTarget("cert", "cert.example")
	pid, _ := s.EnsureProbe(tr.ID, "http", "http|GET|https://cert.example", "GET")
	exp := t0.Add(45 * 24 * time.Hour)
	for i := 0; i < 4; i++ {
		s.RecordHTTP(certHTTP(pid, t0.Add(time.Duration(i)*30*time.Second), exp))
	}
	s.FlushDue(clock) // writes the 1-minute rollup
	flushW(t, s)
	s.Close()

	s = open()
	defer s.Close()
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(exp) {
		t.Fatalf("cert from raw samples: %v %v, want %v", c, ok, exp)
	}
	s.Close()

	s = open()
	defer s.Close()
	if err := s.exec(func(tx *sql.Tx) error {
		_, err := tx.Exec(`DELETE FROM http_samples`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(exp) {
		t.Fatalf("cert from rollups: %v %v, want %v", c, ok, exp)
	}
}

func TestLatestCertForgottenOnDeleteAndRecreate(t *testing.T) {
	s := openTest(t, nil)
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	exp := t0.Add(60 * 24 * time.Hour)
	tr, _ := s.SyncConfigTarget("gone", "gone.example")
	pid, _ := s.EnsureProbe(tr.ID, "http", "http|GET|https://gone.example", "GET")
	s.RecordHTTP(certHTTP(pid, t0, exp))
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(exp) {
		t.Fatalf("cert: %v %v", c, ok)
	}

	// deleting the target forgets its probes' certificates
	if err := s.DeleteTarget(tr.ID); err != nil {
		t.Fatal(err)
	}
	if c, ok := s.LatestCert(pid); ok {
		t.Fatalf("cert %v survived DeleteTarget", c)
	}

	// SQLite reuses the id of the highest deleted row; the new probe must not inherit the cert
	tr2, _ := s.SyncConfigTarget("again", "again.example")
	pid2, err := s.EnsureProbe(tr2.ID, "http", "http|GET|http://again.example", "GET")
	if err != nil {
		t.Fatal(err)
	}
	if pid2 != pid {
		t.Skipf("probe id %d not reused (got %d); the scenario below needs a reused id", pid, pid2)
	}
	if c, ok := s.LatestCert(pid2); ok {
		t.Errorf("re-created probe inherited cert %v", c)
	}
}

// EnsureProbe forgets by itself: a stale entry for the id it hands out is dropped.
func TestLatestCertForgottenByEnsureProbe(t *testing.T) {
	s := openTest(t, nil)
	tr, _ := s.SyncConfigTarget("fresh", "fresh.example")
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	s.noteCert(certHTTP(1, t0, t0.Add(time.Hour))) // stale entry for the id the first probe will get
	if c, ok := s.LatestCert(1); !ok {
		t.Fatalf("setup: no cached cert (%v)", c)
	}
	pid, err := s.EnsureProbe(tr.ID, "http", "http|GET|http://fresh.example", "GET")
	if err != nil {
		t.Fatal(err)
	}
	if pid != 1 {
		t.Fatalf("first probe id = %d, want 1", pid)
	}
	if c, ok := s.LatestCert(pid); ok {
		t.Errorf("new probe has cert %v", c)
	}
	// refreshing the label of an existing probe keeps what was learned about it
	exp := t0.Add(24 * time.Hour)
	s.RecordHTTP(certHTTP(pid, t0, exp))
	if _, err := s.EnsureProbe(tr.ID, "http", "http|GET|http://fresh.example", "renamed"); err != nil {
		t.Fatal(err)
	}
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(exp) {
		t.Errorf("cert lost on EnsureProbe of an existing probe: %v %v", c, ok)
	}
}

func TestLatestCertConcurrent(t *testing.T) {
	s := openTest(t, nil)
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(2)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.RecordHTTP(certHTTP(int64(g%2+1), t0.Add(time.Duration(i)*time.Second), t0.Add(time.Duration(i)*time.Hour)))
			}
		}(g)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.LatestCert(int64(g%2 + 1))
				if i%50 == 0 {
					s.forgetCerts(int64(g%2 + 1))
				}
			}
		}(g)
	}
	wg.Wait()
}

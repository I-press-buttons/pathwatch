package store

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// oracleRebuildHour is the original hour rollup: it recomputes the 1h rows of the given
// targets/probes for the hour starting at hour from all their 1m rows. The incremental
// accumulator must leave exactly these rows in the 1h tables.
func oracleRebuildHour(s *Store, tx *sql.Tx, hour int64, targets, probes []int64) error {
	end := hour + int64(time.Hour/time.Microsecond)
	if len(targets) > 0 {
		in, args := inClause(targets)
		rows, err := tx.Query(`SELECT target_id, ttl, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter, hist FROM icmp_rollup_1m
			WHERE bucket >= ? AND bucket < ? AND target_id IN `+in, append([]any{hour, end}, args...)...)
		if err != nil {
			return err
		}
		type k struct {
			t, p int64
			ttl  int
		}
		merged := map[k]*Roll{}
		for rows.Next() {
			var t, p, n, lost int64
			var ttl int
			var mn, av, mx, jt sql.NullFloat64
			var hist []byte
			if err := rows.Scan(&t, &ttl, &p, &n, &lost, &mn, &av, &mx, &jt, &hist); err != nil {
				rows.Close()
				return err
			}
			key := k{t, p, ttl}
			m := merged[key]
			if m == nil {
				m = &Roll{}
				merged[key] = m
			}
			m.Merge(rollFromRow(n, lost, mn.Float64, av.Float64, mx.Float64, jt.Float64, hist))
		}
		rows.Close()
		for key, r := range merged {
			if err := s.insertICMPRollRow(tx, sqlInsertICMP1h, key.t, hour, key.ttl, key.p, icmpColsOf(r)); err != nil {
				return err
			}
		}
	}
	if len(probes) > 0 {
		in, args := inClause(probes)
		rows, err := tx.Query(`SELECT probe_id, n, errors, dns_avg, connect_avg, tls_avg, ttfb_avg, transfer_avg, total_min, total_avg, total_max, hist, cert_not_after FROM probe_rollup_1m
			WHERE bucket >= ? AND bucket < ? AND probe_id IN `+in+` ORDER BY bucket`, append([]any{hour, end}, args...)...)
		if err != nil {
			return err
		}
		merged := map[int64]*ProbeRoll{}
		for rows.Next() {
			var id, n, e int64
			var dns, conn, tls, ttfb, tr, tmin, tavg, tmax sql.NullFloat64
			var hist []byte
			var cert sql.NullInt64
			if err := rows.Scan(&id, &n, &e, &dns, &conn, &tls, &ttfb, &tr, &tmin, &tavg, &tmax, &hist, &cert); err != nil {
				rows.Close()
				return err
			}
			m := merged[id]
			if m == nil {
				m = &ProbeRoll{}
				merged[id] = m
			}
			m.Merge(probeRollFromRow(n, e, dns.Float64, conn.Float64, tls.Float64, ttfb.Float64, tr.Float64, tmin.Float64, tavg.Float64, tmax.Float64, hist, cert.Int64))
		}
		rows.Close()
		for id, p := range merged {
			if err := s.insertProbeRollRow(tx, sqlInsertProbe1h, id, hour, probeColsOf(p)); err != nil {
				return err
			}
		}
	}
	return nil
}

// dumpTable returns every row of a table, one formatted string each, in primary key order.
// Floats print in their shortest round-trip form, so equal strings mean bit-identical values.
func dumpTable(t *testing.T, s *Store, table, order string) []string {
	t.Helper()
	rows, err := s.rdb.Query(`SELECT * FROM ` + table + ` ORDER BY ` + order)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []string
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for i, v := range vals {
			if bs, ok := v.([]byte); ok {
				v = fmt.Sprintf("%x", bs)
			}
			fmt.Fprintf(&b, "%s=%v ", cols[i], v)
		}
		out = append(out, b.String())
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// hourRows is a snapshot of both 1h tables.
func hourRows(t *testing.T, s *Store) (icmp, probe []string) {
	t.Helper()
	return dumpTable(t, s, "icmp_rollup_1h", "target_id, bucket, ttl, path_id"), dumpTable(t, s, "probe_rollup_1h", "probe_id, bucket")
}

// assertHoursMatchRebuild rebuilds the given hour from the 1m rows with the original algorithm
// and requires that the 1h tables did not change, i.e. that the incremental rows were already
// identical. It also requires some 1h rows to exist, so an empty table cannot pass.
func assertHoursMatchRebuild(t *testing.T, s *Store, what string, hours []time.Time, targets, probes []int64) {
	t.Helper()
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	ic0, pr0 := hourRows(t, s)
	if len(targets) > 0 && len(ic0) == 0 || len(probes) > 0 && len(pr0) == 0 {
		t.Fatalf("%s: no 1h rows (icmp %d, probe %d)", what, len(ic0), len(pr0))
	}
	for _, h := range hours {
		hu := h.Truncate(time.Hour).UnixMicro()
		if err := s.exec(func(tx *sql.Tx) error { return oracleRebuildHour(s, tx, hu, targets, probes) }); err != nil {
			t.Fatal(err)
		}
	}
	ic1, pr1 := hourRows(t, s)
	diff := func(kind string, a, b []string) {
		if len(a) != len(b) {
			t.Fatalf("%s: %s row count %d vs rebuilt %d", what, kind, len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("%s: %s row differs from a full rebuild\n incremental: %s\n rebuilt:     %s", what, kind, a[i], b[i])
			}
		}
	}
	diff("icmp", ic0, ic1)
	diff("probe", pr0, pr1)
}

func openAt(t *testing.T, path string, now func() time.Time) *Store {
	t.Helper()
	s, err := Open(path, Options{NoBackground: true, FlushInterval: 20 * time.Millisecond, Now: now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// hourFixture is a few targets and probes with varied traffic, fed through the real
// aggregator one minute at a time.
type hourFixture struct {
	t       *testing.T
	s       *Store
	rng     *rand.Rand
	targets []int64
	paths   map[int64]int64 // target -> current path id
	probes  []int64
	http    int64
	tcp     int64
}

func newHourFixture(t *testing.T, s *Store, seed int64) *hourFixture {
	t.Helper()
	f := &hourFixture{t: t, s: s, rng: rand.New(rand.NewSource(seed)), paths: map[int64]int64{}}
	for i := 0; i < 3; i++ {
		tr, err := s.SyncConfigTarget(fmt.Sprintf("tgt%d", i), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		pid, err := s.NewPath(tr.ID, "127.0.0.1", 3, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		f.targets = append(f.targets, tr.ID)
		f.paths[tr.ID] = pid
	}
	var err error
	if f.http, err = s.EnsureProbe(f.targets[0], "http", "http:x", "x"); err != nil {
		t.Fatal(err)
	}
	if f.tcp, err = s.EnsureProbe(f.targets[1], "tcp", "tcp:x", "x"); err != nil {
		t.Fatal(err)
	}
	f.probes = []int64{f.http, f.tcp}
	return f
}

// feedMinute records one minute of traffic in the minute starting at m (30 rounds per target,
// an HTTP sample every 15 s, a TCP sample every 10 s) without flushing it.
func (f *hourFixture) feedMinute(m time.Time) {
	for i := 0; i < 30; i++ {
		ts := m.Add(time.Duration(i) * 2 * time.Second)
		for _, tid := range f.targets {
			hops := make([]Hop, 3)
			for h := range hops {
				hops[h] = Hop{TTL: h + 1, Status: 2, RTT: time.Duration((1 + f.rng.Float64()*20*float64(h+1)) * float64(time.Millisecond)), Resp: 1}
				if f.rng.Intn(12) == 0 {
					hops[h] = Hop{TTL: h + 1}
				}
			}
			f.s.RecordRound(Round{TargetID: tid, TS: ts, PathID: f.paths[tid], Hops: hops})
		}
		if i%5 == 0 {
			h := HTTPSample{ProbeID: f.http, TS: ts, Status: 200, DNS: time.Millisecond, Connect: 3 * time.Millisecond, TTFB: time.Duration(10+f.rng.Intn(30)) * time.Millisecond, Total: time.Duration(20+f.rng.Intn(80)) * time.Millisecond,
				CertNotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Hour)}
			if f.rng.Intn(6) == 0 {
				h.Error = "timeout"
			}
			f.s.RecordHTTP(h)
		}
		if i%3 == 0 {
			c := TCPSample{ProbeID: f.tcp, TS: ts, Connect: time.Duration(1+f.rng.Intn(20)) * time.Millisecond}
			if f.rng.Intn(8) == 0 {
				c.Error = "refused"
			}
			f.s.RecordTCP(c)
		}
	}
}

// persist flushes every minute that ended before the end of minute m and waits for the writes.
func (f *hourFixture) persist(m time.Time) {
	f.t.Helper()
	f.s.FlushDue(m.Add(time.Minute + graceBeforeFlush))
	if err := f.s.Sync(); err != nil {
		f.t.Fatal(err)
	}
}

func TestHourRollIncrementalMatchesRebuild(t *testing.T) {
	h0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	s := openTest(t, func() time.Time { return h0.Add(2 * time.Hour) })
	f := newHourFixture(t, s, 1)
	for m := 0; m < 60; m++ {
		min := h0.Add(time.Duration(m) * time.Minute)
		if m == 30 { // a route change mid-hour: new (path, ttl) cells appear
			pid, err := s.NewPath(f.targets[1], "127.0.0.2", 3, min)
			if err != nil {
				t.Fatal(err)
			}
			f.paths[f.targets[1]] = pid
		}
		f.feedMinute(min)
		f.persist(min)
		assertHoursMatchRebuild(t, s, fmt.Sprintf("after minute %d", m), []time.Time{h0}, f.targets, f.probes)
	}
	// every minute was folded exactly once
	var n int64
	if err := s.rdb.QueryRow(`SELECT SUM(n) FROM icmp_rollup_1h WHERE target_id=?`, f.targets[0]).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 60*30*3 {
		t.Errorf("1h n = %d, want %d", n, 60*30*3)
	}
	// the next hour starts a fresh accumulator and leaves the finished hour alone
	min := h0.Add(time.Hour)
	f.feedMinute(min)
	f.persist(min)
	assertHoursMatchRebuild(t, s, "second hour", []time.Time{h0, min}, f.targets, f.probes)
	var hours int
	s.rdb.QueryRow(`SELECT COUNT(DISTINCT bucket) FROM icmp_rollup_1h`).Scan(&hours)
	if hours != 2 {
		t.Errorf("hours with rows = %d, want 2", hours)
	}
}

func TestHourRollLateMinuteRepersist(t *testing.T) {
	h0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	s := openTest(t, func() time.Time { return h0.Add(2 * time.Hour) })
	f := newHourFixture(t, s, 2)
	minute := func(m int) time.Time { return h0.Add(time.Duration(m) * time.Minute) }
	for m := 0; m <= 12; m++ {
		f.feedMinute(minute(m))
		f.persist(minute(m))
	}
	assertHoursMatchRebuild(t, s, "before late samples", []time.Time{h0}, f.targets, f.probes)

	// late samples for an older minute: its 1m rows are replaced and the hour must follow
	f.s.RecordRound(Round{TargetID: f.targets[0], TS: minute(5).Add(7 * time.Second), PathID: f.paths[f.targets[0]],
		Hops: []Hop{{TTL: 1, Status: 2, RTT: 4 * time.Millisecond, Resp: 1}, {TTL: 2, Status: 2, RTT: 5 * time.Millisecond, Resp: 1}, {TTL: 3}}})
	f.s.RecordTCP(TCPSample{ProbeID: f.tcp, TS: minute(5).Add(9 * time.Second), Connect: 3 * time.Millisecond})
	f.persist(minute(5))
	assertHoursMatchRebuild(t, s, "late sample, minute 5", []time.Time{h0}, f.targets, f.probes)

	// a late sample for the newest folded minute
	f.s.RecordRound(Round{TargetID: f.targets[1], TS: minute(12).Add(40 * time.Second), PathID: f.paths[f.targets[1]],
		Hops: []Hop{{TTL: 1, Status: 2, RTT: 6 * time.Millisecond, Resp: 1}}})
	f.persist(minute(12))
	assertHoursMatchRebuild(t, s, "late sample, newest minute", []time.Time{h0}, f.targets, f.probes)

	// the same minute persisted twice with identical content (a minute re-emitted as is)
	mb := MinuteBatch{Bucket: minute(12), ICMP: []ICMPRow{{TargetID: f.targets[2], TTL: 1, PathID: f.paths[f.targets[2]], Bucket: minute(12).UnixMicro(), Roll: &Roll{N: 3, Lost: 1, Min: 1, Max: 2, Sum: 3, Hist: &Hist{}}}}}
	s.persistMinute(mb)
	s.persistMinute(mb)
	assertHoursMatchRebuild(t, s, "same minute twice", []time.Time{h0}, f.targets, f.probes)

	// minutes after the late ones keep folding on top of the rebuilt state
	for m := 13; m < 20; m++ {
		f.feedMinute(minute(m))
		f.persist(minute(m))
		assertHoursMatchRebuild(t, s, fmt.Sprintf("after late samples, minute %d", m), []time.Time{h0}, f.targets, f.probes)
	}

	// a late minute of the previous hour, then back to the current one
	prev := h0.Add(-time.Hour)
	f.feedMinute(prev.Add(59 * time.Minute))
	f.persist(prev.Add(59 * time.Minute))
	f.feedMinute(minute(20))
	f.persist(minute(20))
	assertHoursMatchRebuild(t, s, "previous hour and back", []time.Time{prev, h0}, f.targets, f.probes)
}

func TestHourRollRestartMidHour(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.db")
	h0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	now := h0.Add(2 * time.Hour)
	s := openAt(t, path, func() time.Time { return now })
	f := newHourFixture(t, s, 3)
	minute := func(m int) time.Time { return h0.Add(time.Duration(m) * time.Minute) }
	for m := 0; m < 25; m++ {
		f.feedMinute(minute(m))
		f.persist(minute(m))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// a new process starts with an empty accumulator in the middle of the hour
	s = openAt(t, path, func() time.Time { return now })
	defer s.Close()
	f.s = s
	if s.hacc.icmp != nil {
		t.Fatal("accumulator must start empty")
	}
	for m := 25; m < 60; m++ {
		f.feedMinute(minute(m))
		f.persist(minute(m))
		if m == 25 || m == 26 || m == 59 {
			assertHoursMatchRebuild(t, s, fmt.Sprintf("after restart, minute %d", m), []time.Time{h0}, f.targets, f.probes)
		}
	}
	var n int64
	s.rdb.QueryRow(`SELECT SUM(n) FROM icmp_rollup_1h WHERE target_id=?`, f.targets[2]).Scan(&n)
	if n != 60*30*3 {
		t.Errorf("1h n = %d, want %d", n, 60*30*3)
	}

	// a clean shutdown flushes the open minute; reopening must not double count it either
	f.feedMinute(minute(60))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openAt(t, path, func() time.Time { return now })
	defer s.Close()
	f.s = s
	f.feedMinute(minute(61))
	f.persist(minute(61))
	assertHoursMatchRebuild(t, s, "second restart", []time.Time{h0, h0.Add(time.Hour)}, f.targets, f.probes)
}

func TestHourRollBackfillMultiHour(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bf.db")
	h0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	now := h0.Add(4*time.Hour + 20*time.Minute + 20*time.Second)
	s := openAt(t, path, func() time.Time { return now })
	defer s.Close()
	f := newHourFixture(t, s, 4)
	// 4 h 20 min of raw samples for every target and probe (a long outage of the rollups)
	for m := 0; m < 4*60+20; m++ {
		f.feedMinute(h0.Add(time.Duration(m) * time.Minute))
		if m%30 == 29 {
			if err := s.Sync(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	s.agg = NewAggregator() // as after a restart: nothing in memory
	for _, tbl := range []string{"icmp_rollup_1m", "icmp_rollup_1h", "probe_rollup_1m", "probe_rollup_1h"} {
		if _, err := s.wdb.Exec(`DELETE FROM ` + tbl); err != nil {
			t.Fatal(err)
		}
	}
	s.hacc.reset() // the direct deletes above bypass the writer

	check := func(what string) {
		t.Helper()
		var hours []time.Time
		for h := 0; h < 5; h++ {
			hours = append(hours, h0.Add(time.Duration(h)*time.Hour))
		}
		assertHoursMatchRebuild(t, s, what, hours, f.targets, f.probes)
		for _, tid := range f.targets {
			var n1m, n1h int64
			s.rdb.QueryRow(`SELECT SUM(n) FROM icmp_rollup_1m WHERE target_id=?`, tid).Scan(&n1m)
			s.rdb.QueryRow(`SELECT SUM(n) FROM icmp_rollup_1h WHERE target_id=?`, tid).Scan(&n1h)
			if want := int64(4*60+20) * 30 * 3; n1m != want || n1h != want {
				t.Errorf("%s: target %d: 1m n=%d 1h n=%d, want %d", what, tid, n1m, n1h, want)
			}
		}
	}
	if err := s.Backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	check("backfill")
	// backfilling again recomputes the newest minute of each target and must not double count
	if err := s.Backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	check("second backfill")
}

func TestHourRollDeleteTargetResetsAccumulator(t *testing.T) {
	h0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	s := openTest(t, func() time.Time { return h0.Add(2 * time.Hour) })
	minute := func(m int) time.Time { return h0.Add(time.Duration(m) * time.Minute) }
	roll := func(n int64) *Roll {
		r := &Roll{}
		for i := int64(0); i < n; i++ {
			r.AddReply(10, 10, true)
		}
		return r
	}
	batch := func(m int, tid, pid, probe int64, n int64) MinuteBatch {
		p := &ProbeRoll{}
		for i := int64(0); i < n; i++ {
			p.AddOK(0, 1, 0, 0, 0, 5)
		}
		return MinuteBatch{Bucket: minute(m),
			ICMP:   []ICMPRow{{TargetID: tid, TTL: 1, PathID: pid, Bucket: minute(m).UnixMicro(), Roll: roll(n)}},
			Probes: []ProbeRollRow{{ProbeID: probe, Bucket: minute(m).UnixMicro(), Roll: p}}}
	}

	tr, err := s.SyncConfigTarget("old", "h")
	if err != nil {
		t.Fatal(err)
	}
	probe, err := s.EnsureProbe(tr.ID, "tcp", "tcp:x", "x")
	if err != nil {
		t.Fatal(err)
	}
	for m := 0; m < 3; m++ {
		s.persistMinute(batch(m, tr.ID, 1, probe, 10))
	}
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteTarget(tr.ID); err != nil {
		t.Fatal(err)
	}

	// without a reset the reused ids would inherit the deleted target's 30 probes
	tr2, err := s.SyncConfigTarget("new", "h")
	if err != nil {
		t.Fatal(err)
	}
	probe2, err := s.EnsureProbe(tr2.ID, "tcp", "tcp:x", "x")
	if err != nil {
		t.Fatal(err)
	}
	if tr2.ID != tr.ID || probe2 != probe {
		t.Fatalf("ids not reused (target %d/%d, probe %d/%d); the test needs reuse", tr2.ID, tr.ID, probe2, probe)
	}
	s.persistMinute(batch(3, tr2.ID, 1, probe2, 4))
	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}
	var n, pn int64
	s.rdb.QueryRow(`SELECT n FROM icmp_rollup_1h WHERE target_id=?`, tr2.ID).Scan(&n)
	s.rdb.QueryRow(`SELECT n FROM probe_rollup_1h WHERE probe_id=?`, probe2).Scan(&pn)
	if n != 4 || pn != 4 {
		t.Errorf("1h after reuse: icmp n=%d probe n=%d, want 4 and 4", n, pn)
	}
	assertHoursMatchRebuild(t, s, "after delete", []time.Time{h0}, []int64{tr2.ID}, []int64{probe2})
}

// A failed write leaves the accumulator ahead of the tables; the next minute must recover from
// the 1m rows instead of trusting it.
func TestHourRollRecoversFromFailedWrite(t *testing.T) {
	h0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	s := openTest(t, func() time.Time { return h0.Add(2 * time.Hour) })
	f := newHourFixture(t, s, 5)
	minute := func(m int) time.Time { return h0.Add(time.Duration(m) * time.Minute) }
	for m := 0; m < 5; m++ {
		f.feedMinute(minute(m))
		f.persist(minute(m))
	}
	// make the 1h write of minute 5 fail after its 1m rows were inserted and folded
	if err := s.exec(func(tx *sql.Tx) error {
		_, err := tx.Exec(`ALTER TABLE icmp_rollup_1h RENAME TO icmp_rollup_1h_away`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.feedMinute(minute(5))
	f.persist(minute(5))
	if s.hacc.icmp != nil {
		t.Error("accumulator must be dropped after a failed write")
	}
	if err := s.exec(func(tx *sql.Tx) error {
		_, err := tx.Exec(`ALTER TABLE icmp_rollup_1h_away RENAME TO icmp_rollup_1h`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for m := 6; m < 9; m++ {
		f.feedMinute(minute(m))
		f.persist(minute(m))
	}
	assertHoursMatchRebuild(t, s, "after failed write", []time.Time{h0}, f.targets, f.probes)
}

// BenchmarkPersistHour measures the writer time of one hour of minute persists (10 targets x
// 15 hops). ms/minute59 is the cost of the last minute of the hour, the worst case of the old
// full rebuild.
func BenchmarkPersistHour(b *testing.B) {
	t0 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s, err := Open(filepath.Join(b.TempDir(), "b.db"), Options{NoBackground: true, Now: func() time.Time { return t0 }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	rng := rand.New(rand.NewSource(1))
	var minute59, total time.Duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hour := t0.Add(time.Duration(i) * time.Hour)
		for m := 0; m < 60; m++ {
			b.StopTimer()
			mb := MinuteBatch{Bucket: hour.Add(time.Duration(m) * time.Minute)}
			for tg := int64(1); tg <= 10; tg++ {
				for ttl := 1; ttl <= 15; ttl++ {
					r := &Roll{}
					prev := 0.0
					for k := 0; k < 30; k++ {
						if rng.Intn(100) == 0 {
							r.AddLoss()
							continue
						}
						v := float64(ttl) * 1.7 * (0.85 + 0.3*rng.Float64())
						r.AddReply(v, prev, k > 0)
						prev = v
					}
					mb.ICMP = append(mb.ICMP, ICMPRow{TargetID: tg, TTL: ttl, PathID: tg, Bucket: mb.Bucket.UnixMicro(), Roll: r})
				}
			}
			b.StartTimer()
			start := time.Now()
			s.persistMinute(mb)
			if err := s.Sync(); err != nil {
				b.Fatal(err)
			}
			d := time.Since(start)
			total += d
			if m == 59 {
				minute59 += d
			}
		}
	}
	b.ReportMetric(float64(minute59.Microseconds())/1000/float64(b.N), "ms/minute59")
	b.ReportMetric(float64(total.Microseconds())/1000/float64(b.N), "ms/hour")
}

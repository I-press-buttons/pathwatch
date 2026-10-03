package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func openTest(t *testing.T, now func() time.Time) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"), Options{
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		NoBackground:  true,
		FlushInterval: 20 * time.Millisecond,
		Now:           now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// flushW waits for all queued writes to be committed.
func flushW(t *testing.T, s *Store) {
	t.Helper()
	if err := s.exec(func(tx *sql.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestHistMergeAndPercentiles(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var all []float64
	a, b, whole := &Hist{}, &Hist{}, &Hist{}
	for i := 0; i < 20000; i++ {
		v := math.Exp(rng.NormFloat64()*0.6 + math.Log(30)) // log-normal around 30ms
		all = append(all, v)
		whole.Add(v)
		if i%3 == 0 {
			a.Add(v)
		} else {
			b.Add(v)
		}
	}
	merged := &Hist{}
	merged.Merge(a)
	merged.Merge(b)
	if merged.N != whole.N || merged.C != whole.C {
		t.Fatal("merge of parts differs from the whole histogram")
	}
	sort.Float64s(all)
	for _, q := range []float64{0.5, 0.95, 0.99} {
		want := all[int(q*float64(len(all)))-1]
		got, ok := merged.Quantile(q, all[0], all[len(all)-1])
		if !ok {
			t.Fatal("no quantile")
		}
		if rel := math.Abs(got-want) / want; rel > 0.06 {
			t.Errorf("q%.2f = %.3f, exact %.3f (rel err %.3f)", q, got, want, rel)
		}
	}
	// "averaging percentiles" would be wrong for skewed splits; merging is exact.
	lo, hi := &Hist{}, &Hist{}
	for i := 0; i < 900; i++ {
		lo.Add(10)
	}
	for i := 0; i < 100; i++ {
		hi.Add(500)
	}
	m := &Hist{}
	m.Merge(lo)
	m.Merge(hi)
	if p, _ := m.Quantile(0.95, 10, 500); p < 400 {
		t.Errorf("merged p95 = %v, want ~500", p)
	}
	if p, _ := m.Quantile(0.5, 10, 500); p > 12 {
		t.Errorf("merged p50 = %v, want ~10", p)
	}
}

func TestHistEncodeDecode(t *testing.T) {
	h := &Hist{}
	for _, v := range []float64{0.001, 0.5, 1, 1, 30, 30, 30, 2000, 1e9} {
		h.Add(v)
	}
	b := h.Encode()
	got, err := DecodeHist(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.C != h.C || got.N != h.N {
		t.Error("round trip mismatch")
	}
	if e, _ := DecodeHist(nil); e.N != 0 {
		t.Error("empty blob")
	}
	if _, err := DecodeHist([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Error("garbage accepted")
	}
	if (&Hist{}).Encode() != nil {
		t.Error("empty histogram should encode to nil")
	}
	if _, ok := (&Hist{}).Quantile(0.5, 0, 0); ok {
		t.Error("empty quantile ok")
	}
}

func TestRollMerge(t *testing.T) {
	var a, b Roll
	for _, v := range []float64{10, 12, 11} {
		a.AddReply(v, 0, false)
	}
	a.AddLoss()
	b.AddReply(50, 0, false)
	b.AddLoss()
	b.AddLoss()
	var m Roll
	m.Merge(&a)
	m.Merge(&b)
	if m.N != 7 || m.Lost != 3 || m.Replies() != 4 {
		t.Fatalf("%+v", m)
	}
	if m.Min != 10 || m.Max != 50 {
		t.Errorf("min/max %v %v", m.Min, m.Max)
	}
	if avg, _ := m.Avg(); math.Abs(avg-20.75) > 1e-9 {
		t.Errorf("avg %v", avg)
	}
	if lp, _ := m.LossPct(); math.Abs(lp-300.0/7) > 1e-9 {
		t.Errorf("loss %v", lp)
	}
	var empty Roll
	if _, ok := empty.Avg(); ok {
		t.Error("avg of nothing")
	}
	if _, ok := empty.LossPct(); ok {
		t.Error("loss of nothing")
	}
	// lost probes never count toward latency
	var onlyLoss Roll
	onlyLoss.AddLoss()
	if _, ok := onlyLoss.Avg(); ok {
		t.Error("lost probe produced a latency")
	}
}

func TestJitterIsMeanAbsDiff(t *testing.T) {
	var r Roll
	prev, have := 0.0, false
	for _, v := range []float64{10, 14, 11, 11} {
		r.AddReply(v, prev, have)
		prev, have = v, true
	}
	j, ok := r.Jitter()
	if !ok || math.Abs(j-(4+3+0)/3.0) > 1e-9 {
		t.Errorf("jitter = %v", j)
	}
}

func TestRoundBlobRoundTrip(t *testing.T) {
	hops := []Hop{
		{TTL: 1, Status: 2, RTT: 700 * time.Microsecond, Resp: 1},
		{TTL: 2, Status: 0},
		{TTL: 3, Status: 2, RTT: 12345 * time.Microsecond, Resp: 2},
		{TTL: 4, Status: 1, RTT: 3 * time.Second, Resp: 1},
	}
	got, err := DecodeHops(EncodeHops(hops), len(hops))
	if err != nil {
		t.Fatal(err)
	}
	for i := range hops {
		if got[i].TTL != hops[i].TTL || got[i].Status != hops[i].Status || got[i].RTT != hops[i].RTT || got[i].Resp != hops[i].Resp {
			t.Errorf("hop %d: %+v != %+v", i, got[i], hops[i])
		}
	}
	if _, err := DecodeHops(EncodeHops(hops)[:3], 4); err == nil {
		t.Error("truncated blob accepted")
	}
}

func rnd(t0 time.Time, i int, rtt float64, lost bool, ttl int, path int64) Round {
	h := Hop{TTL: ttl}
	if !lost {
		h.Status = 2
		h.RTT = time.Duration(rtt * float64(time.Millisecond))
		h.Resp = 1
	}
	return Round{TargetID: 1, TS: t0.Add(time.Duration(i) * 2 * time.Second), PathID: path, Hops: []Hop{h}}
}

func TestAggregatorMinuteBuckets(t *testing.T) {
	a := NewAggregator()
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// 30 rounds in minute 12:00 and 10 in 12:01
	for i := 0; i < 40; i++ {
		a.AddRound(rnd(t0, i, 10+float64(i%3), i%10 == 9, 1, 5))
	}
	if got := a.Flush(t0.Add(30 * time.Second)); len(got) != 0 {
		t.Fatalf("nothing is complete yet, got %d", len(got))
	}
	got := a.Flush(t0.Add(time.Minute))
	if len(got) != 1 || !got[0].Bucket.Equal(t0) || len(got[0].ICMP) != 1 {
		t.Fatalf("flush: %+v", got)
	}
	r := got[0].ICMP[0].Roll
	if r.N != 30 || r.Lost != 3 {
		t.Errorf("n=%d lost=%d", r.N, r.Lost)
	}
	rest := a.FlushAll()
	if len(rest) != 1 || rest[0].ICMP[0].Roll.N != 10 {
		t.Errorf("remaining: %+v", rest)
	}
	if len(a.FlushAll()) != 0 {
		t.Error("aggregator not empty after FlushAll")
	}
}

func TestAggregatorProbes(t *testing.T) {
	a := NewAggregator()
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		a.AddHTTP(HTTPSample{ProbeID: 7, TS: t0.Add(time.Duration(i) * 10 * time.Second), Total: 100 * time.Millisecond, Connect: 10 * time.Millisecond, TTFB: 80 * time.Millisecond, Status: 200, CertNotAfter: t0.Add(24 * time.Hour)})
	}
	a.AddHTTP(HTTPSample{ProbeID: 7, TS: t0.Add(45 * time.Second), Error: "timeout"})
	a.AddTCP(TCPSample{ProbeID: 8, TS: t0, Connect: 5 * time.Millisecond})
	a.AddDNS(DNSSample{ProbeID: 9, TS: t0, Error: "timeout"})
	mb := a.Flush(t0.Add(2 * time.Minute))
	if len(mb) != 1 || len(mb[0].Probes) != 3 {
		t.Fatalf("%+v", mb)
	}
	h := mb[0].Probes[0].Roll
	if h.N != 5 || h.Errors != 1 || h.OK() != 4 {
		t.Errorf("http roll: %+v", h)
	}
	if avg, _ := h.AvgTotal(); math.Abs(avg-100) > 1e-9 {
		t.Errorf("avg total %v", avg)
	}
	if sp, _ := h.SuccessPct(); math.Abs(sp-80) > 1e-9 {
		t.Errorf("success %v", sp)
	}
	if h.CertNotAfter == 0 {
		t.Error("cert not tracked")
	}
	if f, _ := mb[0].Probes[2].Roll.FailPct(); f != 100 {
		t.Errorf("dns fail %v", f)
	}
}

func TestMigrationsAndPragmas(t *testing.T) {
	s := openTest(t, nil)
	v, err := s.SchemaVersion()
	if err != nil || v < 1 {
		t.Fatalf("schema version %d %v", v, err)
	}
	var av int
	if err := s.rdb.QueryRow(`PRAGMA auto_vacuum`).Scan(&av); err != nil || av != 2 {
		t.Errorf("auto_vacuum = %d (%v), want 2 (incremental)", av, err)
	}
	var jm string
	if err := s.rdb.QueryRow(`PRAGMA journal_mode`).Scan(&jm); err != nil || jm != "wal" {
		t.Errorf("journal_mode = %q", jm)
	}
	// reopening is idempotent
	path := filepath.Join(t.TempDir(), "x.db")
	for i := 0; i < 2; i++ {
		s2, err := Open(path, Options{NoBackground: true})
		if err != nil {
			t.Fatal(err)
		}
		s2.Close()
	}
}

func TestTierSelection(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		d    time.Duration
		want Tier
	}{
		{time.Hour, TierRaw}, {6 * time.Hour, TierRaw}, {6*time.Hour + time.Second, Tier1m},
		{24 * time.Hour, Tier1m}, {7 * 24 * time.Hour, Tier1m}, {7*24*time.Hour + time.Second, Tier1h}, {90 * 24 * time.Hour, Tier1h},
	}
	for _, c := range cases {
		if got := TierFor(now.Add(-c.d), now); got != c.want {
			t.Errorf("TierFor(%v) = %v, want %v", c.d, got, c.want)
		}
	}
	p := MakePlan(now.Add(-time.Hour), now, 300)
	if p.Step != 12*time.Second || p.Tier != TierRaw {
		t.Errorf("plan: %+v", p)
	}
	p = MakePlan(now.Add(-24*time.Hour), now, 300)
	if p.Tier != Tier1m || p.Step%time.Minute != 0 {
		t.Errorf("1m plan: %+v", p)
	}
	p = MakePlan(now.Add(-90*24*time.Hour), now, 300)
	if p.Tier != Tier1h || p.Step%time.Hour != 0 || p.N < 100 || p.N > 301 {
		t.Errorf("1h plan: %+v", p)
	}
	if p.From.After(now.Add(-90 * 24 * time.Hour)) {
		t.Error("origin must not be after from")
	}
}

func setupTarget(t *testing.T, s *Store) (target TargetRow, path int64) {
	t.Helper()
	tr, err := s.SyncConfigTarget("tgt", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := s.NewPath(tr.ID, "127.0.0.1", 1, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	s.AddPathHop(pid, 1, 0, "127.0.0.1")
	return tr, pid
}

// feed writes n rounds starting at t0, one every 2s, loss on every 10th.
func feed(s *Store, tid, pid int64, t0 time.Time, n int, rtt float64) {
	for i := 0; i < n; i++ {
		hop := Hop{TTL: 1, Status: 1, RTT: time.Duration(rtt * float64(time.Millisecond)), Resp: 1}
		if i%10 == 9 {
			hop = Hop{TTL: 1}
		}
		s.RecordRound(Round{TargetID: tid, TS: t0.Add(time.Duration(i) * 2 * time.Second), PathID: pid, Hops: []Hop{hop}})
	}
}

func TestRollupsAndHourRebuild(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := t0
	s := openTest(t, func() time.Time { return clock })
	tr, pid := setupTarget(t, s)
	// 2 hours of rounds would be heavy; use 3 minutes spanning an hour boundary
	start := time.Date(2026, 1, 1, 10, 58, 0, 0, time.UTC)
	feed(s, tr.ID, pid, start, 90, 20) // 180s
	clock = start.Add(10 * time.Minute)
	s.FlushDue(clock)
	flushW(t, s)

	rows, err := s.rdb.Query(`SELECT bucket, n, lost FROM icmp_rollup_1m WHERE target_id=? ORDER BY bucket`, tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	var n1m int
	var tot, lost int64
	for rows.Next() {
		var b, n, l int64
		rows.Scan(&b, &n, &l)
		n1m++
		tot += n
		lost += l
	}
	rows.Close()
	if n1m != 3 || tot != 90 || lost != 9 {
		t.Fatalf("1m rollups: %d rows total n=%d lost=%d", n1m, tot, lost)
	}
	// 1h rollups are the merge of the 1m rows
	rows, err = s.rdb.Query(`SELECT bucket, n, lost, rtt_avg, hist FROM icmp_rollup_1h WHERE target_id=? ORDER BY bucket`, tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	type hr struct{ n, lost int64 }
	var hours []hr
	for rows.Next() {
		var b, n, l int64
		var avg float64
		var hist []byte
		rows.Scan(&b, &n, &l, &avg, &hist)
		hours = append(hours, hr{n, l})
		if math.Abs(avg-20) > 1e-9 {
			t.Errorf("1h avg %v", avg)
		}
		h, err := DecodeHist(hist)
		if err != nil || h.N != uint32(n-l) {
			t.Errorf("hist n=%d want %d (%v)", h.N, n-l, err)
		}
	}
	rows.Close()
	if len(hours) != 2 || hours[0].n+hours[1].n != 90 || hours[0].lost+hours[1].lost != 9 {
		t.Fatalf("hour rows: %+v", hours)
	}

	// idempotent: persisting the same minute again must not double count the hour
	feed(s, tr.ID, pid, start.Add(30*time.Minute), 5, 20)
	clock = start.Add(40 * time.Minute)
	s.FlushDue(clock)
	flushW(t, s)
	var hn int64
	s.rdb.QueryRow(`SELECT SUM(n) FROM icmp_rollup_1h WHERE target_id=?`, tr.ID).Scan(&hn)
	if hn != 95 {
		t.Errorf("hour total n = %d, want 95", hn)
	}
}

func TestQueriesAcrossTiers(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := t0.Add(time.Hour)
	s := openTest(t, func() time.Time { return clock })
	tr, pid := setupTarget(t, s)
	feed(s, tr.ID, pid, t0, 600, 25) // 20 minutes
	s.FlushDue(clock)
	flushW(t, s)

	for _, tier := range []Tier{TierRaw, Tier1m, Tier1h} {
		plan := SinglePlan(t0, t0.Add(30*time.Minute), tier)
		cells, err := s.ICMPCells(tr.ID, plan)
		if err != nil {
			t.Fatal(err)
		}
		tot, ok := cells.E2ETotal(false)
		if !ok || tot.N != 600 || tot.Lost != 60 {
			t.Errorf("%v: e2e total n=%d lost=%d ok=%v", tier, tot.N, tot.Lost, ok)
			continue
		}
		if avg, _ := tot.Avg(); math.Abs(avg-25) > 1e-6 {
			t.Errorf("%v: avg %v", tier, avg)
		}
		if p95, ok := tot.Quantile(0.95); !ok || math.Abs(p95-25)/25 > 0.05 {
			t.Errorf("%v: p95 %v", tier, p95)
		}
	}
	// bucketed raw series
	plan := MakePlan(t0, t0.Add(20*time.Minute), 10)
	cells, _ := s.ICMPCells(tr.ID, plan)
	ser := cells.Series(1)
	var sum int64
	for _, r := range ser {
		if r != nil {
			sum += r.N
		}
	}
	if sum != 600 {
		t.Errorf("bucketed n = %d", sum)
	}
	// last rounds
	lr, err := s.LastRounds(tr.ID, 3)
	if err != nil || len(lr) != 3 || !lr[0].TS.Before(lr[2].TS) {
		t.Errorf("LastRounds: %v %+v", err, lr)
	}
}

func TestBackfillAndSeeding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.db")
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	open := func(now time.Time) *Store {
		s, err := Open(path, Options{NoBackground: true, FlushInterval: 20 * time.Millisecond, Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := open(t0.Add(time.Hour))
	tr, pid := setupTarget(t, s)
	feed(s, tr.ID, pid, t0, 150, 15) // 5 minutes
	// simulate a crash: raw rows written, rollups never flushed
	flushW(t, s)
	s.agg = NewAggregator()
	s.wdb.Exec(`DELETE FROM icmp_rollup_1m`)
	s.Close()

	// restart 2m30s into the last minute (t0+5m is the open minute for "now")
	now := t0.Add(5*time.Minute + 20*time.Second)
	s2 := open(now)
	defer s2.Close()
	// add one open-minute round to be replayed
	s2.RecordRound(Round{TargetID: tr.ID, TS: t0.Add(5*time.Minute + 2*time.Second), PathID: pid, Hops: []Hop{{TTL: 1, Status: 1, RTT: 15 * time.Millisecond, Resp: 1}}})
	flushW(t, s2)
	s2.agg = NewAggregator() // forget it, then backfill must seed it from raw
	if err := s2.Backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	flushW(t, s2)
	var n int64
	s2.rdb.QueryRow(`SELECT SUM(n) FROM icmp_rollup_1m WHERE target_id=?`, tr.ID).Scan(&n)
	if n != 150 {
		t.Errorf("backfilled 1m total = %d, want 150", n)
	}
	var h int64
	s2.rdb.QueryRow(`SELECT SUM(n) FROM icmp_rollup_1h WHERE target_id=?`, tr.ID).Scan(&h)
	if h != 150 {
		t.Errorf("backfilled 1h total = %d, want 150", h)
	}
	open1 := s2.agg.FlushAll()
	if len(open1) != 1 || open1[0].ICMP[0].Roll.N != 1 {
		t.Errorf("open minute not seeded: %+v", open1)
	}
}

func TestRetention(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s, err := Open(filepath.Join(t.TempDir(), "r.db"), Options{
		NoBackground: true, FlushInterval: 20 * time.Millisecond, Now: func() time.Time { return now },
		RawRetention: 7 * 24 * time.Hour, Rollup1mRetention: 90 * 24 * time.Hour,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tr, pid := setupTarget(t, s)
	old := now.Add(-10 * 24 * time.Hour)
	recent := now.Add(-time.Hour)
	feed(s, tr.ID, pid, old, 20, 10)
	feed(s, tr.ID, pid, recent, 20, 10)
	s.FlushDue(now)
	flushW(t, s)
	if err := s.Retain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var raw, m1 int64
	s.rdb.QueryRow(`SELECT COUNT(*) FROM icmp_rounds`).Scan(&raw)
	s.rdb.QueryRow(`SELECT COUNT(*) FROM icmp_rollup_1m`).Scan(&m1)
	if raw != 20 {
		t.Errorf("raw rows after retention = %d, want 20", raw)
	}
	if m1 < 2 { // 1m rollups are retained for 90d, so both the 10-day-old and the recent ones stay
		t.Errorf("1m rows = %d, want the old and the recent buckets", m1)
	}
	// with a shorter 1m retention the old rollups go too
	s.opts.Rollup1mRetention = 24 * time.Hour
	if err := s.Retain(context.Background()); err != nil {
		t.Fatal(err)
	}
	var m2, h1 int64
	s.rdb.QueryRow(`SELECT COUNT(*) FROM icmp_rollup_1m WHERE bucket < ?`, now.Add(-24*time.Hour).UnixMicro()).Scan(&m2)
	s.rdb.QueryRow(`SELECT COUNT(*) FROM icmp_rollup_1h`).Scan(&h1)
	if m2 != 0 {
		t.Errorf("expired 1m rollups remain: %d", m2)
	}
	if h1 != 2 { // 1h retention is 0 = forever
		t.Errorf("1h rollups = %d, want both kept", h1)
	}
}

func TestTargetsLifecycle(t *testing.T) {
	s := openTest(t, nil)
	a, err := s.SyncConfigTarget("alpha", "a.example")
	if err != nil || a.Source != "config" || !a.Active {
		t.Fatalf("%+v %v", a, err)
	}
	u, err := s.CreateUITarget("Beta", "b.example", `{"x":1}`)
	if err != nil || u.Source != "ui" || u.Spec != `{"x":1}` {
		t.Fatalf("%+v %v", u, err)
	}
	if _, err := s.CreateUITarget("beta", "x", "{}"); !errors.Is(err, ErrDuplicate) {
		t.Errorf("case-insensitive duplicate: %v", err)
	}
	if _, err := s.CreateUITarget("alpha", "x", "{}"); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate of config target: %v", err)
	}
	if err := s.SetTargetPaused(u.ID, true); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Target(u.ID)
	if !got.Paused {
		t.Error("not paused")
	}
	if err := s.SetTargetPaused(9999, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("pause unknown: %v", err)
	}
	// config target removed from config becomes inactive, hidden by default
	if err := s.DeactivateConfigTargetsExcept(nil); err != nil {
		t.Fatal(err)
	}
	vis, _ := s.Targets(false)
	all, _ := s.Targets(true)
	if len(vis) != 1 || vis[0].Name != "Beta" || len(all) != 2 {
		t.Errorf("visible=%d all=%d", len(vis), len(all))
	}
	// the ui target is deleted with its data
	pid, _ := s.EnsureProbe(u.ID, "tcp", "tcp|443", "TCP :443")
	s.RecordTCP(TCPSample{ProbeID: pid, TS: time.Now(), Connect: time.Millisecond})
	if err := s.DeleteTarget(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Target(u.ID); !errors.Is(err, ErrNotFound) {
		t.Error("target survived delete")
	}
	var n int
	s.rdb.QueryRow(`SELECT COUNT(*) FROM tcp_samples`).Scan(&n)
	if n != 0 {
		t.Error("samples survived delete")
	}
	// config re-add reactivates
	a2, _ := s.SyncConfigTarget("alpha", "a2.example")
	if a2.ID != a.ID || !a2.Active || a2.Host != "a2.example" {
		t.Errorf("reactivate: %+v", a2)
	}
	// config takes over a UI target with the same name
	_, _ = s.CreateUITarget("gamma", "g", "{}")
	g, _ := s.SyncConfigTarget("gamma", "g2")
	if g.Source != "config" || g.Spec != "" {
		t.Errorf("takeover: %+v", g)
	}
}

func TestEventsAlertsSilences(t *testing.T) {
	s := openTest(t, nil)
	tr, _ := s.SyncConfigTarget("e", "e")
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ttl := 5
	id, err := s.InsertEvent(Event{TargetID: &tr.ID, Kind: EventRateLimited, TTL: &ttl, From: t0, Details: json.RawMessage(`{"loss":50}`)})
	if err != nil {
		t.Fatal(err)
	}
	open, _ := s.OpenEvents(EventRateLimited)
	if len(open) != 1 || open[0].ID != id {
		t.Fatalf("open: %+v", open)
	}
	s.CloseEvent(id, t0.Add(time.Hour))
	flushW(t, s)
	open, _ = s.OpenEvents()
	if len(open) != 0 {
		t.Error("still open")
	}
	_, _ = s.InsertEvent(Event{Kind: EventLocalOutage, From: t0.Add(time.Minute), To: ptrTime(t0.Add(2 * time.Minute))})
	ev, _ := s.Events(EventQuery{TargetID: &tr.ID, From: t0, To: t0.Add(3 * time.Hour)})
	if len(ev) != 2 {
		t.Errorf("events: %d (target + global expected)", len(ev))
	}
	ev, _ = s.Events(EventQuery{From: t0, To: t0.Add(3 * time.Hour), ExcludeKinds: []string{EventLocalOutage}})
	if len(ev) != 1 || ev[0].Kind != EventRateLimited || string(ev[0].Details) != `{"loss":50}` {
		t.Errorf("exclude: %+v", ev)
	}
	ev, _ = s.Events(EventQuery{From: t0.Add(5 * time.Hour), To: t0.Add(6 * time.Hour)})
	if len(ev) != 0 {
		t.Error("range filter")
	}

	a := &Alert{TargetID: &tr.ID, Rule: "http-down", RuleType: "http_failure", State: "firing", StartedAt: t0, Message: "down"}
	if err := s.SaveAlert(a); err != nil || a.ID == 0 {
		t.Fatalf("%v %d", err, a.ID)
	}
	counts, total, _ := s.ActiveAlertCounts()
	if total != 1 || counts[tr.ID] != 1 {
		t.Errorf("counts %v %d", counts, total)
	}
	a.State = "resolved"
	a.EndedAt = ptrTime(t0.Add(time.Minute))
	if err := s.SaveAlert(a); err != nil {
		t.Fatal(err)
	}
	list, _ := s.ListAlerts(10, nil)
	if len(list) != 1 || list[0].State != "resolved" || list[0].EndedAt == nil {
		t.Errorf("%+v", list)
	}
	if _, total, _ = s.ActiveAlertCounts(); total != 0 {
		t.Error("resolved alert counted active")
	}

	sl, err := s.CreateSilence(Silence{StartsAt: t0, EndsAt: t0.Add(time.Hour), Reason: "x", CreatedBy: "me"})
	if err != nil || sl.ID == 0 {
		t.Fatal(err)
	}
	list2, _ := s.Silences(t0.Add(time.Minute))
	if len(list2) != 1 || list2[0].TargetID != nil || list2[0].Rule != nil {
		t.Errorf("%+v", list2)
	}
	if l, _ := s.Silences(t0.Add(2 * time.Hour)); len(l) != 0 {
		t.Error("expired silence listed")
	}
	if err := s.DeleteSilence(sl.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSilence(sl.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestPathsAndGaps(t *testing.T) {
	s := openTest(t, nil)
	tr, _ := s.SyncConfigTarget("p", "p")
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p1, _ := s.NewPath(tr.ID, "1.1.1.1", 0, t0)
	p2, _ := s.NewPath(tr.ID, "1.1.1.1", 4, t0.Add(time.Hour))
	s.SetPathDestTTL(p1, 3)
	s.AddPathHop(p2, 1, 0, "10.0.0.1")
	s.AddPathHop(p2, 1, 1, "10.0.0.2")
	s.UpdatePathShares(p2, []ShareUpdate{{1, 0, 0.7}, {1, 1, 0.3}})
	s.RecordGap(tr.ID, t0.Add(10*time.Minute), t0.Add(20*time.Minute), "stopped")
	flushW(t, s)
	at, err := s.PathAt(tr.ID, t0.Add(30*time.Minute))
	if err != nil || at.ID != p1 || at.DestTTL != 3 || at.EndedAt == nil {
		t.Errorf("PathAt: %+v %v", at, err)
	}
	last, _ := s.LatestPath(tr.ID)
	if last.ID != p2 || last.EndedAt != nil {
		t.Errorf("latest: %+v", last)
	}
	ph, _ := s.PathHops([]int64{p2})
	if len(ph[p2]) != 2 || ph[p2][0].Share != 0.7 || ph[p2][1].Address != "10.0.0.2" {
		t.Errorf("hops: %+v", ph[p2])
	}
	g, _ := s.Gaps(tr.ID, t0, t0.Add(time.Hour))
	if len(g) != 1 || g[0].To.Sub(g[0].From) != 10*time.Minute {
		t.Errorf("gaps: %+v", g)
	}
	ev, _ := s.Events(EventQuery{TargetID: &tr.ID, From: t0, To: t0.Add(time.Hour), Kinds: []string{EventGap}})
	if len(ev) != 1 {
		t.Errorf("gap event: %d", len(ev))
	}
}

func TestProbeQueries(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	clock := t0.Add(time.Hour)
	s := openTest(t, func() time.Time { return clock })
	tr, _ := s.SyncConfigTarget("pq", "pq")
	pid, _ := s.EnsureProbe(tr.ID, "http", "http|GET|x", "GET x")
	for i := 0; i < 60; i++ {
		smp := HTTPSample{ProbeID: pid, TS: t0.Add(time.Duration(i) * 30 * time.Second), Status: 200, Total: 100 * time.Millisecond, DNS: time.Millisecond, Connect: 10 * time.Millisecond, TLS: 20 * time.Millisecond, TTFB: 60 * time.Millisecond, Transfer: 9 * time.Millisecond, CertNotAfter: t0.Add(100 * 24 * time.Hour)}
		if i%10 == 0 {
			smp.Error = "timeout"
		}
		s.RecordHTTP(smp)
	}
	s.FlushDue(clock)
	flushW(t, s)
	for _, tier := range []Tier{TierRaw, Tier1m, Tier1h} {
		pc, err := s.ProbeCells(pid, "http", SinglePlan(t0, t0.Add(31*time.Minute), tier))
		if err != nil {
			t.Fatal(err)
		}
		tot := pc.Total()
		if tot.N != 60 || tot.Errors != 6 {
			t.Errorf("%v: n=%d errors=%d", tier, tot.N, tot.Errors)
		}
		if avg, _ := tot.AvgTotal(); math.Abs(avg-100) > 1e-6 {
			t.Errorf("%v: avg total %v", tier, avg)
		}
	}
	if c, ok := s.LatestCert(pid); !ok || !c.Equal(t0.Add(100*24*time.Hour)) {
		t.Errorf("cert: %v %v", c, ok)
	}
}

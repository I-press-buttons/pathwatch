package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// reading rounds

func TestAppendHopsMatchesDecodeHops(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var buf []Hop
	for i := 0; i < 2000; i++ {
		n := 1 + rng.Intn(20)
		hops := make([]Hop, n)
		for j := range hops {
			hops[j] = Hop{TTL: j + 1}
			if rng.Intn(4) != 0 {
				hops[j].Status = uint8(1 + rng.Intn(3))
				hops[j].RTT = time.Duration(rng.Intn(300000)) * time.Microsecond
				hops[j].Resp = rng.Intn(3)
			}
		}
		blob := EncodeHops(hops)
		switch rng.Intn(4) {
		case 0:
			blob = blob[:rng.Intn(len(blob))] // truncated
		case 1:
			rng.Read(blob[rng.Intn(len(blob)):]) // garbage tail
		}
		want, werr := DecodeHops(blob, n)
		var gerr error
		buf, gerr = appendHops(buf, blob, n)
		if (werr == nil) != (gerr == nil) {
			t.Fatalf("blob %x: DecodeHops err %v, appendHops err %v", blob, werr, gerr)
		}
		if werr != nil {
			continue
		}
		if len(buf) != len(want) {
			t.Fatalf("%d hops, want %d", len(buf), len(want))
		}
		for j := range want {
			if buf[j] != want[j] {
				t.Fatalf("hop %d: %+v, want %+v", j, buf[j], want[j])
			}
		}
	}
	blob := EncodeHops([]Hop{{TTL: 1, Status: 1, RTT: time.Millisecond, Resp: 1}, {TTL: 2}})
	buf, _ = appendHops(buf, blob, 2)
	if n := testing.AllocsPerRun(100, func() { buf, _ = appendHops(buf, blob, 2) }); n != 0 {
		t.Fatalf("appendHops allocates %v times with a warm buffer", n)
	}
}

// ---------------------------------------------------------------------------
// cell loading: every option must give what a full load gives

// cellFixture is a store with four targets over three hours of 2 s rounds, so that the raw,
// 1m and 1h tiers all hold the same data.
type cellFixture struct {
	s       *Store
	t0, now time.Time
	targets map[string]TargetRow
}

const (
	fixRounds = 5400 // 3 h at 2 s
	fixStep   = 2 * time.Second
)

// hopSpec describes how a path answers: hops probed, TTLs up to respond answer, and whether
// the last hop is the destination.
type hopSpec struct {
	hops, respond int
	dest          bool
}

func (c *cellFixture) round(rng *rand.Rand, tr TargetRow, path int64, i int, sp hopSpec) {
	hops := make([]Hop, sp.hops)
	blackout := i >= 1200 && i < 1230 // a minute where everything is lost: rows without replies
	for k := range hops {
		ttl := k + 1
		hops[k] = Hop{TTL: ttl}
		if ttl > sp.respond || blackout || rng.Intn(12) == 0 {
			continue
		}
		hops[k].Status = 2
		if sp.dest && ttl == sp.hops {
			hops[k].Status = 1
		}
		hops[k].RTT = time.Duration(float64(ttl)*2000*(0.7+0.6*rng.Float64())) * time.Microsecond
		hops[k].Resp = 1
	}
	c.s.RecordRound(Round{TargetID: tr.ID, TS: c.t0.Add(time.Duration(i) * fixStep), PathID: path, Hops: hops})
}

func newCellFixture(t *testing.T) *cellFixture {
	t.Helper()
	c := &cellFixture{t0: time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC), targets: map[string]TargetRow{}}
	c.now = c.t0.Add(4 * time.Hour)
	c.s = openTest(t, func() time.Time { return c.now })
	rng := rand.New(rand.NewSource(11))
	target := func(name string) TargetRow {
		tr, err := c.s.SyncConfigTarget(name, name+".example")
		if err != nil {
			t.Fatal(err)
		}
		c.targets[name] = tr
		return tr
	}
	path := func(tr TargetRow, dest int, at int) int64 {
		id, err := c.s.NewPath(tr.ID, "192.0.2.1", dest, c.t0.Add(time.Duration(at)*fixStep))
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	flush := func() {
		if err := c.s.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	// "change": the route changes in the middle (destination at TTL 3, then 4), with a stretch
	// where rounds alternate between the two versions.
	tr := target("change")
	a, b := path(tr, 3, 0), path(tr, 4, 2400)
	for i := 0; i < fixRounds; i++ {
		switch {
		case i < 2400 || (i < 2550 && i%2 == 0):
			c.round(rng, tr, a, i, hopSpec{3, 3, true})
		default:
			c.round(rng, tr, b, i, hopSpec{4, 4, true})
		}
		if i%2000 == 1999 {
			flush()
		}
	}
	// "silent": the destination never answers ICMP; the last responding hop is TTL 3, then 2
	// after a route change.
	tr = target("silent")
	a, b = path(tr, 0, 0), path(tr, 0, 3000)
	for i := 0; i < fixRounds; i++ {
		if i < 3000 {
			c.round(rng, tr, a, i, hopSpec{5, 3, false})
		} else {
			c.round(rng, tr, b, i, hopSpec{4, 2, false})
		}
		if i%2000 == 1999 {
			flush()
		}
	}
	// "late": the destination does not answer at first, and does after the route change.
	tr = target("late")
	a, b = path(tr, 0, 0), path(tr, 3, 2700)
	for i := 0; i < fixRounds; i++ {
		if i < 2700 {
			c.round(rng, tr, a, i, hopSpec{4, 2, false})
		} else {
			c.round(rng, tr, b, i, hopSpec{3, 3, true})
		}
		if i%2000 == 1999 {
			flush()
		}
	}
	// "dark": the destination (TTL 4) went dark while TTL 3 still answers, then the route
	// changed to a path whose destination never answers (last hop TTL 2).
	tr = target("dark")
	a, b = path(tr, 4, 0), path(tr, 0, 2700)
	for i := 0; i < fixRounds; i++ {
		if i < 2700 {
			c.round(rng, tr, a, i, hopSpec{4, 3, true})
		} else {
			c.round(rng, tr, b, i, hopSpec{4, 2, false})
		}
		if i%2000 == 1999 {
			flush()
		}
	}
	// "empty": a path with a destination, and no data at all.
	tr = target("empty")
	path(tr, 2, 0)
	flush()
	c.s.FlushDue(c.now)
	flush()
	return c
}

// fixturePlans covers every tier, bucketed and as a single bucket, with range edges that fall
// inside a minute and inside an hour.
func (c *cellFixture) plans() map[string]Plan {
	end := c.t0.Add(3*time.Hour + 10*time.Minute)
	return map[string]Plan{
		"raw/bucketed": MakePlan(c.t0.Add(-10*time.Minute), end, 37),
		"raw/single":   SinglePlan(c.t0.Add(30*time.Minute), c.t0.Add(150*time.Minute), TierRaw),
		"1m/bucketed":  MakePlan(c.t0.Add(-30*time.Hour), end, 45),
		"1m/single":    SinglePlan(c.t0.Add(17*time.Minute+30*time.Second), c.t0.Add(3*time.Hour), Tier1m),
		"1h/bucketed":  MakePlan(c.t0.Add(-9*24*time.Hour), c.now, 60),
		"1h/single":    SinglePlan(c.t0.Add(10*time.Minute), c.t0.Add(2*time.Hour+20*time.Minute), Tier1h),
	}
}

// refICMPCells is ICMPCells as it was before the options: every row of the range, merged one
// by one through rollFromRow, with a Hist per cell.
func refICMPCells(t *testing.T, s *Store, targetID int64, p Plan) (map[cellKey]*Roll, map[int64]int) {
	t.Helper()
	cells := map[cellKey]*Roll{}
	last := map[int64]int{}
	cell := func(path int64, ttl, b int) *Roll {
		k := cellKey{path, ttl, b}
		if cells[k] == nil {
			cells[k] = &Roll{}
		}
		return cells[k]
	}
	from, to := us(p.From), us(p.To)
	if p.Tier == TierRaw {
		rows, err := s.rdb.Query(`SELECT ts, path_id, hop_count, results FROM icmp_rounds WHERE target_id=? AND ts>=? AND ts<=? ORDER BY ts`, targetID, from, to)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		prev := map[int]float64{}
		for rows.Next() {
			var ts, path int64
			var hc int
			var blob []byte
			if err := rows.Scan(&ts, &path, &hc, &blob); err != nil {
				t.Fatal(err)
			}
			hops, err := DecodeHops(blob, hc)
			if err != nil {
				continue
			}
			b := p.Index(fromUs(ts))
			if b < 0 {
				continue
			}
			for _, h := range hops {
				r := cell(path, h.TTL, b)
				if h.Responded() {
					v := h.RTTms()
					pv, ok := prev[h.TTL]
					r.AddReply(v, pv, ok)
					prev[h.TTL] = v
					if h.TTL > last[path] {
						last[path] = h.TTL
					}
				} else {
					r.AddLoss()
				}
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return cells, last
	}
	table, lo := "icmp_rollup_1m", from
	if p.Tier == Tier1h {
		table, lo = "icmp_rollup_1h", p.From.Truncate(time.Hour).UnixMicro()
	}
	rows, err := s.rdb.Query(`SELECT bucket, ttl, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter, hist FROM `+table+` WHERE target_id=? AND bucket>=? AND bucket<=?`, targetID, lo, to)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var bucket, path, n, lost int64
		var ttl int
		var mn, av, mx, jt sql.NullFloat64
		var hist []byte
		if err := rows.Scan(&bucket, &ttl, &path, &n, &lost, &mn, &av, &mx, &jt, &hist); err != nil {
			t.Fatal(err)
		}
		tm := fromUs(bucket)
		if tm.Before(p.From) {
			tm = p.From
		}
		b := p.Index(tm)
		if b < 0 {
			continue
		}
		roll := rollFromRow(n, lost, mn.Float64, av.Float64, mx.Float64, jt.Float64, hist)
		cell(path, ttl, b).Merge(roll)
		if roll.Replies() > 0 && ttl > last[path] {
			last[path] = ttl
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return cells, last
}

func near(a, b float64) bool { return math.Abs(a-b) <= 1e-9*math.Max(1, math.Abs(a)) }

// rollDiff reports how two merged rolls differ. Sums are compared with a tolerance: merging
// cells in map order may round differently; counts, extremes and histograms must be exact.
func rollDiff(a, b *Roll, hist bool) string {
	switch {
	case a == nil && b == nil:
		return ""
	case a == nil || b == nil:
		return fmt.Sprintf("one side is empty: %+v vs %+v", a, b)
	case a.N != b.N || a.Lost != b.Lost || a.JitN != b.JitN:
		return fmt.Sprintf("counts: %+v vs %+v", *a, *b)
	case a.Replies() > 0 && (a.Min != b.Min || a.Max != b.Max):
		return fmt.Sprintf("extremes: %v..%v vs %v..%v", a.Min, a.Max, b.Min, b.Max)
	case !near(a.Sum, b.Sum) || !near(a.JitSum, b.JitSum):
		return fmt.Sprintf("sums: %v/%v vs %v/%v", a.Sum, a.JitSum, b.Sum, b.JitSum)
	}
	aa, ab := a.Avg()
	ba, bb := b.Avg()
	ja, jok := a.Jitter()
	jb, jok2 := b.Jitter()
	la, lok := a.LossPct()
	lb, lok2 := b.LossPct()
	if ab != bb || jok != jok2 || lok != lok2 || !near(aa, ba) || !near(ja, jb) || !near(la, lb) {
		return "avg/jitter/loss differ"
	}
	if hist {
		if histOf(a.Hist) != histOf(b.Hist) {
			return "histograms differ"
		}
		for _, q := range []float64{0.5, 0.95, 0.99} {
			x, xok := a.Quantile(q)
			y, yok := b.Quantile(q)
			if xok != yok || x != y {
				return fmt.Sprintf("p%v: %v/%v vs %v/%v", q*100, x, xok, y, yok)
			}
		}
	} else if _, ok := b.Quantile(0.95); ok {
		return "quantile reported without histograms"
	}
	return ""
}

func rollsDiff(a, b []*Roll, hist bool) string {
	if len(a) != len(b) {
		return fmt.Sprintf("%d buckets vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != nil && a[i].N == 0 && b[i] == nil {
			continue
		}
		if d := rollDiff(a[i], b[i], hist); d != "" {
			return fmt.Sprintf("bucket %d: %s", i, d)
		}
	}
	return ""
}

func TestICMPCellsMatchReference(t *testing.T) {
	c := newCellFixture(t)
	ctx := context.Background()
	for pname, plan := range c.plans() {
		for tname, tr := range c.targets {
			t.Run(pname+"/"+tname, func(t *testing.T) {
				got, err := c.s.ICMPCells(ctx, tr.ID, plan, CellOpts{})
				if err != nil {
					t.Fatal(err)
				}
				cells, last := refICMPCells(t, c.s, tr.ID, plan)
				if len(cells) != len(got.cells) {
					t.Fatalf("%d cells, want %d", len(got.cells), len(cells))
				}
				for k, want := range cells {
					g := got.cells[k]
					if g == nil || !sameRollExact(g, want) {
						t.Fatalf("cell %+v: %+v, want %+v", k, g, want)
					}
				}
				if len(last) != len(got.lastResp) {
					t.Fatalf("lastResp %v, want %v", got.lastResp, last)
				}
				for p, v := range last {
					if got.lastResp[p] != v {
						t.Fatalf("lastResp %v, want %v", got.lastResp, last)
					}
				}
			})
		}
	}
}

// sameE2E compares what the end-to-end accessors report.
func sameE2E(t *testing.T, full, got *ICMPCells, fallback, hist bool) {
	t.Helper()
	fs, fok := full.E2ESeries(fallback)
	gs, gok := got.E2ESeries(fallback)
	if fok != gok {
		t.Fatalf("E2ESeries(%v) found %v, want %v", fallback, gok, fok)
	}
	if d := rollsDiff(fs, gs, hist); d != "" {
		t.Fatalf("E2ESeries(%v): %s", fallback, d)
	}
	ft, _ := full.E2ETotal(fallback)
	gt, _ := got.E2ETotal(fallback)
	if d := rollDiff(ft, gt, hist); d != "" {
		t.Fatalf("E2ETotal(%v): %s", fallback, d)
	}
	for id := range full.paths {
		if f, g := full.e2eTTL(id, fallback), got.e2eTTL(id, fallback); f != g {
			t.Fatalf("path %d: destination TTL %d, want %d", id, g, f)
		}
	}
}

func withoutDest(c *ICMPCells) bool {
	for _, p := range c.paths {
		if p.DestTTL == 0 {
			return true
		}
	}
	return false
}

func TestICMPCellsOptions(t *testing.T) {
	c := newCellFixture(t)
	ctx := context.Background()
	for pname, plan := range c.plans() {
		for tname, tr := range c.targets {
			t.Run(pname+"/"+tname, func(t *testing.T) {
				full, err := c.s.ICMPCells(ctx, tr.ID, plan, CellOpts{})
				if err != nil {
					t.Fatal(err)
				}
				load := func(o CellOpts) *ICMPCells {
					t.Helper()
					got, err := c.s.ICMPCells(ctx, tr.ID, plan, o)
					if err != nil {
						t.Fatalf("%+v: %v", o, err)
					}
					return got
				}

				// NoHist: every statistic as before, no quantiles
				nh := load(CellOpts{NoHist: true})
				if nh.LastRespTTL() != full.LastRespTTL() || nh.MaxTTL() != full.MaxTTL() || fmt.Sprint(nh.PathIDs()) != fmt.Sprint(full.PathIDs()) {
					t.Fatalf("NoHist: last %d max %d paths %v, want %d %d %v", nh.LastRespTTL(), nh.MaxTTL(), nh.PathIDs(), full.LastRespTTL(), full.MaxTTL(), full.PathIDs())
				}
				for ttl := 1; ttl <= full.MaxTTL()+1; ttl++ {
					if d := rollsDiff(full.Series(ttl), nh.Series(ttl), false); d != "" {
						t.Fatalf("NoHist series %d: %s", ttl, d)
					}
					if d := rollDiff(full.Total(ttl), nh.Total(ttl), false); d != "" {
						t.Fatalf("NoHist total %d: %s", ttl, d)
					}
				}
				sameE2E(t, full, nh, false, false)
				sameE2E(t, full, nh, true, false)

				// a single TTL, with and without histograms
				for ttl := 1; ttl <= full.MaxTTL()+1; ttl++ {
					for _, noHist := range []bool{false, true} {
						one := load(CellOpts{TTL: ttl, NoHist: noHist})
						if d := rollsDiff(full.Series(ttl), one.Series(ttl), !noHist); d != "" {
							t.Fatalf("TTL %d (noHist %v): %s", ttl, noHist, d)
						}
						if d := rollDiff(full.Total(ttl), one.Total(ttl), !noHist); d != "" {
							t.Fatalf("TTL %d total (noHist %v): %s", ttl, noHist, d)
						}
						for k := range one.cells {
							if k.ttl != ttl {
								t.Fatalf("TTL %d load holds a cell of TTL %d", ttl, k.ttl)
							}
						}
					}
				}
				if one := load(CellOpts{TTL: 2, LastResp: true}); one.LastRespTTL() != full.LastRespTTL() {
					t.Fatalf("TTL 2 with LastResp: %d, want %d", one.LastRespTTL(), full.LastRespTTL())
				}

				// the destination only
				for _, mode := range []E2EMode{E2EDest, E2EDestOrLast} {
					for _, noHist := range []bool{false, true} {
						for _, lastResp := range []bool{false, true} {
							o := CellOpts{E2E: mode, NoHist: noHist, LastResp: lastResp}
							got := load(o)
							sameE2E(t, full, got, false, !noHist)
							if mode == E2EDestOrLast {
								sameE2E(t, full, got, true, !noHist)
							}
							// asked for, or needed for the last responding hops anyway
							if (lastResp || (mode == E2EDestOrLast && withoutDest(full))) && got.LastRespTTL() != full.LastRespTTL() {
								t.Fatalf("%+v: LastRespTTL %d, want %d", o, got.LastRespTTL(), full.LastRespTTL())
							}
							if got.LastRespTTL() > full.LastRespTTL() {
								t.Fatalf("%+v: LastRespTTL %d beyond the real %d", o, got.LastRespTTL(), full.LastRespTTL())
							}
							if len(got.cells) > len(full.cells) {
								t.Fatalf("%+v: more cells than a full load", o)
							}
						}
					}
				}
				// E2E loads are narrower than a full load whenever there is something to skip
				if d := load(CellOpts{E2E: E2EDest}); full.MaxTTL() > 1 && len(d.cells) >= len(full.cells) && len(full.cells) > 0 {
					t.Fatalf("E2EDest loaded %d of %d cells", len(d.cells), len(full.cells))
				}
			})
		}
	}
}

// TestICMPCellsE2EScenarios pins what the end-to-end accessors find in the fixture, so that a
// regression of the filters cannot hide behind an unchanged "full" load.
func TestICMPCellsE2EScenarios(t *testing.T) {
	c := newCellFixture(t)
	ctx := context.Background()
	plan := SinglePlan(c.t0, c.t0.Add(3*time.Hour), Tier1m)
	for _, tier := range []Tier{TierRaw, Tier1m, Tier1h} {
		plan.Tier = tier
		want := map[string]struct {
			dest, destOrLast int64 // probes of the destination series; 0 = none
			last             int
		}{
			"change": {fixRounds, fixRounds, 4},
			"silent": {0, fixRounds, 3},
			"late":   {fixRounds - 2700, fixRounds, 3},
			"dark":   {2700, fixRounds, 3}, // the first path's destination cells exist, all lost
			"empty":  {0, 0, 0},
		}
		for name, w := range want {
			tr := c.targets[name]
			for _, mode := range []E2EMode{E2EDest, E2EDestOrLast} {
				got, err := c.s.ICMPCells(ctx, tr.ID, plan, CellOpts{NoHist: true, E2E: mode, LastResp: true})
				if err != nil {
					t.Fatal(err)
				}
				if got.LastRespTTL() != w.last {
					t.Errorf("%v %s: last responding TTL %d, want %d", tier, name, got.LastRespTTL(), w.last)
				}
				d, ok := got.E2ETotal(false)
				if exp := w.dest; (exp > 0) != ok || (ok && d.N != exp) {
					t.Errorf("%v %s %v: E2ETotal(false) n=%d ok=%v, want n=%d", tier, name, mode, d.N, ok, exp)
				}
				if mode == E2EDestOrLast {
					l, ok := got.E2ETotal(true)
					if exp := w.destOrLast; (exp > 0) != ok || (ok && l.N != exp) {
						t.Errorf("%v %s: E2ETotal(true) n=%d ok=%v, want n=%d", tier, name, l.N, ok, exp)
					}
				}
			}
		}
	}
}

func TestCellsContextCanceled(t *testing.T) {
	c := newCellFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr := c.targets["change"]
	for name, plan := range c.plans() {
		if _, err := c.s.ICMPCells(ctx, tr.ID, plan, CellOpts{}); !errors.Is(err, context.Canceled) {
			t.Errorf("ICMPCells %s: %v, want context.Canceled", name, err)
		}
		if _, err := c.s.ProbeCells(ctx, 1, "http", plan, CellOpts{}); !errors.Is(err, context.Canceled) {
			t.Errorf("ProbeCells %s: %v, want context.Canceled", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// probes

func probeDiff(a, b *ProbeRoll, hist bool) string {
	switch {
	case a == nil && b == nil:
		return ""
	case a == nil || b == nil:
		return fmt.Sprintf("one side is empty: %+v vs %+v", a, b)
	case a.N != b.N || a.Errors != b.Errors || a.CertNotAfter != b.CertNotAfter:
		return fmt.Sprintf("counts: %+v vs %+v", *a, *b)
	case a.OK() > 0 && (a.TotalMin != b.TotalMin || a.TotalMax != b.TotalMax):
		return "extremes differ"
	case !near(a.DNS, b.DNS) || !near(a.Connect, b.Connect) || !near(a.TLS, b.TLS) || !near(a.TTFB, b.TTFB) || !near(a.Transfer, b.Transfer) || !near(a.TotalSum, b.TotalSum):
		return fmt.Sprintf("phase sums: %+v vs %+v", *a, *b)
	}
	if hist {
		if histOf(a.Hist) != histOf(b.Hist) {
			return "histograms differ"
		}
		x, xok := a.Quantile(0.95)
		y, yok := b.Quantile(0.95)
		if xok != yok || x != y {
			return "p95 differs"
		}
	} else if _, ok := b.Quantile(0.95); ok {
		return "quantile reported without histograms"
	}
	return ""
}

func TestProbeCellsOptions(t *testing.T) {
	c := newCellFixture(t)
	ctx := context.Background()
	rng := rand.New(rand.NewSource(13))
	tr := c.targets["change"]
	probes := map[string]int64{}
	for _, typ := range []string{"http", "tcp"} {
		id, err := c.s.EnsureProbe(tr.ID, typ, typ+"|x", typ)
		if err != nil {
			t.Fatal(err)
		}
		probes[typ] = id
	}
	dns, err := c.s.EnsureProbe(0, "dns", "dns|1.1.1.1", "dns")
	if err != nil {
		t.Fatal(err)
	}
	probes["dns"] = dns
	var okHTTP int64
	for i := 0; i < fixRounds/15; i++ { // every 30 s
		ts := c.t0.Add(time.Duration(i) * 30 * time.Second)
		smp := HTTPSample{ProbeID: probes["http"], TS: ts, Status: 200, DNS: time.Millisecond, Connect: 10 * time.Millisecond, TLS: 20 * time.Millisecond,
			TTFB: time.Duration(40+rng.Intn(60)) * time.Millisecond, Transfer: 5 * time.Millisecond, CertNotAfter: c.t0.Add(90 * 24 * time.Hour)}
		smp.Total = smp.DNS + smp.Connect + smp.TLS + smp.TTFB + smp.Transfer
		if i%9 == 4 {
			smp.Error = "timeout"
		} else {
			okHTTP++
		}
		c.s.RecordHTTP(smp)
	}
	for i := 0; i < fixRounds/5; i++ { // every 10 s
		ts := c.t0.Add(time.Duration(i) * 10 * time.Second)
		tcp := TCPSample{ProbeID: probes["tcp"], TS: ts, Connect: time.Duration(15+rng.Intn(10)) * time.Millisecond}
		d := DNSSample{ProbeID: probes["dns"], TS: ts, RTT: time.Duration(5+rng.Intn(40)) * time.Millisecond}
		if i%7 == 0 {
			tcp.Error, d.Error = "refused", "timeout"
		}
		c.s.RecordTCP(tcp)
		c.s.RecordDNS(d)
	}
	c.s.FlushDue(c.now)
	if err := c.s.Sync(); err != nil {
		t.Fatal(err)
	}
	for pname, plan := range c.plans() {
		for typ, id := range probes {
			t.Run(pname+"/"+typ, func(t *testing.T) {
				full, err := c.s.ProbeCells(ctx, id, typ, plan, CellOpts{})
				if err != nil {
					t.Fatal(err)
				}
				nh, err := c.s.ProbeCells(ctx, id, typ, plan, CellOpts{NoHist: true})
				if err != nil {
					t.Fatal(err)
				}
				if len(full.Rolls) != len(nh.Rolls) {
					t.Fatalf("%d buckets, want %d", len(nh.Rolls), len(full.Rolls))
				}
				seen := false
				for i := range full.Rolls {
					if d := probeDiff(full.Rolls[i], nh.Rolls[i], false); d != "" {
						t.Fatalf("bucket %d: %s", i, d)
					}
					if r := full.Rolls[i]; r != nil && r.OK() > 0 {
						seen = true
						if _, ok := r.Quantile(0.95); !ok {
							t.Fatalf("bucket %d: no p95 in a full load", i)
						}
					}
				}
				if !seen {
					t.Fatal("no samples in the range")
				}
				if d := probeDiff(full.Total(), nh.Total(), false); d != "" {
					t.Fatalf("total: %s", d)
				}
				if typ == "http" && plan.Tier != TierRaw {
					if got := full.Total(); got.N < 1 || got.CertNotAfter == 0 {
						t.Fatalf("http total %+v", got)
					}
				}
			})
		}
	}
	// rollups against the way rows were merged before
	for _, tier := range []Tier{Tier1m, Tier1h} {
		plan := SinglePlan(c.t0.Add(7*time.Minute), c.t0.Add(3*time.Hour), tier)
		for typ, id := range probes {
			got, err := c.s.ProbeCells(ctx, id, typ, plan, CellOpts{})
			if err != nil {
				t.Fatal(err)
			}
			table, lo := "probe_rollup_1m", us(plan.From)
			if tier == Tier1h {
				table, lo = "probe_rollup_1h", plan.From.Truncate(time.Hour).UnixMicro()
			}
			rows, err := c.s.rdb.Query(`SELECT bucket, n, errors, dns_avg, connect_avg, tls_avg, ttfb_avg, transfer_avg, total_min, total_avg, total_max, hist, cert_not_after FROM `+table+` WHERE probe_id=? AND bucket>=? AND bucket<=? ORDER BY bucket`, id, lo, us(plan.To))
			if err != nil {
				t.Fatal(err)
			}
			want := &ProbeRoll{}
			for rows.Next() {
				var bucket, n, e int64
				var dns, conn, tls, ttfb, tr, tmin, tavg, tmax sql.NullFloat64
				var hist []byte
				var cert sql.NullInt64
				if err := rows.Scan(&bucket, &n, &e, &dns, &conn, &tls, &ttfb, &tr, &tmin, &tavg, &tmax, &hist, &cert); err != nil {
					t.Fatal(err)
				}
				want.Merge(probeRollFromRow(n, e, dns.Float64, conn.Float64, tls.Float64, ttfb.Float64, tr.Float64, tmin.Float64, tavg.Float64, tmax.Float64, hist, cert.Int64))
			}
			rows.Close()
			if d := probeDiff(want, got.Total(), true); d != "" {
				t.Errorf("%v %s: %s", tier, typ, d)
			}
		}
	}
	// the http probe sent okHTTP successes over the whole 3 hours, whatever the tier
	for _, tier := range []Tier{TierRaw, Tier1m, Tier1h} {
		pc, err := c.s.ProbeCells(ctx, probes["http"], "http", SinglePlan(c.t0, c.t0.Add(3*time.Hour), tier), CellOpts{NoHist: true})
		if err != nil {
			t.Fatal(err)
		}
		if tot := pc.Total(); tot.OK() != okHTTP {
			t.Errorf("%v: %d successful samples, want %d", tier, tot.OK(), okHTTP)
		}
	}
}

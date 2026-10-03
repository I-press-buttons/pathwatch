package analyze

import (
	"math"
	"testing"
	"time"
)

func TestMOS(t *testing.T) {
	// Matches the API example: 12.3ms avg, 0.8ms jitter, no loss -> ~4.39
	if m := MOS(12.3, 0.8, 0); math.Abs(m-4.39) > 0.02 {
		t.Errorf("MOS(12.3, 0.8, 0) = %.3f, want ~4.39", m)
	}
	cases := []struct {
		avg, jit, loss float64
		min, max       float64
	}{
		{0, 0, 0, 4.4, 4.5},
		{50, 5, 0, 4.2, 4.5},
		{150, 20, 1, 3.5, 4.2}, // above 160 total: second branch
		{400, 50, 5, 1, 3.0},
		{50, 5, 40, 1, 1.6},
		{5000, 500, 100, 1, 1.0001},
	}
	for _, c := range cases {
		m := MOS(c.avg, c.jit, c.loss)
		if m < c.min || m > c.max || m < 1 || m > 4.5 {
			t.Errorf("MOS(%v,%v,%v) = %.3f, want in [%v,%v]", c.avg, c.jit, c.loss, m, c.min, c.max)
		}
	}
	// exact formula check at the branch point
	lat := 160.0 // avg 150 + 2*0 + 10
	r := 93.2 - (lat-120)/10
	want := 1 + 0.035*r + 0.000007*r*(r-60)*(100-r)
	if got := MOS(150, 0, 0); math.Abs(got-want) > 1e-9 {
		t.Errorf("branch >=160: %v != %v", got, want)
	}
	// monotonic: more loss never improves
	prev := 5.0
	for l := 0.0; l <= 50; l += 5 {
		m := MOS(30, 2, l)
		if m > prev {
			t.Errorf("MOS increased with loss at %v%%", l)
		}
		prev = m
	}
}

func hop(ttl, sent, lost int, avg float64) HopStat {
	return HopStat{TTL: ttl, Sent: sent, Lost: lost, AvgMs: avg, HaveAvg: sent > lost, EverResponded: true}
}

func classes(r Result) []string {
	out := make([]string, len(r.Hops))
	for i, h := range r.Hops {
		out[i] = h.Class
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestClassifyRateLimitedMiddleHop(t *testing.T) {
	// hop 3 drops 60% of ICMP replies but the destination and everything downstream is clean
	hops := []HopStat{hop(1, 30, 0, 1), hop(2, 30, 0, 5), hop(3, 30, 18, 20), hop(4, 30, 0, 22), hop(5, 30, 0, 25)}
	r := Classify(DefaultParams(), hops, nil)
	if want := []string{ClassOK, ClassOK, ClassRateLimited, ClassOK, ClassOK}; !eq(classes(r), want) {
		t.Errorf("classes = %v, want %v", classes(r), want)
	}
	if r.Real {
		t.Error("rate limiting must never be a real degradation")
	}
}

func TestClassifyRealDegradation(t *testing.T) {
	// loss starts at hop 3 and persists through every downstream hop and the destination
	hops := []HopStat{hop(1, 30, 0, 1), hop(2, 30, 0, 5), hop(3, 30, 10, 20), hop(4, 30, 11, 22), hop(5, 30, 9, 25)}
	r := Classify(DefaultParams(), hops, nil)
	if want := []string{ClassOK, ClassOK, ClassDegraded, ClassDegraded, ClassDegraded}; !eq(classes(r), want) {
		t.Errorf("classes = %v, want %v", classes(r), want)
	}
	if !r.Real || r.StartTTL != 3 {
		t.Errorf("real=%v start=%d, want real starting at hop 3", r.Real, r.StartTTL)
	}
}

func TestClassifyDownstreamProbeClearsHop(t *testing.T) {
	// every ICMP hop from 3 on is lossy, but the HTTP probe is clean -> rate limited, not real
	hops := []HopStat{hop(1, 30, 0, 1), hop(2, 30, 15, 5), hop(3, 30, 15, 20)}
	sig := []SignalStat{{Name: "http", Sent: 2, Failed: 0}}
	// too few samples for the probe: it is ignored, so the degradation is real
	if r := Classify(DefaultParams(), hops, sig); !r.Real {
		t.Error("probe with too few samples must be ignored")
	}
	sig = []SignalStat{{Name: "tcp", Sent: 6, Failed: 0, AvgMs: 10, HaveAvg: true}}
	r := Classify(DefaultParams(), hops, sig)
	if r.Real || r.ClassOf(2) != ClassRateLimited || r.ClassOf(3) != ClassRateLimited {
		t.Errorf("classes = %v real=%v", classes(r), r.Real)
	}
	// but if the TCP probe fails as well, it's real
	sig = []SignalStat{{Name: "tcp", Sent: 6, Failed: 3}}
	if r := Classify(DefaultParams(), hops, sig); !r.Real || r.StartTTL != 2 {
		t.Errorf("real=%v start=%d", r.Real, r.StartTTL)
	}
}

func TestClassifyLatencyAgainstBand(t *testing.T) {
	h2 := hop(2, 30, 0, 80)
	h2.Upper = 20 // baseline band edge
	h3 := hop(3, 30, 0, 90)
	h3.Upper = 25
	r := Classify(DefaultParams(), []HopStat{hop(1, 30, 0, 1), h2, h3}, nil)
	if r.ClassOf(2) != ClassDegraded || r.ClassOf(3) != ClassDegraded || r.StartTTL != 2 {
		t.Errorf("latency step should be real from hop 2: %v start=%d", classes(r), r.StartTTL)
	}
	// destination fine, hop 2 slow -> rate limited / deprioritised
	h3.AvgMs = 20
	r = Classify(DefaultParams(), []HopStat{hop(1, 30, 0, 1), h2, h3}, nil)
	if r.ClassOf(2) != ClassRateLimited || r.Real {
		t.Errorf("classes = %v real=%v", classes(r), r.Real)
	}
	// no band (cold start): latency is not judged
	h2.Upper = 0
	r = Classify(DefaultParams(), []HopStat{hop(1, 30, 0, 1), h2}, nil)
	if r.ClassOf(2) != ClassOK {
		t.Errorf("cold start should not classify latency: %v", classes(r))
	}
}

func TestClassifyNoReplyHops(t *testing.T) {
	silent := HopStat{TTL: 2, Sent: 30, Lost: 30, EverResponded: false}
	r := Classify(DefaultParams(), []HopStat{hop(1, 30, 0, 1), silent, hop(3, 30, 0, 10)}, nil)
	if r.ClassOf(2) != ClassNoReply || r.Real {
		t.Errorf("silent hop: %v", classes(r))
	}
	// a silent hop is neither a clean nor a degraded downstream signal
	r = Classify(DefaultParams(), []HopStat{hop(1, 30, 10, 1), silent}, nil)
	if !r.Real || r.StartTTL != 1 {
		t.Errorf("only a silent hop downstream: real=%v", r.Real)
	}
	// a hop that normally answers and now loses everything IS degraded
	vanished := HopStat{TTL: 2, Sent: 30, Lost: 30, EverResponded: true}
	r = Classify(DefaultParams(), []HopStat{hop(1, 30, 0, 1), vanished}, nil)
	if r.ClassOf(2) != ClassDegraded {
		t.Errorf("vanished hop: %v", classes(r))
	}
	// permanently lossy but alive router in the middle of a healthy path
	r = Classify(DefaultParams(), []HopStat{hop(1, 30, 0, 1), hop(2, 30, 29, 5), hop(3, 30, 0, 9)}, nil)
	if r.ClassOf(2) != ClassRateLimited {
		t.Errorf("lossy-but-alive hop: %v", classes(r))
	}
}

func TestClassifyThresholdAndMinSamples(t *testing.T) {
	p := DefaultParams()
	// exactly at the threshold is not degraded (loss must exceed it)
	r := Classify(p, []HopStat{hop(1, 100, 5, 1)}, nil)
	if r.Hops[0].Degraded {
		t.Error("5% is not above a 5% threshold")
	}
	r = Classify(p, []HopStat{hop(1, 100, 6, 1)}, nil)
	if !r.Hops[0].Degraded {
		t.Error("6% should be degraded")
	}
	r = Classify(p, []HopStat{hop(1, 3, 3, 1)}, nil)
	if r.Hops[0].Degraded {
		t.Error("too few samples should not be judged")
	}
}

func TestTrackerHysteresisProducesOneLongEvent(t *testing.T) {
	tr := NewTracker()
	k := Key{Target: 1, TTL: 4, Class: ClassRateLimited}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Minute) }
	var starts, ends int
	obs := func(i int, in bool) {
		if x := tr.Observe(k, in, at(i)); x != nil {
			if x.Start {
				starts++
				if !x.At.Equal(at(1)) {
					t.Errorf("start should be the first bad window, got %v", x.At)
				}
			} else {
				ends++
			}
		}
	}
	obs(0, false)
	obs(1, true) // first bad window
	obs(2, true) // second -> starts
	if starts != 1 {
		t.Fatalf("starts=%d", starts)
	}
	// permanently lossy router with the odd clean minute: still one event
	for i := 3; i < 100; i++ {
		obs(i, i%17 != 0)
	}
	if starts != 1 || ends != 0 {
		t.Errorf("flapping: starts=%d ends=%d, want a single long event", starts, ends)
	}
	obs(100, false)
	obs(101, false)
	if ends != 0 {
		t.Error("ends too early")
	}
	obs(102, false)
	if ends != 1 {
		t.Errorf("ends=%d", ends)
	}
	// a single bad window never starts an event
	obs(110, true)
	obs(111, false)
	if starts != 1 {
		t.Errorf("single blip started an event: %d", starts)
	}
}

func TestTrackerRestore(t *testing.T) {
	tr := NewTracker()
	k := Key{Target: 2, TTL: 3, Class: ClassDegraded}
	tr.Restore(k)
	if !tr.Active(k) {
		t.Fatal("not active")
	}
	if len(tr.Keys(true)) != 1 {
		t.Error("keys")
	}
}

func TestGapDetection(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	g := NewGapDetector(2 * time.Second)
	if g.ObserveAt(t0, 0) != nil {
		t.Fatal("first observation cannot be a gap")
	}
	// normal rounds
	for i := 1; i <= 5; i++ {
		if gap := g.ObserveAt(t0.Add(time.Duration(i)*2*time.Second), 2*time.Second); gap != nil {
			t.Fatalf("regular round flagged as gap: %+v", gap)
		}
	}
	last := t0.Add(10 * time.Second)
	// exactly 3x interval is not a gap, more than 3x is
	if g.ObserveAt(last.Add(6*time.Second), 6*time.Second) != nil {
		t.Error("3x interval should not be a gap")
	}
	last = last.Add(6 * time.Second)
	gap := g.ObserveAt(last.Add(7*time.Second), 7*time.Second)
	if gap == nil || gap.Reason != GapStalled || gap.To.Sub(gap.From) != 7*time.Second || !gap.From.Equal(last) {
		t.Fatalf("stall: %+v", gap)
	}
	last = last.Add(7 * time.Second)
	// wall clock jumps forward 1h while monotonic elapsed only 2s (e.g. suspend / NTP step)
	gap = g.ObserveAt(last.Add(time.Hour), 2*time.Second)
	if gap == nil || gap.Reason != GapClockJump {
		t.Fatalf("forward clock jump: %+v", gap)
	}
	last = last.Add(time.Hour)
	// wall clock jumps backwards
	gap = g.ObserveAt(last.Add(-30*time.Minute), 2*time.Second)
	if gap == nil || gap.Reason != GapClockJump || !gap.From.Before(gap.To) {
		t.Fatalf("backward clock jump: %+v", gap)
	}
	last = last.Add(-30 * time.Minute)
	// small wall/monotonic skew (NTP slew) is tolerated
	if g.ObserveAt(last.Add(2100*time.Millisecond), 2*time.Second) != nil {
		t.Error("slew flagged as gap")
	}
	// Reset starts fresh
	g.Reset()
	if g.ObserveAt(last.Add(time.Hour), time.Hour) != nil {
		t.Error("observation after reset")
	}
}

func TestGapDetectorRealClock(t *testing.T) {
	g := NewGapDetector(50 * time.Millisecond)
	g.Observe(time.Now())
	time.Sleep(10 * time.Millisecond)
	if g.Observe(time.Now()) != nil {
		t.Error("unexpected gap")
	}
	time.Sleep(200 * time.Millisecond)
	if gap := g.Observe(time.Now()); gap == nil || gap.Reason != GapStalled {
		t.Errorf("expected stalled gap, got %+v", gap)
	}
}

func TestLocalOutageDetector(t *testing.T) {
	d := NewLocalOutageDetector()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ok := func(id int64) TargetHealth { return TargetHealth{TargetID: id, E2EKnown: true} }
	bad := func(id int64) TargetHealth { return TargetHealth{TargetID: id, E2EKnown: true, E2EFailing: true} }

	if st, ch := d.Observe(t0, []TargetHealth{ok(1), ok(2)}); st.Down || ch {
		t.Fatal("healthy")
	}
	// a single failing target is not the local link
	if st, _ := d.Observe(t0.Add(time.Minute), []TargetHealth{bad(1), ok(2)}); st.Down {
		t.Error("one failing target of two")
	}
	// gateway down with failing e2e -> outage
	gw := bad(1)
	gw.Gateway1Down = true
	st, ch := d.Observe(t0.Add(2*time.Minute), []TargetHealth{gw, ok(2)})
	if !st.Down || !ch || st.Reason != "gateway" || !st.Since.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("gateway outage: %+v changed=%v", st, ch)
	}
	// still down while bad; recovery needs UpAfter clean windows
	if st, ch := d.Observe(t0.Add(3*time.Minute), []TargetHealth{bad(1), bad(2)}); !st.Down || ch {
		t.Error("should remain down without a new transition")
	}
	if st, _ := d.Observe(t0.Add(4*time.Minute), []TargetHealth{ok(1), ok(2)}); !st.Down {
		t.Error("recovered after one clean window")
	}
	st, ch = d.Observe(t0.Add(5*time.Minute), []TargetHealth{ok(1), ok(2)})
	if st.Down || !ch {
		t.Errorf("not recovered: %+v", st)
	}
	// every target failing at once
	st, _ = d.Observe(t0.Add(6*time.Minute), []TargetHealth{bad(1), bad(2), bad(3)})
	if !st.Down || st.Reason != "all_targets" {
		t.Errorf("all targets: %+v", st)
	}
	// a silent gateway whose e2e is fine (ICMP filtering) is not an outage
	d2 := NewLocalOutageDetector()
	g2 := ok(1)
	g2.Gateway1Down = true
	if st, _ := d2.Observe(t0, []TargetHealth{g2}); st.Down {
		t.Error("gateway silent but e2e fine")
	}
}

func TestBandTracker(t *testing.T) {
	b := NewBandTracker()
	if _, _, ok := b.Band("k"); ok {
		t.Error("band during cold start")
	}
	for i := 0; i < 29; i++ {
		b.Observe("k", 20)
	}
	if _, _, ok := b.Band("k"); ok {
		t.Error("band before MinSamples")
	}
	b.Observe("k", 22)
	med, up, ok := b.Band("k")
	if !ok || med != 20 {
		t.Fatalf("median %v ok=%v", med, ok)
	}
	if up < 30 { // median 20 + max(MAD-based 0, 50% = 10, 10) = 30
		t.Errorf("upper = %v, want >= 30", up)
	}
	// the absolute floor keeps a tiny baseline from being hypersensitive
	for i := 0; i < 40; i++ {
		b.Observe("tiny", 1)
	}
	if _, up, _ := b.Band("tiny"); up < 11 {
		t.Errorf("tiny upper = %v, want >= 11", up)
	}
	// window trimming
	b.Window = 50
	for i := 0; i < 100; i++ {
		b.Observe("w", float64(i))
	}
	if b.Len("w") != 50 {
		t.Errorf("len = %d", b.Len("w"))
	}
}

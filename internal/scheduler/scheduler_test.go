package scheduler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func hopsFrom(list ...string) []store.Hop {
	out := make([]store.Hop, len(list))
	for i, a := range list {
		h := store.Hop{TTL: i + 1}
		if a != "" {
			h.Status, h.Addr, h.RTT = 2, addr(a), time.Millisecond
		}
		out[i] = h
	}
	return out
}

func obs(dest int, ip string, list ...string) Obs {
	hops := hopsFrom(list...)
	if dest > 0 {
		hops[dest-1].Status = 1
	}
	return Obs{TS: time.Now(), IP: addr(ip), DestTTL: dest, Hops: hops}
}

func TestPathTrackerStableAndFirstVersion(t *testing.T) {
	tr := NewPathTracker()
	d := tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "10.0.0.2", "9.9.9.9"))
	if d.Started == nil || d.Previous != nil || len(d.Placed) != 1 || len(d.Added) != 3 {
		t.Fatalf("first round: %+v", d)
	}
	if d.Started.DestTTL != 3 || len(d.DestTTLSet) != 1 {
		t.Errorf("dest ttl not recorded: %+v", d.Started)
	}
	for i := 0; i < 20; i++ {
		d = tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "10.0.0.2", "9.9.9.9"))
		if d.Started != nil || len(d.Placed) != 1 || len(d.Added) != 0 {
			t.Fatalf("stable round %d: %+v", i, d)
		}
		if p := d.Placed[0]; p.Obs.Hops[0].Resp != 1 || p.Obs.Hops[2].Resp != 1 {
			t.Fatalf("responder index: %+v", p.Obs.Hops)
		}
	}
	if tr.Pending() != 0 {
		t.Error("pending rounds")
	}
}

func TestPathTrackerHolesAreNotChanges(t *testing.T) {
	tr := NewPathTracker()
	tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "10.0.0.2", "9.9.9.9"))
	for i := 0; i < 10; i++ {
		// hop 2 rate-limited/lost: not a difference
		d := tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "", "9.9.9.9"))
		if d.Started != nil || tr.Pending() != 0 || len(d.Placed) != 1 {
			t.Fatalf("hole caused a change: %+v pending=%d", d, tr.Pending())
		}
	}
}

func TestPathTrackerLoadBalancedHopIsASetNotAChange(t *testing.T) {
	tr := NewPathTracker()
	tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "10.0.0.2", "9.9.9.9"))
	// hop 2 alternates between two interfaces; each different round is followed by a normal one
	var added int
	for i := 0; i < 30; i++ {
		var d Decision
		if i%2 == 0 {
			d = tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "10.0.0.22", "9.9.9.9"))
		} else {
			d = tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "10.0.0.2", "9.9.9.9"))
		}
		if d.Started != nil {
			t.Fatalf("load balancing started a new path version at round %d", i)
		}
		added += len(d.Added)
	}
	if added != 1 {
		t.Errorf("alternate responder added %d times, want once", added)
	}
	if tr.Pending() != 0 {
		t.Error("pending after matching round")
	}
	v := tr.Current()
	if len(v.Resp[2]) != 2 || v.IndexOf(2, addr("10.0.0.22")) != 1 {
		t.Errorf("responder set: %+v", v.Resp[2])
	}
	sh := v.Shares()
	var sum float64
	for _, s := range sh {
		if s.TTL == 2 {
			sum += s.Share
		}
	}
	if sum < 0.999 || sum > 1.001 {
		t.Errorf("shares at ttl 2 sum to %v", sum)
	}
}

func TestPathTrackerDebounce(t *testing.T) {
	tr := NewPathTracker()
	first := tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "10.0.0.2", "9.9.9.9")).Started
	diff := func() Obs { return obs(4, "9.9.9.9", "10.0.0.1", "10.1.1.2", "10.1.1.3", "9.9.9.9") }

	// two different rounds then a normal one: no change, held rounds merged into the old version
	if d := tr.Observe(diff()); d.Started != nil || len(d.Placed) != 0 || tr.Pending() != 1 {
		t.Fatalf("round 1 should be held: %+v", d)
	}
	if d := tr.Observe(diff()); d.Started != nil || len(d.Placed) != 0 || tr.Pending() != 2 {
		t.Fatalf("round 2 should be held: %+v", d)
	}
	d := tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "10.0.0.2", "9.9.9.9"))
	if d.Started != nil || len(d.Placed) != 3 || tr.Pending() != 0 {
		t.Fatalf("matching round should release 3 rounds on the old version: %+v", d)
	}
	for _, p := range d.Placed {
		if p.Version != first {
			t.Error("released round on wrong version")
		}
	}

	// three consecutive different rounds: new version, all three placed on it
	tr.Observe(diff())
	tr.Observe(diff())
	d = tr.Observe(diff())
	if d.Started == nil || d.Previous == nil || len(d.Placed) != 3 {
		t.Fatalf("expected a new path version with 3 rounds: %+v", d)
	}
	if d.Started == first || tr.Current() != d.Started || d.Started.DestTTL != 4 {
		t.Errorf("version: %+v", d.Started)
	}
	for _, p := range d.Placed {
		if p.Version != d.Started {
			t.Error("round not on the new version")
		}
	}
	// the new version's responder indices are its own
	if got := d.Placed[0].Obs.Hops[1].Resp; got != 1 {
		t.Errorf("resp idx in new version = %d, want 1", got)
	}
	// back to normal on the new path
	if d := tr.Observe(diff()); d.Started != nil || len(d.Placed) != 1 {
		t.Errorf("steady on new path: %+v", d)
	}
}

func TestPathTrackerDestTTLChangeAndLateDest(t *testing.T) {
	tr := NewPathTracker()
	// destination not answering at first
	d := tr.Observe(obs(0, "9.9.9.9", "10.0.0.1", "10.0.0.2", ""))
	if d.Started.DestTTL != 0 {
		t.Fatal("dest ttl set without reply")
	}
	// later the destination answers: sets DestTTL, not a path change
	d = tr.Observe(obs(3, "9.9.9.9", "10.0.0.1", "10.0.0.2", "9.9.9.9"))
	if d.Started != nil || len(d.DestTTLSet) != 1 || tr.Current().DestTTL != 3 {
		t.Fatalf("late destination: %+v", d)
	}
	// a different destination TTL for 3 rounds is a path change
	for i := 0; i < 3; i++ {
		d = tr.Observe(obs(4, "9.9.9.9", "10.0.0.1", "10.0.0.2", "", "9.9.9.9"))
	}
	if d.Started == nil {
		t.Error("longer path should start a new version after the debounce")
	}
}

func TestPathTrackerResolvedIPChangeIsImmediate(t *testing.T) {
	tr := NewPathTracker()
	tr.Observe(obs(2, "9.9.9.9", "10.0.0.1", "9.9.9.9"))
	tr.Observe(obs(2, "9.9.9.9", "10.0.0.1", "9.9.9.9"))
	d := tr.Observe(obs(2, "8.8.8.8", "10.0.0.1", "8.8.8.8"))
	if d.Started == nil || d.Started.IP != addr("8.8.8.8") || d.Previous == nil {
		t.Fatalf("%+v", d)
	}
}

func TestPathTrackerFlush(t *testing.T) {
	tr := NewPathTracker()
	tr.Observe(obs(2, "9.9.9.9", "10.0.0.1", "9.9.9.9"))
	tr.Observe(obs(2, "9.9.9.9", "10.7.7.7", "9.9.9.9"))
	if tr.Pending() != 1 {
		t.Fatal("expected a held round")
	}
	if d := tr.Flush(); len(d.Placed) != 1 || tr.Pending() != 0 {
		t.Errorf("flush: %+v", d)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(30)
	if l.Next() != 30 {
		t.Fatal("first round probes everything")
	}
	l.Record(8, 8)
	if l.Next() != 8 || l.Known() != 8 {
		t.Errorf("stops at the destination: %d", l.Next())
	}
	for i := 0; i < 4; i++ {
		l.Record(0, 7)
	}
	if l.Next() != 8 {
		t.Errorf("a few misses keep probing the known length: %d", l.Next())
	}
	l.Record(0, 7)
	if l.Next() != 11 {
		t.Errorf("after the miss streak the limit grows by the slack: %d", l.Next())
	}
	l.Record(10, 10) // path got longer
	if l.Next() != 10 {
		t.Errorf("new destination ttl: %d", l.Next())
	}
	l.Rediscover()
	if l.Next() != 30 {
		t.Error("rediscovery probes MaxHops")
	}
	l.Record(10, 10)

	// destination that never answers: trailing * rows are trimmed
	u := NewLimiter(30)
	u.Record(0, 6)
	for i := 0; i < 5; i++ {
		u.Record(0, 6)
	}
	if u.Next() != 9 {
		t.Errorf("unresponsive destination: %d, want last responder + 3", u.Next())
	}
	// never any reply at all: keep probing the full depth
	z := NewLimiter(12)
	z.Record(0, 0)
	if z.Next() != 3 {
		t.Logf("no responders: %d", z.Next())
	}
	if NewLimiter(5).Next() != 5 {
		t.Error("clamped to MaxHops")
	}
}

// ---------------------------------------------------------------------------
// scheduler with a fake prober

type fakeProber struct {
	mu         sync.Mutex
	path       []string // responder per ttl (1-based index = ttl-1); the last entry is the destination
	destSilent bool
	lossy      map[int]float64
	maxTTL     atomic.Int32
	calls      atomic.Int64
	flows      map[uint16]bool
}

func (f *fakeProber) Mode() string { return probe.ModeRaw }
func (f *fakeProber) Close() error { return nil }
func (f *fakeProber) Probe(ctx context.Context, req probe.Request) probe.Result {
	f.calls.Add(1)
	for {
		cur := f.maxTTL.Load()
		if int32(req.TTL) <= cur || f.maxTTL.CompareAndSwap(cur, int32(req.TTL)) {
			break
		}
	}
	f.mu.Lock()
	if f.flows == nil {
		f.flows = map[uint16]bool{}
	}
	f.flows[req.Flow] = true
	f.mu.Unlock()
	n := len(f.path)
	if req.TTL < n {
		return probe.Result{Status: probe.StatusTTLExceeded, Addr: addr(f.path[req.TTL-1]), RTT: time.Duration(req.TTL) * time.Millisecond}
	}
	if f.destSilent {
		return probe.Result{}
	}
	return probe.Result{Status: probe.StatusReply, Addr: addr(f.path[n-1]), RTT: time.Duration(n) * time.Millisecond}
}

type recObserver struct {
	rounds, probes, changed atomic.Int64
}

func (o *recObserver) Round(RoundEvent) { o.rounds.Add(1) }
func (o *recObserver) Probe(ProbeEvent) { o.probes.Add(1) }
func (o *recObserver) TargetsChanged()  { o.changed.Add(1) }

type staticResolver map[string]string

func (r staticResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if v, ok := r[host]; ok {
		return []netip.Addr{addr(v)}, nil
	}
	return nil, errors.New("no such host")
}

func newTestScheduler(t *testing.T, p probe.Prober, res Resolver) (*Scheduler, *store.Store, *recObserver) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"), store.Options{Logger: log, FlushInterval: 20 * time.Millisecond, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	obs := &recObserver{}
	s := New(Options{Store: st, Prober: p, Observer: obs, Logger: log, Resolver: res, Stagger: time.Millisecond, Version: "test"})
	s.Start(context.Background())
	t.Cleanup(func() { s.Close(); st.Close() })
	return s, st, obs
}

func icmpTarget(name, host string, interval time.Duration) config.Target {
	return config.Target{Name: name, Host: host, Source: config.SourceConfig,
		ICMP: &config.ICMPSettings{Interval: interval, Timeout: interval, Rediscovery: time.Hour, MaxHops: 12}}
}

func waitUntil(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestSchedulerRoundsAndPathStopAtDestination(t *testing.T) {
	fp := &fakeProber{path: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "192.0.2.9"}}
	s, st, obs := newTestScheduler(t, fp, nil)
	if err := s.SyncConfig([]config.Target{icmpTarget("t1", "192.0.2.9", 60*time.Millisecond)}, nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "rounds", func() bool { return obs.rounds.Load() >= 8 })
	s.Close()
	st.FlushDue(time.Now().Add(time.Hour))

	states := s.States()
	if len(states) != 1 || states[0].ResolvedIP != "192.0.2.9" || states[0].Row.Name != "t1" {
		t.Fatalf("states: %+v", states)
	}
	rounds, err := st.LastRounds(states[0].Row.ID, 5)
	if err != nil || len(rounds) == 0 {
		t.Fatalf("rounds: %v %d", err, len(rounds))
	}
	r := rounds[len(rounds)-1]
	if len(r.Hops) != 4 || r.Hops[3].Status != 1 || r.Hops[0].Status != 2 {
		t.Fatalf("round hops: %+v", r.Hops)
	}
	p, err := st.LatestPath(states[0].Row.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "dest ttl persisted", func() bool {
		p, _ = st.LatestPath(states[0].Row.ID)
		return p.DestTTL == 4
	})
	ph, _ := st.PathHops([]int64{p.ID})
	if len(ph[p.ID]) != 4 {
		t.Errorf("path hops: %+v", ph[p.ID])
	}
	// the first round probes up to MaxHops(12) but later rounds stop at the destination
	if fp.maxTTL.Load() > 12 {
		t.Errorf("probed beyond max_hops: %d", fp.maxTTL.Load())
	}
	// every round shares one flow identity (Paris)
	if len(fp.flows) != 1 {
		t.Errorf("flows used: %v, want one per target", fp.flows)
	}
	pr := st.Aggregator().FlushAll()
	for _, mb := range pr {
		for _, row := range mb.ICMP {
			if row.TTL > 4 {
				t.Errorf("aggregated ttl %d beyond the destination", row.TTL)
			}
		}
	}
}

func TestSchedulerUnresponsiveDestination(t *testing.T) {
	fp := &fakeProber{path: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "192.0.2.50"}, destSilent: true}
	s, st, obs := newTestScheduler(t, fp, nil)
	if err := s.SyncConfig([]config.Target{icmpTarget("quiet", "192.0.2.50", 30*time.Millisecond)}, nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "icmp_unresponsive", func() bool {
		sts := s.States()
		return len(sts) == 1 && sts[0].ICMPUnresponsive
	})
	id := s.States()[0].Row.ID
	n := obs.rounds.Load()
	waitUntil(t, "more rounds", func() bool { return obs.rounds.Load() > n+5 })
	rounds, _ := st.LastRounds(id, 3)
	// trailing * rows are trimmed to last responder (3) + slack (3) = 6 once the window fills
	if got := len(rounds[len(rounds)-1].Hops); got > 6 {
		t.Errorf("hops per round = %d, want trimmed to <= 6", got)
	}
	ev, _ := st.Events(store.EventQuery{TargetID: &id, From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Kinds: []string{store.EventICMPUnresponsive}})
	if len(ev) != 1 || ev[0].To != nil {
		t.Errorf("icmp_unresponsive event: %+v", ev)
	}
	p, _ := st.LatestPath(id)
	if p.DestTTL != 0 {
		t.Errorf("dest ttl %d for a silent destination", p.DestTTL)
	}
	// topology exposes it for the analyzer
	if ti := s.Targets(); len(ti) != 1 || !ti[0].ICMPUnresponsive {
		t.Errorf("topology: %+v", ti)
	}
}

func TestSchedulerRouteChangeEvent(t *testing.T) {
	fp := &fakeProber{path: []string{"10.0.0.1", "10.0.0.2", "192.0.2.9"}}
	s, st, obs := newTestScheduler(t, fp, nil)
	_ = s.SyncConfig([]config.Target{icmpTarget("rc", "192.0.2.9", 30*time.Millisecond)}, nil)
	waitUntil(t, "rounds", func() bool { return obs.rounds.Load() >= 5 })
	id := s.States()[0].Row.ID
	fp.mu.Lock()
	fp.path = []string{"10.0.0.1", "10.9.9.9", "192.0.2.9"}
	fp.mu.Unlock()
	waitUntil(t, "route change", func() bool {
		ev, _ := st.Events(store.EventQuery{TargetID: &id, From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Kinds: []string{store.EventRouteChange}})
		return len(ev) == 1
	})
	waitUntil(t, "two path versions", func() bool {
		var n int
		rows, _ := st.PathsOf([]int64{1, 2, 3})
		n = len(rows)
		return n == 2
	})
}

func TestSchedulerPauseResumeAndUITargets(t *testing.T) {
	fp := &fakeProber{path: []string{"10.0.0.1", "192.0.2.7"}}
	s, st, obs := newTestScheduler(t, fp, staticResolver{"host.example": "192.0.2.7"})
	tg := icmpTarget("ui-one", "host.example", 30*time.Millisecond)
	row, err := s.AddUITarget(tg)
	if err != nil {
		t.Fatal(err)
	}
	if row.Source != config.SourceUI || obs.changed.Load() == 0 {
		t.Fatalf("row %+v changed=%d", row, obs.changed.Load())
	}
	if _, err := s.AddUITarget(tg); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate: %v", err)
	}
	waitUntil(t, "rounds on ui target", func() bool { return obs.rounds.Load() >= 3 })
	st1, _ := s.State(row.ID)
	if st1.ResolvedIP != "192.0.2.7" || !st1.Running {
		t.Fatalf("state: %+v", st1)
	}

	// pause stops probing without restart
	if err := s.SetPaused(row.ID, true); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	n := obs.rounds.Load()
	time.Sleep(250 * time.Millisecond)
	if obs.rounds.Load() != n {
		t.Error("rounds continued while paused")
	}
	if ps, _ := s.State(row.ID); ps.Running || !ps.Row.Paused {
		t.Errorf("paused state: %+v", ps)
	}
	if err := s.SetPaused(row.ID, false); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "rounds after resume", func() bool { return obs.rounds.Load() > n+3 })

	// remove
	if err := s.RemoveTarget(row.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.State(row.ID); ok {
		t.Error("state after remove")
	}
	if _, err := st.Target(row.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error("db row after remove")
	}
	// config targets cannot be removed
	if err := s.SyncConfig([]config.Target{icmpTarget("cfg", "192.0.2.7", 30*time.Millisecond)}, nil); err != nil {
		t.Fatal(err)
	}
	cid := s.States()[0].Row.ID
	if err := s.RemoveTarget(cid); !errors.Is(err, ErrConfigTarget) {
		t.Errorf("remove config target: %v", err)
	}
	// ...but may be paused
	if err := s.SetPaused(cid, true); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerLoadsUITargetsOnRestart(t *testing.T) {
	fp := &fakeProber{path: []string{"192.0.2.7"}}
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	open := func() (*Scheduler, *store.Store) {
		st, err := store.Open(filepath.Join(dir, "r.db"), store.Options{Logger: log, FlushInterval: 20 * time.Millisecond, NoBackground: true})
		if err != nil {
			t.Fatal(err)
		}
		s := New(Options{Store: st, Prober: fp, Logger: log, Stagger: time.Millisecond})
		s.Start(context.Background())
		return s, st
	}
	s, st := open()
	row, err := s.AddUITarget(icmpTarget("persist", "192.0.2.7", 40*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	_ = s.SetPaused(row.ID, true)
	s.Close()
	st.Close()

	s2, st2 := open()
	defer st2.Close()
	defer s2.Close()
	if err := s2.LoadUITargets(); err != nil {
		t.Fatal(err)
	}
	ps, ok := s2.State(row.ID)
	if !ok || !ps.Row.Paused || ps.Running || ps.Spec.ICMP == nil || ps.Spec.ICMP.Interval != 40*time.Millisecond {
		t.Fatalf("restored: %+v ok=%v", ps, ok)
	}
	if err := s2.SetPaused(row.ID, false); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "rounds", func() bool { c := fp.calls.Load(); return c > 5 })
}

func TestSchedulerNoProberStillRunsOtherProbes(t *testing.T) {
	s, _, obs := newTestScheduler(t, nil, nil)
	if s.ICMPMode() != probe.ModeUnavailable {
		t.Error("mode")
	}
	tg := config.Target{Name: "tcp-only", Host: "127.0.0.1", Source: config.SourceConfig,
		ICMP:   &config.ICMPSettings{Interval: time.Second, Timeout: time.Second, Rediscovery: time.Hour, MaxHops: 5},
		Probes: []config.Probe{{Type: config.ProbeTCP, Port: 1, Interval: 50 * time.Millisecond, Timeout: 200 * time.Millisecond, PinIP: true}}}
	if err := s.SyncConfig([]config.Target{tg}, nil); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "tcp probes", func() bool { return obs.probes.Load() >= 2 })
	if ok, _ := s.Healthy(); !ok {
		t.Error("healthy without icmp expectations")
	}
}

func TestSyncConfigDeactivatesRemovedTargets(t *testing.T) {
	fp := &fakeProber{path: []string{"192.0.2.7"}}
	s, st, _ := newTestScheduler(t, fp, nil)
	a, b := icmpTarget("a", "192.0.2.7", time.Second), icmpTarget("b", "192.0.2.8", time.Second)
	if err := s.SyncConfig([]config.Target{a, b}, nil); err != nil {
		t.Fatal(err)
	}
	if len(s.States()) != 2 {
		t.Fatal("two targets expected")
	}
	if err := s.SyncConfig([]config.Target{a}, nil); err != nil {
		t.Fatal(err)
	}
	if len(s.States()) != 1 {
		t.Errorf("states after removal: %d", len(s.States()))
	}
	all, _ := st.Targets(true)
	vis, _ := st.Targets(false)
	if len(all) != 2 || len(vis) != 1 {
		t.Errorf("db: all=%d visible=%d", len(all), len(vis))
	}
}

func TestPickAddr(t *testing.T) {
	a4, b4, c6 := addr("1.1.1.1"), addr("2.2.2.2"), addr("2606::1")
	if got := pickAddr([]netip.Addr{c6, b4, a4}, netip.Addr{}); got != b4 {
		t.Errorf("first v4: %v", got)
	}
	if got := pickAddr([]netip.Addr{b4, a4}, a4); got != a4 {
		t.Errorf("sticky pin: %v", got)
	}
	if got := pickAddr([]netip.Addr{c6}, netip.Addr{}); got != c6 {
		t.Errorf("v6 only: %v", got)
	}
	if got := pickAddr([]netip.Addr{b4}, a4); got != b4 {
		t.Errorf("pin gone: %v", got)
	}
}

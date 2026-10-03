package analyze

import (
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

type recEngine struct {
	mu      sync.Mutex
	minutes []alert.Minute
}

func (r *recEngine) HandleMinute(m alert.Minute) {
	r.mu.Lock()
	r.minutes = append(r.minutes, m)
	r.mu.Unlock()
}
func (r *recEngine) HandleProbe(alert.ProbeSample) {}
func (r *recEngine) Close()                        {}

type topo struct {
	targets []TargetInfo
}

func (t *topo) Targets() []TargetInfo  { return t.targets }
func (t *topo) DNSProbes() []ProbeInfo { return nil }

func roll(n, lost int, avg float64) *store.Roll {
	r := &store.Roll{}
	for i := 0; i < n-lost; i++ {
		r.AddReply(avg, avg, i > 0)
	}
	for i := 0; i < lost; i++ {
		r.AddLoss()
	}
	return r
}

func probeRoll(n, errs int, avg float64) *store.ProbeRoll {
	p := &store.ProbeRoll{}
	for i := 0; i < n-errs; i++ {
		p.AddOK(0, avg, 0, 0, 0, avg)
	}
	for i := 0; i < errs; i++ {
		p.AddError()
	}
	return p
}

type fixture struct {
	st   *store.Store
	an   *Analyzer
	eng  *recEngine
	tid  int64
	path int64
	tcp  int64
	t0   time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"), store.Options{Logger: log, NoBackground: true, FlushInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tr, _ := st.SyncConfigTarget("t", "t")
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	pid, _ := st.NewPath(tr.ID, "9.9.9.9", 4, t0)
	st.SetPathDestTTL(pid, 4)
	tcp, _ := st.EnsureProbe(tr.ID, "tcp", "tcp|443", "TCP :443")
	st.Sync()
	eng := &recEngine{}
	an := New(st, &topo{targets: []TargetInfo{{ID: tr.ID, Name: "t", Probes: []ProbeInfo{{ID: tcp, Type: "tcp", Label: "TCP :443"}}}}}, eng, log)
	return &fixture{st: st, an: an, eng: eng, tid: tr.ID, path: pid, tcp: tcp, t0: t0}
}

// minute builds a batch: hop2Lost/hop3.. losses per TTL out of 30 probes, tcpErrs of 6.
func (f *fixture) minute(i int, loss [5]int, tcpErrs int) store.MinuteBatch {
	b := f.t0.Add(time.Duration(i) * time.Minute)
	mb := store.MinuteBatch{Bucket: b}
	for ttl := 1; ttl <= 4; ttl++ {
		mb.ICMP = append(mb.ICMP, store.ICMPRow{TargetID: f.tid, TTL: ttl, PathID: f.path, Bucket: b.UnixMicro(), Roll: roll(30, loss[ttl], float64(ttl)*5)})
	}
	mb.Probes = append(mb.Probes, store.ProbeRollRow{ProbeID: f.tcp, Bucket: b.UnixMicro(), Roll: probeRoll(6, tcpErrs, 20)})
	return mb
}

func (f *fixture) events(t *testing.T, kind string) []store.Event {
	t.Helper()
	f.st.Sync()
	tid := f.tid
	evs, err := f.st.Events(store.EventQuery{TargetID: &tid, From: f.t0.Add(-time.Hour), To: f.t0.Add(24 * time.Hour), Kinds: []string{kind}})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestAnalyzerRateLimitedHopIsAnEventNotAnAlertSignal(t *testing.T) {
	f := newFixture(t)
	// hop 2 loses 60% of its ICMP replies; hop 3, the destination and the TCP probe are clean
	for i := 0; i < 6; i++ {
		f.an.OnMinute(f.minute(i, [5]int{0, 0, 18, 0, 0}, 0))
	}
	evs := f.events(t, store.EventRateLimited)
	if len(evs) != 1 || evs[0].TTL == nil || *evs[0].TTL != 2 || evs[0].To != nil {
		t.Fatalf("expected one open rate_limited event on ttl 2, got %+v", evs)
	}
	if !evs[0].From.Equal(f.t0) {
		t.Errorf("event should start at the first bad window: %v", evs[0].From)
	}
	if deg := f.events(t, store.EventDegraded); len(deg) != 0 {
		t.Errorf("degraded events: %+v", deg)
	}
	an, ok := f.an.Latest(f.tid)
	if !ok || an.Classes[2] != ClassRateLimited || an.Real {
		t.Errorf("latest: %+v", an)
	}
	// engine sees classification, no degradation
	last := f.eng.minutes[len(f.eng.minutes)-1]
	if len(last.Targets) != 1 || last.Targets[0].Degradation != nil || last.Targets[0].Hops[1].Class != ClassRateLimited {
		t.Errorf("engine minute: %+v", last.Targets)
	}
	if e := last.Targets[0].E2E; e == nil || e.LossPct != 0 || e.AvgMS != 20 || last.Targets[0].E2ESource != "icmp" {
		t.Errorf("e2e: %+v %s", e, last.Targets[0].E2ESource)
	}
	// 5 more bad minutes keep it a single event; a recovery of 3 clean minutes ends it
	for i := 6; i < 20; i++ {
		f.an.OnMinute(f.minute(i, [5]int{0, 0, 18, 0, 0}, 0))
	}
	if evs := f.events(t, store.EventRateLimited); len(evs) != 1 {
		t.Fatalf("flood of events: %d", len(evs))
	}
	for i := 20; i < 23; i++ {
		f.an.OnMinute(f.minute(i, [5]int{}, 0))
	}
	evs = f.events(t, store.EventRateLimited)
	if len(evs) != 1 || evs[0].To == nil || !evs[0].To.Equal(f.t0.Add(20*time.Minute)) {
		t.Fatalf("event should end at the first clean window: %+v", evs)
	}
}

func TestAnalyzerRealDegradation(t *testing.T) {
	f := newFixture(t)
	// loss from hop 3 on, destination and TCP degraded as well
	for i := 0; i < 3; i++ {
		f.an.OnMinute(f.minute(i, [5]int{0, 0, 0, 9, 10}, 3))
	}
	an, _ := f.an.Latest(f.tid)
	if !an.Real || an.StartTTL != 3 || an.Classes[3] != ClassDegraded || an.Classes[4] != ClassDegraded {
		t.Errorf("latest: %+v", an)
	}
	last := f.eng.minutes[len(f.eng.minutes)-1].Targets[0]
	if last.Degradation == nil || last.Degradation.StartTTL != 3 {
		t.Errorf("engine degradation: %+v", last.Degradation)
	}
	if deg := f.events(t, store.EventDegraded); len(deg) != 2 {
		t.Errorf("degraded events: %+v", deg)
	}
}

func TestAnalyzerEndToEndFallbackToTCPForUnresponsiveDestination(t *testing.T) {
	f := newFixture(t)
	// the destination TTL 4 never answered: path dest_ttl 0, hops 1-3 answer
	if _, err := f.st.NewPath(f.tid, "9.9.9.9", 0, f.t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	pid, _ := f.st.LatestPath(f.tid)
	f.path = pid.ID
	f.an.topo.(*topo).targets[0].ICMPUnresponsive = true
	b := f.t0.Add(5 * time.Minute)
	mb := store.MinuteBatch{Bucket: b}
	for ttl := 1; ttl <= 3; ttl++ {
		mb.ICMP = append(mb.ICMP, store.ICMPRow{TargetID: f.tid, TTL: ttl, PathID: f.path, Bucket: b.UnixMicro(), Roll: roll(30, 0, float64(ttl)*5)})
	}
	mb.ICMP = append(mb.ICMP, store.ICMPRow{TargetID: f.tid, TTL: 4, PathID: f.path, Bucket: b.UnixMicro(), Roll: roll(30, 30, 0)})
	mb.Probes = []store.ProbeRollRow{{ProbeID: f.tcp, Bucket: b.UnixMicro(), Roll: probeRoll(6, 1, 33)}}
	f.an.OnMinute(mb)
	tm := f.eng.minutes[0].Targets[0]
	if tm.E2ESource != "tcp" || tm.E2E == nil || tm.E2E.AvgMS != 33 || tm.E2E.Lost != 1 || !tm.ICMPUnresponsive {
		t.Errorf("e2e should come from TCP: %+v source=%s", tm.E2E, tm.E2ESource)
	}
	// the silent destination hop is no_reply, not degraded
	if tm.Hops[3].Class != ClassNoReply || tm.Degradation != nil {
		t.Errorf("hop 4: %+v degradation=%+v", tm.Hops[3], tm.Degradation)
	}
	// without a TCP probe the last responding hop is used
	f.an.topo.(*topo).targets[0].Probes = nil
	f.an.OnMinute(mb)
	tm = f.eng.minutes[1].Targets[0]
	if tm.E2ESource != "last_hop" || tm.E2E == nil || tm.E2E.AvgMS != 15 {
		t.Errorf("last hop fallback: %+v %s", tm.E2E, tm.E2ESource)
	}
}

func TestAnalyzerLocalOutage(t *testing.T) {
	f := newFixture(t)
	t2, _ := f.st.SyncConfigTarget("t2", "t2")
	p2, _ := f.st.NewPath(t2.ID, "8.8.8.8", 4, f.t0)
	f.st.SetPathDestTTL(p2, 4)
	f.st.Sync()
	f.an.topo.(*topo).targets = append(f.an.topo.(*topo).targets, TargetInfo{ID: t2.ID, Name: "t2"})
	mk := func(i int, gwLoss int, dstLoss int) store.MinuteBatch {
		b := f.t0.Add(time.Duration(i) * time.Minute)
		mb := store.MinuteBatch{Bucket: b}
		for _, x := range []struct {
			tid  int64
			path int64
		}{{f.tid, f.path}, {t2.ID, p2}} {
			for ttl := 1; ttl <= 4; ttl++ {
				lost := 0
				switch ttl {
				case 1:
					lost = gwLoss
				case 4:
					lost = dstLoss
				}
				mb.ICMP = append(mb.ICMP, store.ICMPRow{TargetID: x.tid, TTL: ttl, PathID: x.path, Bucket: b.UnixMicro(), Roll: roll(30, lost, 5)})
			}
		}
		return mb
	}
	// warm: the gateway has answered before
	f.an.OnMinute(mk(0, 0, 0))
	if f.an.Local().Down {
		t.Fatal("down while healthy")
	}
	f.an.OnMinute(mk(1, 30, 30)) // gateway silent and both targets failing
	if !f.an.Local().Down || f.an.Local().Reason != "gateway" {
		t.Fatalf("local state: %+v", f.an.Local())
	}
	last := f.eng.minutes[len(f.eng.minutes)-1]
	if !last.Local.Down {
		t.Error("engine should be told about the local outage")
	}
	outs := f.localEvents(t)
	if len(outs) != 1 || outs[0].TargetID != nil || outs[0].To != nil {
		t.Fatalf("local_outage events: %+v", outs)
	}
	f.an.OnMinute(mk(2, 0, 0))
	f.an.OnMinute(mk(3, 0, 0))
	if f.an.Local().Down {
		t.Error("outage should have ended")
	}
	if outs := f.localEvents(t); len(outs) != 1 || outs[0].To == nil {
		t.Errorf("event not closed: %+v", outs)
	}
}

func (f *fixture) localEvents(t *testing.T) []store.Event {
	f.st.Sync()
	evs, err := f.st.Events(store.EventQuery{From: f.t0.Add(-time.Hour), To: f.t0.Add(24 * time.Hour), Kinds: []string{store.EventLocalOutage}})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestAnalyzerRestoresOpenEvents(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 3; i++ {
		f.an.OnMinute(f.minute(i, [5]int{0, 0, 18, 0, 0}, 0))
	}
	// a restarted analyzer resumes the open event instead of creating a second one
	an2 := New(f.st, f.an.topo, f.eng, nil)
	an2.Start()
	for i := 3; i < 8; i++ {
		an2.OnMinute(f.minute(i, [5]int{0, 0, 18, 0, 0}, 0))
	}
	if evs := f.events(t, store.EventRateLimited); len(evs) != 1 {
		t.Errorf("duplicate events after restart: %d", len(evs))
	}
}

func TestAnalyzerBaselinesFeedLatencyBands(t *testing.T) {
	f := newFixture(t)
	// 40 minutes of healthy data build baselines
	for i := 0; i < 40; i++ {
		f.an.OnMinute(f.minute(i, [5]int{}, 0))
	}
	if f.an.bands.Len(hopKey(f.tid, 3)) != 40 {
		t.Errorf("baseline samples: %d", f.an.bands.Len(hopKey(f.tid, 3)))
	}
	// a latency step at every hop and the TCP probe = real degradation even without loss
	b := f.t0.Add(41 * time.Minute)
	mb := store.MinuteBatch{Bucket: b}
	for ttl := 1; ttl <= 4; ttl++ {
		avg := float64(ttl) * 5
		if ttl >= 3 {
			avg += 200
		}
		mb.ICMP = append(mb.ICMP, store.ICMPRow{TargetID: f.tid, TTL: ttl, PathID: f.path, Bucket: b.UnixMicro(), Roll: roll(30, 0, avg)})
	}
	mb.Probes = []store.ProbeRollRow{{ProbeID: f.tcp, Bucket: b.UnixMicro(), Roll: probeRoll(6, 0, 250)}}
	f.an.OnMinute(mb)
	an, _ := f.an.Latest(f.tid)
	if !an.Real || an.StartTTL != 3 {
		t.Errorf("latency step: %+v", an)
	}
	// degraded minutes do not enter the baseline (frozen)
	if f.an.bands.Len(hopKey(f.tid, 3)) != 40 {
		t.Errorf("degraded minute fed the baseline: %d", f.an.bands.Len(hopKey(f.tid, 3)))
	}
}

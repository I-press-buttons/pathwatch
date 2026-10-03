package analyze

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// ProbeInfo describes one probe of a target for the analyzer.
type ProbeInfo struct {
	ID    int64
	Type  string // icmp-trace | http | tcp | dns
	Label string
}

// TargetInfo describes a running target for the analyzer.
type TargetInfo struct {
	ID               int64
	Name             string
	ICMPUnresponsive bool
	Probes           []ProbeInfo
}

// Topology tells the analyzer which targets and probes exist. The scheduler implements it.
type Topology interface {
	Targets() []TargetInfo
	DNSProbes() []ProbeInfo
}

// Analysis is the latest classification of a target.
type Analysis struct {
	At       time.Time
	Classes  map[int]string // ttl -> class (ok | rate_limited | degraded | no_reply)
	Real     bool
	StartTTL int
}

type ttlKey struct {
	target int64
	ttl    int
}

// Analyzer consumes completed 1-minute batches: it classifies hops, records rate-limited and
// degraded state transitions as events, detects local outages and forwards a per-minute summary
// to the alert engine.
type Analyzer struct {
	st     *store.Store
	topo   Topology
	engine alert.Engine
	log    *slog.Logger
	params Params

	bands   *BandTracker
	tracker *Tracker
	local   *LocalOutageDetector

	mu        sync.Mutex
	ever      map[ttlKey]bool
	eventIDs  map[Key]int64
	localEv   int64
	latest    map[int64]Analysis
	localSt   alert.LocalState
	pathDest  map[int64]int
	processed int
}

// New creates an analyzer. engine may be nil (then alert.Nop is used).
func New(st *store.Store, topo Topology, engine alert.Engine, log *slog.Logger) *Analyzer {
	if engine == nil {
		engine = alert.Nop{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Analyzer{
		st: st, topo: topo, engine: engine, log: log, params: DefaultParams(),
		bands: NewBandTracker(), tracker: NewTracker(), local: NewLocalOutageDetector(),
		ever: map[ttlKey]bool{}, eventIDs: map[Key]int64{}, latest: map[int64]Analysis{}, pathDest: map[int64]int{},
	}
}

// Start restores open events and subscribes to the store's completed minutes.
func (a *Analyzer) Start() {
	if evs, err := a.st.OpenEvents(store.EventRateLimited, store.EventDegraded, store.EventLocalOutage); err == nil {
		for _, e := range evs {
			switch {
			case e.Kind == store.EventLocalOutage:
				a.localEv = e.ID
			case e.TargetID != nil && e.TTL != nil:
				k := Key{Target: *e.TargetID, TTL: *e.TTL, Class: e.Kind}
				a.tracker.Restore(k)
				a.eventIDs[k] = e.ID
			}
		}
	}
	a.st.SubscribeMinutes(a.OnMinute)
}

// Latest returns the most recent classification of a target.
func (a *Analyzer) Latest(targetID int64) (Analysis, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v, ok := a.latest[targetID]
	return v, ok
}

// Local returns the current local-connectivity state.
func (a *Analyzer) Local() alert.LocalState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.localSt
}

// HasData reports whether at least one minute has been analysed (local status is "unknown" before).
func (a *Analyzer) HasData() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.processed > 0
}

// HandleProbe forwards an individual probe result to the alert engine.
func (a *Analyzer) HandleProbe(s alert.ProbeSample) { a.engine.HandleProbe(s) }

func statOf(r *store.Roll) alert.Stat {
	s := alert.Stat{Sent: int(r.N), Lost: int(r.Lost)}
	s.LossPct, _ = r.LossPct()
	if avg, ok := r.Avg(); ok {
		s.AvgMS, s.HaveAvg = avg, true
	}
	s.P95MS, _ = r.Quantile(0.95)
	s.JitterMS, _ = r.Jitter()
	return s
}

func probeMinute(info ProbeInfo, r *store.ProbeRoll) alert.ProbeMinute {
	pm := alert.ProbeMinute{ProbeID: info.ID, Type: info.Type, Label: info.Label, N: int(r.N), Errors: int(r.Errors)}
	if v, ok := r.AvgTotal(); ok {
		pm.AvgTotalMS, pm.HaveAvg = v, true
	}
	pm.AvgTTFBMS, _ = r.AvgTTFB()
	pm.P95TotalMS, _ = r.Quantile(0.95)
	if r.CertNotAfter != 0 {
		pm.CertNotAfter = time.UnixMicro(r.CertNotAfter).UTC()
	}
	return pm
}

func hopKey(target int64, ttl int) string { return fmt.Sprintf("h:%d:%d", target, ttl) }
func probeKey(id int64) string            { return fmt.Sprintf("p:%d", id) }

// OnMinute processes one completed minute. It is registered with store.SubscribeMinutes.
func (a *Analyzer) OnMinute(mb store.MinuteBatch) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.processed++

	rowsByTarget := map[int64][]store.ICMPRow{}
	for _, r := range mb.ICMP {
		rowsByTarget[r.TargetID] = append(rowsByTarget[r.TargetID], r)
	}
	probeRolls := map[int64]*store.ProbeRoll{}
	for _, p := range mb.Probes {
		probeRolls[p.ProbeID] = p.Roll
	}

	out := alert.Minute{Bucket: mb.Bucket}
	var health []TargetHealth

	for _, ti := range a.topo.Targets() {
		rows := rowsByTarget[ti.ID]
		tm := alert.TargetMinute{TargetID: ti.ID, Name: ti.Name, ICMPUnresponsive: ti.ICMPUnresponsive}
		th := TargetHealth{TargetID: ti.ID}

		// probes of this target
		var signals []SignalStat
		var tcpRoll *store.ProbeRoll
		var tcpInfo ProbeInfo
		var httpRoll *store.ProbeRoll
		for _, pi := range ti.Probes {
			r := probeRolls[pi.ID]
			if r == nil || r.N == 0 {
				continue
			}
			pm := probeMinute(pi, r)
			sig := SignalStat{Name: pi.Label, Sent: int(r.N), Failed: int(r.Errors)}
			if v, ok := r.AvgTotal(); ok {
				sig.AvgMs, sig.HaveAvg = v, true
			}
			if _, up, ok := a.bands.Band(probeKey(pi.ID)); ok {
				sig.Upper = up
			}
			switch pi.Type {
			case "tcp":
				tm.TCP = append(tm.TCP, pm)
				signals = append(signals, sig)
				if tcpRoll == nil {
					tcpRoll, tcpInfo = r, pi
				}
			case "http":
				tm.HTTP = append(tm.HTTP, pm)
				signals = append(signals, sig)
				if httpRoll == nil {
					httpRoll = r
				}
			}
			// freeze: only healthy minutes feed the baseline
			if sig.HaveAvg && judge(a.params.norm(), sig.Sent, sig.Failed, sig.AvgMs, sig.HaveAvg, sig.Upper) != StateDegraded {
				a.bands.Observe(probeKey(pi.ID), sig.AvgMs)
			}
		}
		_ = tcpInfo

		// ICMP hops of the dominant path version in this minute
		var hopStats []HopStat
		var destTTL int
		hopRolls := map[int]*store.Roll{}
		if len(rows) > 0 {
			dom := dominantPath(rows)
			destTTL = a.destTTL(dom)
			maxTTL := 0
			for _, r := range rows {
				if r.PathID != dom {
					continue
				}
				hopRolls[r.TTL] = r.Roll
				if r.TTL > maxTTL {
					maxTTL = r.TTL
				}
			}
			for ttl := 1; ttl <= maxTTL; ttl++ {
				r := hopRolls[ttl]
				if r == nil {
					continue
				}
				k := ttlKey{ti.ID, ttl}
				if r.Replies() > 0 {
					a.ever[k] = true
				}
				hs := HopStat{TTL: ttl, Sent: int(r.N), Lost: int(r.Lost), EverResponded: a.ever[k], IsDest: ttl == destTTL}
				if avg, ok := r.Avg(); ok {
					hs.AvgMs, hs.HaveAvg = avg, true
				}
				if _, up, ok := a.bands.Band(hopKey(ti.ID, ttl)); ok {
					hs.Upper = up
				}
				hopStats = append(hopStats, hs)
			}
		}

		if len(hopStats) > 0 {
			res := Classify(a.params, hopStats, signals)
			an := Analysis{At: mb.Bucket, Classes: map[int]string{}, Real: res.Real, StartTTL: res.StartTTL}
			for i, hc := range res.Hops {
				an.Classes[hc.TTL] = hc.Class
				hs := hopStats[i]
				a.observeClass(ti.ID, hc, hs, mb.Bucket)
				if hs.HaveAvg && !hc.Degraded {
					a.bands.Observe(hopKey(ti.ID, hc.TTL), hs.AvgMs)
				}
				tm.Hops = append(tm.Hops, alert.HopMinute{TTL: hc.TTL, Stat: statOf(hopRolls[hc.TTL]), Class: hc.Class})
				if hs.Sent > 0 && hs.Lost == hs.Sent && hs.EverResponded {
					if hc.TTL == 1 {
						th.Gateway1Down = true
					}
					if hc.TTL == 2 {
						th.Gateway2Down = true
					}
				}
			}
			a.latest[ti.ID] = an
			if res.Real {
				tm.Degradation = &alert.Degradation{StartTTL: res.StartTTL}
			}
		}
		// hops that disappeared from the path no longer carry a class
		a.endMissing(ti.ID, hopStats, mb.Bucket)

		// end-to-end stat
		switch {
		case destTTL > 0 && hopRolls[destTTL] != nil && hopRolls[destTTL].N > 0:
			s := statOf(hopRolls[destTTL])
			tm.E2E, tm.E2ESource = &s, "icmp"
		case tcpRoll != nil:
			r := tcpRoll
			s := alert.Stat{Sent: int(r.N), Lost: int(r.Errors)}
			s.LossPct, _ = r.FailPct()
			if v, ok := r.AvgTotal(); ok {
				s.AvgMS, s.HaveAvg = v, true
			}
			s.P95MS, _ = r.Quantile(0.95)
			tm.E2E, tm.E2ESource = &s, "tcp"
		case len(hopStats) > 0:
			last := 0
			for _, hs := range hopStats {
				if hs.HaveAvg {
					last = hs.TTL
				}
			}
			if last > 0 {
				s := statOf(hopRolls[last])
				tm.E2E, tm.E2ESource = &s, "last_hop"
			}
		case httpRoll != nil:
			r := httpRoll
			s := alert.Stat{Sent: int(r.N), Lost: int(r.Errors)}
			s.LossPct, _ = r.FailPct()
			if v, ok := r.AvgTotal(); ok {
				s.AvgMS, s.HaveAvg = v, true
			}
			tm.E2E, tm.E2ESource = &s, "http"
		}
		if tm.E2E != nil && tm.E2E.Sent >= a.params.norm().MinSamples {
			th.E2EKnown = true
			th.E2EFailing = tm.E2E.LossPct > a.params.norm().LossThreshold
		}
		if len(rows) > 0 || len(tm.HTTP) > 0 || len(tm.TCP) > 0 {
			out.Targets = append(out.Targets, tm)
			health = append(health, th)
		}
	}

	for _, pi := range a.topo.DNSProbes() {
		if r := probeRolls[pi.ID]; r != nil && r.N > 0 {
			out.DNS = append(out.DNS, probeMinute(pi, r))
		}
	}

	if len(health) > 0 {
		st, changed := a.local.Observe(mb.Bucket, health)
		if changed {
			a.onLocalChange(st, mb.Bucket)
		}
	}
	out.Local = a.localSt
	sort.Slice(out.Targets, func(i, j int) bool { return out.Targets[i].TargetID < out.Targets[j].TargetID })
	a.engine.HandleMinute(out)
}

func dominantPath(rows []store.ICMPRow) int64 {
	n := map[int64]int64{}
	for _, r := range rows {
		n[r.PathID] += r.Roll.N
	}
	var best int64
	var bestN int64 = -1
	for p, c := range n {
		if c > bestN || (c == bestN && p > best) {
			best, bestN = p, c
		}
	}
	return best
}

func (a *Analyzer) destTTL(path int64) int {
	if m, err := a.st.PathsOf([]int64{path}); err == nil {
		if p, ok := m[path]; ok {
			a.pathDest[path] = p.DestTTL
		}
	}
	return a.pathDest[path]
}

func (a *Analyzer) observeClass(target int64, hc HopClass, hs HopStat, at time.Time) {
	for _, class := range []string{ClassRateLimited, ClassDegraded} {
		k := Key{Target: target, TTL: hc.TTL, Class: class}
		tr := a.tracker.Observe(k, hc.Class == class, at)
		if tr != nil {
			a.applyTransition(*tr, hs)
		}
	}
}

func (a *Analyzer) endMissing(target int64, present []HopStat, at time.Time) {
	have := map[int]bool{}
	for _, h := range present {
		have[h.TTL] = true
	}
	for _, k := range a.tracker.Keys(true) {
		if k.Target != target || have[k.TTL] {
			continue
		}
		if tr := a.tracker.Observe(k, false, at); tr != nil {
			a.applyTransition(*tr, HopStat{})
		}
	}
}

func (a *Analyzer) applyTransition(tr Transition, hs HopStat) {
	if tr.Start {
		ttl := tr.TTL
		tid := tr.Target
		det, _ := json.Marshal(map[string]any{"loss_pct": round1(100 * float64(hs.Lost) / float64(maxInt(hs.Sent, 1))), "avg_ms": round1(hs.AvgMs)})
		id, err := a.st.InsertEvent(store.Event{TargetID: &tid, Kind: tr.Class, TTL: &ttl, From: tr.At, Details: det})
		if err != nil {
			a.log.Warn("record classification event failed", "err", err)
			return
		}
		a.eventIDs[tr.Key] = id
		if tr.Class == ClassRateLimited {
			a.log.Info("hop classified as ICMP rate-limited", "target", tr.Target, "ttl", tr.TTL)
		}
		return
	}
	if id, ok := a.eventIDs[tr.Key]; ok {
		a.st.CloseEvent(id, tr.At)
		delete(a.eventIDs, tr.Key)
	}
}

func (a *Analyzer) onLocalChange(st LocalState, at time.Time) {
	a.localSt = alert.LocalState{Down: st.Down, Since: st.Since, Reason: st.Reason}
	if st.Down {
		det, _ := json.Marshal(map[string]string{"reason": st.Reason})
		id, err := a.st.InsertEvent(store.Event{Kind: store.EventLocalOutage, From: st.Since, Details: det})
		if err == nil {
			a.localEv = id
		}
		a.log.Warn("local connectivity problem detected", "reason", st.Reason, "since", st.Since)
		return
	}
	if a.localEv != 0 {
		a.st.CloseEvent(a.localEv, at)
		a.localEv = 0
	}
	a.log.Info("local connectivity restored")
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Close releases the analyzer's resources.
func (a *Analyzer) Close() { a.engine.Close() }

package alert

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// gapLimit is the longest silence between two completed minutes that is still "normal". A longer
// one means the monitor itself was not running (or the host slept): pending conditions and
// clear-holds restart, and nothing triggers or resolves on the missing data.
const gapLimit = 3 * time.Minute

// probeFallbackLag bounds how long a probe sample waits for its minute to be analysed.
const probeFallbackLag = 3 * time.Minute

// maxQueuedSamples caps the sample queue (it only grows when minutes stop flowing).
const maxQueuedSamples = 20000

// RuleEngineOptions configure a RuleEngine.
type RuleEngineOptions struct {
	Store  *store.Store
	Sink   AlertSink // optional: receives every alert change (SSE)
	Config *config.Config
	Log    *slog.Logger
	// Now overrides the clock (tests).
	Now func() time.Time
	// Healthy reports whether the monitor is healthy (the /healthz signal); gates the heartbeat.
	Healthy func() bool
	// SyncBaselines computes baselines inline instead of in the background (tests).
	SyncBaselines bool
	// Sender overrides the outbox sender (tests); by default one is created from Config.
	Sender *Sender
}

// probeState is what the engine tracks per probe between samples.
type probeState struct {
	lastTS     time.Time
	ivl        time.Duration // typical interval between samples
	fails, oks int
	failSince  time.Time
	okSince    time.Time
	lastErr    string
	lastCert   time.Time
}

// RuleEngine is the alert rule engine: it evaluates the configured rules against the analyzer's
// per-minute output and the individual probe results, runs the pending/firing/resolved state
// machines, persists alerts, records suppressed ones and queues notifications in the outbox.
// It implements Engine.
type RuleEngine struct {
	st     *store.Store
	sink   AlertSink
	log    *slog.Logger
	now    func() time.Time
	sender *Sender
	hb     *Heartbeat
	base   *baselines

	mu         sync.Mutex
	cfg        *settings
	states     map[stateKey]*ruleState
	probes     map[int64]*probeState
	queue      []ProbeSample
	names      map[int64]string
	labels     map[int64]string
	probeCount map[int64]map[string]map[int64]bool // target -> probe type -> probe ids
	local      LocalState
	localState *ruleState
	lastMinute time.Time
	minuteCut  time.Time
	certSeen   map[int64]map[int64]bool // probe -> NotAfter (unix ms) values already alerted
	routeSeen  map[int64]bool           // route_change event ids already handled
	routeFrom  time.Time
	closed     bool
	lastPrune  time.Time
	cur        time.Time // data time of the observation being processed
	ownSender  bool      // the engine built the sender from the config (and reconfigures it on reload)
}

// NewRuleEngine creates the engine, restores active alerts, cooldowns and the once-per-event
// bookkeeping from the database, and returns it ready for HandleMinute/HandleProbe. Call Start to
// launch the outbox sender and the heartbeat.
func NewRuleEngine(o RuleEngineOptions) *RuleEngine {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	e := &RuleEngine{
		st: o.Store, sink: o.Sink, log: o.Log, now: o.Now,
		cfg: newSettings(o.Config), states: map[stateKey]*ruleState{}, probes: map[int64]*probeState{},
		names: map[int64]string{}, labels: map[int64]string{}, probeCount: map[int64]map[string]map[int64]bool{},
		certSeen: map[int64]map[int64]bool{}, routeSeen: map[int64]bool{},
	}
	e.sender = o.Sender
	e.ownSender = o.Sender == nil
	if e.sender == nil {
		e.sender = NewSender(o.Store, o.Sink, o.Log, o.Now)
		e.sender.Configure(o.Config)
	}
	e.base = newBaselines(o.Store, o.Now, !o.SyncBaselines)
	e.hb = NewHeartbeat(o.Log, o.Healthy)
	e.hb.Configure(o.Config.Alerts.Heartbeat)
	e.routeFrom = o.Now().Add(-2 * time.Minute)
	e.lastPrune = o.Now()
	e.restore()
	return e
}

// Start launches the outbox sender and the heartbeat.
func (e *RuleEngine) Start() {
	e.sender.Start()
	e.hb.Start()
}

// Close stops the background goroutines and writes back unsaved alert values.
func (e *RuleEngine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	for _, st := range e.states {
		if st.alert != nil && st.dirty {
			e.save(st, false)
		}
	}
	e.mu.Unlock()
	e.hb.Close()
	e.sender.Close()
}

// Sender returns the outbox sender (for tests and diagnostics).
func (e *RuleEngine) Sender() *Sender { return e.sender }

// Reload applies a new configuration: rules, thresholds, channels, maintenance windows and the
// heartbeat. Alerts of rules that no longer apply are resolved.
func (e *RuleEngine) Reload(cfg *config.Config) {
	if e.ownSender {
		e.sender.Configure(cfg)
	}
	e.hb.Configure(cfg.Alerts.Heartbeat)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = newSettings(cfg)
	e.names = map[int64]string{} // targets may have been renamed in the UI
	e.resolveOrphans(e.now())
}

// restore rebuilds the state machines of alerts that were active when the process stopped, so a
// restart neither re-fires nor loses them, plus the cooldown and once-per-event memory.
func (e *RuleEngine) restore() {
	now := e.now()
	active, err := e.st.ActiveAlerts()
	if err != nil {
		e.log.Error("restoring active alerts failed", "err", err)
	}
	for i := range active {
		a := active[i]
		var d map[string]any
		_ = json.Unmarshal([]byte(a.DetailsJSON), &d)
		var tid, subject int64
		if a.TargetID != nil {
			tid = *a.TargetID
		}
		if v, ok := d["probe_id"].(float64); ok {
			subject = int64(v)
		}
		st := &ruleState{key: stateKey{tid, a.Rule, subject}, rtype: a.RuleType, alert: &a, details: d}
		if st.rtype == RuleLocalConnectivity {
			st.key = stateKey{0, RuleLocalConnectivity, 0}
			st.rule = config.RuleConfig{Name: RuleLocalConnectivity, Type: RuleLocalConnectivity}
			st.tname = "local connection"
			e.localState = st
		}
		if a.PeakValue != nil {
			st.peak = *a.PeakValue
		}
		if a.Baseline != nil {
			st.baseMed = *a.Baseline
		}
		if v, ok := d["mad"].(float64); ok {
			st.baseMAD = v
		}
		if v, ok := d["threshold"].(float64); ok {
			st.threshold = v
		}
		if v, ok := d["not_after_ms"].(float64); ok {
			st.certNotAfter = time.UnixMilli(int64(v)).UTC()
		}
		if v, ok := d["probe"].(string); ok {
			st.label = v
		}
		e.states[st.key] = st
	}
	if cd := e.cfg.cooldown; cd > 0 {
		if rs, err := e.st.AlertsEndedSince(now.Add(-cd)); err == nil {
			for _, a := range rs {
				var tid, subject int64
				if a.TargetID != nil {
					tid = *a.TargetID
				}
				var d map[string]any
				_ = json.Unmarshal([]byte(a.DetailsJSON), &d)
				if v, ok := d["probe_id"].(float64); ok {
					subject = int64(v)
				}
				k := stateKey{tid, a.Rule, subject}
				st := e.states[k]
				if st == nil {
					st = &ruleState{key: k, rtype: a.RuleType}
					e.states[k] = st
				}
				if a.EndedAt != nil && a.EndedAt.After(st.lastResolved) {
					st.lastResolved = *a.EndedAt
				}
			}
		}
	}
	if as, err := e.st.AlertsOfType("cert_expiry", 500); err == nil {
		for _, a := range as {
			var d struct {
				ProbeID  int64 `json:"probe_id"`
				NotAfter int64 `json:"not_after_ms"`
			}
			if json.Unmarshal([]byte(a.DetailsJSON), &d) == nil && d.ProbeID != 0 && d.NotAfter != 0 {
				e.markCert(d.ProbeID, d.NotAfter)
			}
		}
	}
	if as, err := e.st.AlertsOfType("route_change", 200); err == nil {
		for _, a := range as {
			var d struct {
				EventID int64 `json:"event_id"`
			}
			if json.Unmarshal([]byte(a.DetailsJSON), &d) == nil && d.EventID != 0 {
				e.routeSeen[d.EventID] = true
			}
		}
	}
	if len(active) > 0 {
		e.log.Info("restored active alerts", "count", len(active))
	}
}

func (e *RuleEngine) markCert(probe, notAfterMS int64) {
	m := e.certSeen[probe]
	if m == nil {
		m = map[int64]bool{}
		e.certSeen[probe] = m
	}
	m[notAfterMS] = true
}

// state returns the state machine for a key, creating it. The rule is refreshed on every call
// (configuration changes apply to the next evaluation).
func (e *RuleEngine) state(k stateKey, rtype string, rule config.RuleConfig, tname, label string) *ruleState {
	st := e.states[k]
	if st == nil {
		st = &ruleState{key: k}
		e.states[k] = st
	}
	st.rtype, st.rule, st.tname = rtype, rule, tname
	if label != "" {
		st.label = label
	}
	return st
}

func (e *RuleEngine) targetName(id int64) string {
	if n, ok := e.names[id]; ok {
		return n
	}
	if id != 0 {
		if t, err := e.st.Target(id); err == nil {
			e.names[id] = t.Name
			return t.Name
		}
	}
	return fmt.Sprintf("target %d", id)
}

func (e *RuleEngine) probeLabel(id int64) string {
	if l, ok := e.labels[id]; ok {
		return l
	}
	return fmt.Sprintf("probe %d", id)
}

// multi reports whether the target has more than one probe of the type (then messages name it).
func (e *RuleEngine) multi(target int64, typ string) bool {
	return len(e.probeCount[target][typ]) > 1
}

func (e *RuleEngine) noteProbe(target int64, typ string, id int64, label string) {
	if label != "" {
		e.labels[id] = label
	}
	m := e.probeCount[target]
	if m == nil {
		m = map[string]map[int64]bool{}
		e.probeCount[target] = m
	}
	if m[typ] == nil {
		m[typ] = map[int64]bool{}
	}
	m[typ][id] = true
}

func (e *RuleEngine) withLabel(msg string, target int64, typ string, label string) string {
	if label != "" && (target == 0 || e.multi(target, typ)) {
		return msg + " (" + label + ")"
	}
	return msg
}

// ---------------------------------------------------------------------------
// HandleProbe

// HandleProbe queues an individual probe result. Results are analysed once the minute they
// belong to has been analysed (so the local-outage verdict for that time is known), or after a
// short fallback delay when minutes stop arriving.
func (e *RuleEngine) HandleProbe(s ProbeSample) {
	if s.Type != "http" && s.Type != "tcp" && s.Type != "dns" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	if len(e.queue) >= maxQueuedSamples {
		e.queue = e.queue[len(e.queue)/2:]
	}
	e.queue = append(e.queue, s)
	cut := s.TS.Add(-probeFallbackLag)
	if e.minuteCut.After(cut) {
		cut = e.minuteCut
	}
	e.drain(cut)
}

// drain analyses queued samples older than cutoff, in arrival order.
func (e *RuleEngine) drain(cutoff time.Time) {
	if len(e.queue) == 0 {
		return
	}
	keep := e.queue[:0:0]
	var ready []ProbeSample
	for _, s := range e.queue {
		if s.TS.Before(cutoff) {
			ready = append(ready, s)
		} else {
			keep = append(keep, s)
		}
	}
	e.queue = keep
	for _, s := range ready {
		e.processSample(s)
	}
}

func (e *RuleEngine) processSample(s ProbeSample) {
	ps := e.probes[s.ProbeID]
	if ps == nil {
		ps = &probeState{}
		e.probes[s.ProbeID] = ps
	}
	// consecutive means consecutive in time: a stall (the monitor was not probing) breaks the streak
	if !ps.lastTS.IsZero() {
		delta := s.TS.Sub(ps.lastTS)
		if ps.ivl > 0 && delta > 3*ps.ivl && delta > 30*time.Second {
			ps.fails, ps.oks = 0, 0
			ps.failSince, ps.okSince = time.Time{}, time.Time{}
		} else if delta > 0 && (ps.ivl == 0 || delta < ps.ivl*2) {
			ps.ivl = delta
		}
	}
	ps.lastTS = s.TS
	if s.OK {
		if ps.oks == 0 {
			ps.okSince = s.TS
		}
		ps.oks++
		ps.fails = 0
		ps.failSince = time.Time{}
	} else {
		if ps.fails == 0 {
			ps.failSince = s.TS
		}
		ps.fails++
		ps.oks = 0
		ps.okSince = time.Time{}
		ps.lastErr = failureReason(s)
	}
	var ruleType string
	switch s.Type {
	case "http":
		ruleType = "http_failure"
	case "tcp":
		ruleType = "tcp_failure"
	default:
		ruleType = "dns_failure"
	}
	tname := ""
	if s.TargetID != 0 {
		tname = e.targetName(s.TargetID)
	}
	label := e.probeLabel(s.ProbeID)
	if s.TargetID == 0 {
		tname = label
	}
	ruleTarget := tname
	if s.TargetID == 0 {
		ruleTarget = "" // DNS probes are not bound to a target: per-target disable/override cannot apply
	}
	for _, r := range e.cfg.rulesFor(ruleTarget, ruleType) {
		n := r.Consecutive
		if n < 1 {
			n = 1
		}
		st := e.state(stateKey{s.TargetID, r.Name, s.ProbeID}, ruleType, r, tname, label)
		o := obs{
			at: s.TS, breach: ps.fails >= n, clear: ps.oks >= n,
			value: float64(ps.fails), hasValue: ps.fails > 0, since: ps.failSince, clearFrom: ps.okSince, unit: "failures",
		}
		if ps.fails > 0 {
			noun := "probe"
			if s.TargetID == 0 {
				noun = "probe " + label
			}
			o.msg = fmt.Sprintf("%s %s failing: %s in a row (%s)", probeKind(ruleType), noun, pluralize(ps.fails, "failure", "failures"), ps.lastErr)
			if s.TargetID != 0 {
				o.msg = e.withLabel(o.msg, s.TargetID, s.Type, label)
			}
		}
		o.details = map[string]any{"consecutive": n, "last_error": ps.lastErr}
		e.step(st, o)
	}
	if s.Type == "http" && !s.CertNotAfter.IsZero() {
		e.processCert(s, ps, tname)
	}
}

// processCert applies the cert_expiry rules to one HTTPS sample.
func (e *RuleEngine) processCert(s ProbeSample, ps *probeState, tname string) {
	na := s.CertNotAfter.UTC()
	ps.lastCert = na
	for _, r := range e.cfg.rulesFor(tname, "cert_expiry") {
		st := e.state(stateKey{s.TargetID, r.Name, s.ProbeID}, "cert_expiry", r, tname, e.probeLabel(s.ProbeID))
		if st.active() {
			if na.Equal(st.certNotAfter) {
				st.certChanged = 0
				days := daysUntil(na, s.TS)
				v := days
				st.alert.Value = &v
				continue
			}
			// the certificate was replaced; require two samples so a load balancer serving
			// two certificates does not flap
			st.certChanged++
			if st.certChanged >= 2 {
				st.clearSince = s.TS
				e.resolve(st, s.TS)
			}
			continue
		}
		remaining := na.Sub(s.TS)
		if remaining > r.WarnBefore.D() || e.certSeen[s.ProbeID][na.UnixMilli()] {
			continue
		}
		e.markCert(s.ProbeID, na.UnixMilli())
		st.certNotAfter = na
		days := daysUntil(na, s.TS)
		e.step(st, obs{
			at: s.TS, breach: true, since: s.TS, hasValue: true, value: days, unit: "days",
			msg:     e.withLabel(certMessage(na, s.TS), s.TargetID, "http", st.label),
			details: map[string]any{"warn_before": FormatDuration(r.WarnBefore.D())},
		})
	}
}

// ---------------------------------------------------------------------------
// HandleMinute

// HandleMinute evaluates the minute-based rules for one completed minute.
func (e *RuleEngine) HandleMinute(m Minute) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	end := m.Bucket.Add(time.Minute)
	if !e.lastMinute.IsZero() && m.Bucket.Sub(e.lastMinute) > gapLimit {
		e.onGap(m.Bucket)
	}
	e.lastMinute = m.Bucket
	e.minuteCut = end

	e.handleLocal(m, end)
	e.drain(end)

	for _, tm := range m.Targets {
		e.names[tm.TargetID] = tm.Name
		for _, pm := range tm.HTTP {
			e.noteProbe(tm.TargetID, "http", pm.ProbeID, pm.Label)
		}
		for _, pm := range tm.TCP {
			e.noteProbe(tm.TargetID, "tcp", pm.ProbeID, pm.Label)
		}
	}
	for _, pm := range m.DNS {
		e.noteProbe(0, "dns", pm.ProbeID, pm.Label)
	}
	for _, tm := range m.Targets {
		e.evalLoss(tm, m.Bucket, end)
		e.evalDegradation(tm, m.Bucket, end)
		for _, pm := range tm.HTTP {
			e.evalLatency(tm.TargetID, tm.Name, pm, "http_latency", end)
		}
	}
	for _, pm := range m.DNS {
		e.evalLatency(0, pm.Label, pm, "dns_latency", end)
	}
	e.handleRouteChanges()
	e.housekeeping(end)
}

// onGap restarts every pending condition and clear-hold: a monitor gap is "no data", never
// evidence. Firing alerts stay firing.
func (e *RuleEngine) onGap(at time.Time) {
	e.log.Info("monitor gap detected; alert conditions restart", "resume", at)
	for _, st := range e.states {
		st.win = nil
		st.clearSince = time.Time{}
		if !st.active() {
			st.since = time.Time{}
		}
	}
	for _, ps := range e.probes {
		ps.fails, ps.oks = 0, 0
		ps.failSince, ps.okSince = time.Time{}, time.Time{}
	}
}

// housekeeping promotes suppressed alerts whose suppression ended and resolves alerts of rules
// that no longer exist.
func (e *RuleEngine) housekeeping(end time.Time) {
	for _, st := range e.states {
		if st.alert != nil && st.alert.State == "suppressed" && st.alert.EndedAt == nil && st.rule.Name != "" {
			e.maybePromote(st, end)
		}
	}
	e.resolveOrphans(end)
	if end.Sub(e.lastPrune) > 10*time.Minute {
		e.lastPrune = end
		for k := range e.states {
			if k.target == 0 {
				continue
			}
			if _, err := e.st.Target(k.target); errors.Is(err, store.ErrNotFound) {
				delete(e.states, k) // the target was deleted (and its alerts with it)
			}
		}
	}
}

// resolveOrphans ends active alerts whose rule was removed or disabled (or disabled for the
// target) in the configuration.
func (e *RuleEngine) resolveOrphans(at time.Time) {
	for _, st := range e.states {
		if st.alert == nil || st.rtype == RuleLocalConnectivity {
			continue
		}
		tname := st.tname
		if tname == "" && st.key.target != 0 {
			if n, ok := e.names[st.key.target]; ok {
				tname = n
			} else {
				continue // not seen since the restart; cannot judge per-target overrides yet
			}
		}
		if st.key.target == 0 {
			tname = ""
		}
		if _, ok := e.cfg.ruleByName(tname, st.alert.Rule); !ok {
			st.clearSince = at
			e.log.Info("rule no longer applies; resolving its alert", "rule", st.alert.Rule, "target", tname)
			e.resolve(st, at)
		}
	}
}

// handleLocal runs the built-in local_connectivity alert.
func (e *RuleEngine) handleLocal(m Minute, end time.Time) {
	e.local = m.Local
	ls := e.localState
	if ls == nil {
		ls = &ruleState{
			key: stateKey{0, RuleLocalConnectivity, 0}, rtype: RuleLocalConnectivity, tname: "local connection",
			rule: config.RuleConfig{Name: RuleLocalConnectivity, Type: RuleLocalConnectivity},
		}
		e.localState = ls
		e.states[ls.key] = ls
	}
	if m.Local.Down && !ls.active() {
		reason := m.Local.Reason
		msg := "Local connectivity problem"
		switch reason {
		case "gateway":
			msg = "Local connectivity lost: the gateway (hop 1 or 2) stopped responding"
		case "all_targets":
			msg = "Local connectivity lost: every target is failing at once"
		}
		since := m.Local.Since
		if since.IsZero() {
			since = m.Bucket
		}
		ls.since = since
		e.activate(ls, obs{at: end, breach: true, since: since, msg: msg, details: map[string]any{"reason": reason}})
		return
	}
	if !m.Local.Down && ls.active() {
		// the analyzer declares recovery after two clean minutes; the outage ended before them
		ls.clearSince = m.Bucket.Add(-time.Minute)
		e.resolve(ls, end)
	}
}

// evalLoss runs final_hop_loss: end-to-end loss (destination ICMP, or the TCP probe for targets
// that do not answer ICMP) over the rule's window.
func (e *RuleEngine) evalLoss(tm TargetMinute, bucket, end time.Time) {
	if tm.E2E == nil || (tm.E2ESource != "icmp" && tm.E2ESource != "tcp") || tm.E2E.Sent == 0 {
		return
	}
	for _, r := range e.cfg.rulesFor(tm.Name, "final_hop_loss") {
		st := e.state(stateKey{tm.TargetID, r.Name, 0}, "final_hop_loss", r, tm.Name, "")
		win := r.Window.D()
		st.win = append(st.win, lossEntry{bucket, tm.E2E.Sent, tm.E2E.Lost})
		cut := 0
		for cut < len(st.win) && st.win[cut].bucket.Before(end.Add(-win)) {
			cut++
		}
		st.win = st.win[cut:]
		if len(st.win) == 0 || st.win[0].bucket.After(end.Add(-win)) {
			continue // the window is not covered by data yet
		}
		sent, lost := 0, 0
		var firstLoss, lastLossEnd time.Time
		for _, w := range st.win {
			sent += w.sent
			lost += w.lost
			if w.lost > 0 {
				if firstLoss.IsZero() {
					firstLoss = w.bucket
				}
				lastLossEnd = w.bucket.Add(time.Minute)
			}
		}
		if sent == 0 {
			continue
		}
		pct := 100 * float64(lost) / float64(sent)
		clearBelow := r.ThresholdPct * e.cfg.clearRatio
		clearFrom := lastLossEnd
		if clearFrom.IsZero() {
			clearFrom = st.win[0].bucket
		}
		src := ""
		if tm.E2ESource == "tcp" {
			src = ", TCP probe"
		}
		e.step(st, obs{
			at: end, breach: pct > r.ThresholdPct, clear: pct < clearBelow,
			value: pct, hasValue: true, since: firstLoss, clearFrom: clearFrom, unit: "%",
			msg:     fmt.Sprintf("End-to-end loss %s over %s (threshold %s%s)", fmtPct(pct), fmtWindow(win), fmtPct(r.ThresholdPct), src),
			details: map[string]any{"threshold_pct": r.ThresholdPct, "window": fmtWindow(win), "source": tm.E2ESource},
		})
	}
}

// evalDegradation runs path_degradation from the analyzer's verdict (rate-limited hops never
// reach it).
func (e *RuleEngine) evalDegradation(tm TargetMinute, bucket, end time.Time) {
	if len(tm.Hops) == 0 {
		return // no hop data this minute: no information
	}
	for _, r := range e.cfg.rulesFor(tm.Name, "path_degradation") {
		st := e.state(stateKey{tm.TargetID, r.Name, 0}, "path_degradation", r, tm.Name, "")
		o := obs{at: end, breach: tm.Degradation != nil, clear: tm.Degradation == nil, since: bucket, hold: r.Sustain.D(), clearHold: r.Sustain.D(), clearFrom: bucket, unit: "hop"}
		if tm.Degradation != nil {
			o.value, o.hasValue = float64(tm.Degradation.StartTTL), true
			o.msg = fmt.Sprintf("Path degraded: problem begins at hop %d", tm.Degradation.StartTTL)
			o.details = map[string]any{"start_ttl": tm.Degradation.StartTTL}
		}
		e.step(st, o)
	}
}

// evalLatency runs http_latency / dns_latency for one probe's minute.
func (e *RuleEngine) evalLatency(target int64, tname string, pm ProbeMinute, ruleType string, end time.Time) {
	if !pm.HaveAvg {
		return // every sample failed: http_failure/dns_failure's business, no latency information
	}
	ruleTarget := tname
	if target == 0 {
		ruleTarget = ""
	}
	for _, r := range e.cfg.rulesFor(ruleTarget, ruleType) {
		metric := r.Metric
		v := pm.AvgTotalMS
		if ruleType == "dns_latency" {
			metric = "total"
		} else if metric == "ttfb" {
			v = pm.AvgTTFBMS
			if v <= 0 {
				continue
			}
		}
		st := e.state(stateKey{target, r.Name, pm.ProbeID}, ruleType, r, tname, pm.Label)
		var med, mad float64
		if st.active() {
			med, mad = st.baseMed, st.baseMAD // frozen while the alert lasts
		} else {
			sustain := r.Sustain.D()
			b := e.base.get(pm.ProbeID, metric, r.BaselineWindow.D(), r.MinBaseline.D(), sustain+time.Minute, st.pending())
			if !b.Ready {
				st.since = time.Time{} // learning baseline: the rule is inactive
				continue
			}
			med, mad = b.Median, b.MAD
		}
		trig := latencyThreshold(r, med, mad)
		clr := clearThreshold(trig, med, e.cfg.clearRatio)
		if !st.active() {
			st.baseMed, st.baseMAD, st.threshold = med, mad, trig
		}
		base := med
		var msg string
		if ruleType == "http_latency" {
			msg = fmt.Sprintf("HTTP %s %s vs baseline %s", metricLabel(metric), fmtMS(v), fmtMS(med))
		} else {
			msg = fmt.Sprintf("DNS lookup %s vs baseline %s", fmtMS(v), fmtMS(med))
		}
		msg = e.withLabel(msg, target, pm.Type, pm.Label)
		e.step(st, obs{
			at: end, breach: v > trig, clear: v < clr, value: v, hasValue: true, baseline: &base,
			since: end.Add(-time.Minute), hold: r.Sustain.D(), clearHold: r.Sustain.D(), clearFrom: end.Add(-time.Minute),
			unit: "ms", msg: msg, details: map[string]any{"metric": metric},
		})
	}
}

// ---------------------------------------------------------------------------
// route_change

// handleRouteChanges turns new route_change events from the store into one-shot alerts.
func (e *RuleEngine) handleRouteChanges() {
	now := e.now()
	evs, err := e.st.Events(store.EventQuery{From: e.routeFrom, To: now.Add(time.Minute), Kinds: []string{store.EventRouteChange}})
	if err != nil {
		e.log.Warn("reading route changes failed", "err", err)
		return
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].ID < evs[j].ID })
	for _, ev := range evs {
		if e.routeSeen[ev.ID] || ev.TargetID == nil || ev.From.Before(e.routeFrom) {
			continue
		}
		e.routeSeen[ev.ID] = true
		tid := *ev.TargetID
		tname := e.targetName(tid)
		for _, r := range e.cfg.rulesFor(tname, "route_change") {
			e.oneShot(tid, tname, r, ev)
		}
	}
	// events older than the lookback never matter again
	if len(e.routeSeen) > 5000 {
		e.routeSeen = map[int64]bool{}
	}
}

func (e *RuleEngine) oneShot(tid int64, tname string, r config.RuleConfig, ev store.Event) {
	st := &ruleState{key: stateKey{tid, r.Name, 0}, rtype: "route_change", rule: r, tname: tname}
	at := ev.From.UTC()
	reason := e.suppressReason(st, at)
	d := map[string]any{"event_id": ev.ID}
	var evd map[string]any
	if json.Unmarshal(ev.Details, &evd) == nil {
		for _, k := range []string{"from_path", "to_path", "resolved_ip"} {
			if v, ok := evd[k]; ok {
				d[k] = v
			}
		}
	}
	end := at
	a := &store.Alert{
		TargetID: &tid, Rule: r.Name, RuleType: "route_change", State: StateResolved, SuppressedReason: reason,
		StartedAt: at, EndedAt: &end, Message: fmt.Sprintf("Network path to %s changed (new path version)", tname),
	}
	if reason != "" {
		a.State = "suppressed"
	}
	st.alert, st.details = a, d
	e.save(st, reason == "")
}

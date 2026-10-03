package alert

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// Suppression reasons recorded in alerts.suppressed_reason.
const (
	SuppressSilence     = "silence"
	SuppressMaintenance = "maintenance"
	SuppressLocalOutage = "local_outage"
	SuppressCooldown    = "cooldown"
)

// stateKey identifies one state machine: a (target, rule) pair, plus the probe for rules that
// are evaluated per probe (a target may have several HTTP probes).
type stateKey struct {
	target  int64  // 0 for DNS probes and the local alert
	rule    string // rule name
	subject int64  // probe id for probe-based rules, else 0
}

// lossEntry is one minute of end-to-end loss for a final_hop_loss window.
type lossEntry struct {
	bucket     time.Time
	sent, lost int
}

// ruleState is the pending -> firing -> resolved state machine of one (target, rule[, probe]).
//
//	idle     alert == nil, since zero
//	pending  alert == nil, since set (the condition holds but has not yet held for sustain)
//	active   alert != nil: firing, or suppressed while its condition holds
type ruleState struct {
	key   stateKey
	rtype string
	rule  config.RuleConfig
	tname string
	label string // probe label

	since      time.Time // pending: when the condition began
	clearSince time.Time // active: when the clear condition began holding
	alert      *store.Alert
	peak       float64
	lastSaved  time.Time
	dirty      bool

	baseMed, baseMAD float64 // baseline frozen at activation (latency rules)
	threshold        float64
	details          map[string]any

	lastResolved time.Time // cooldown reference
	win          []lossEntry
	certNotAfter time.Time // cert_expiry: the certificate this alert is about
	certChanged  int
}

func (st *ruleState) active() bool  { return st.alert != nil }
func (st *ruleState) pending() bool { return st.alert == nil && !st.since.IsZero() }

// obs is one evaluation result fed to the state machine.
type obs struct {
	at        time.Time // data time of the observation
	breach    bool      // the trigger condition holds
	clear     bool      // the clear condition (below the hysteresis threshold) holds
	value     float64   // current value (valid when hasValue)
	hasValue  bool
	baseline  *float64
	msg       string        // alert message, used when the alert fires
	since     time.Time     // when the breach began (pending start, alert started_at)
	hold      time.Duration // the breach must hold this long before firing
	clearHold time.Duration // the clear condition must hold this long before resolving
	clearFrom time.Time     // when the clear condition began (ended_at); zero = first observation
	unit      string
	details   map[string]any
}

func firstTime(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// step advances the state machine with one observation.
func (e *RuleEngine) step(st *ruleState, o obs) {
	e.cur = o.at
	if !st.active() {
		if !o.breach {
			st.since = time.Time{}
			return
		}
		if st.since.IsZero() {
			st.since = firstTime(o.since, o.at)
		}
		if o.at.Sub(st.since) < o.hold {
			return // pending: not yet held for sustain
		}
		e.activate(st, o)
		return
	}
	a := st.alert
	if o.hasValue {
		v := o.value
		a.Value = &v
		if v > st.peak {
			grew := st.peak <= 0 || v > st.peak*1.25
			st.peak = v
			p := v
			a.PeakValue = &p
			if grew && o.at.Sub(st.lastSaved) >= time.Minute {
				st.dirty = true
			}
		}
		if st.lastSaved.IsZero() || o.at.Sub(st.lastSaved) >= valueSaveEvery {
			st.dirty = true
		}
	}
	if o.clear {
		if st.clearSince.IsZero() {
			st.clearSince = firstTime(o.clearFrom, o.at)
		}
		if o.at.Sub(st.clearSince) >= o.clearHold {
			e.resolve(st, o.at)
			return
		}
	} else {
		st.clearSince = time.Time{}
	}
	if a.State == "suppressed" && o.breach {
		e.maybePromote(st, o.at)
	}
	if st.dirty {
		e.save(st, false)
	}
}

// valueSaveEvery throttles how often a firing alert's current value is written back.
const valueSaveEvery = 5 * time.Minute

// suppressReason decides whether an alert starting now must not be sent, and why.
func (e *RuleEngine) suppressReason(st *ruleState, at time.Time) string {
	if st.rtype != RuleLocalConnectivity && e.local.Down {
		return SuppressLocalOutage
	}
	now := e.now()
	for _, t := range []time.Time{now, at} {
		if t.IsZero() {
			continue
		}
		for _, s := range e.silences() {
			if s.Covers(t, st.key.target, st.rule.Name) || s.Covers(t, st.key.target, st.rtype) {
				return SuppressSilence
			}
		}
		if _, ok := e.cfg.maint.Silenced(t); ok {
			return SuppressMaintenance
		}
	}
	if oneShot(st.rtype) || st.rtype == RuleLocalConnectivity {
		return ""
	}
	if cd := e.cfg.cooldown; cd > 0 && !st.lastResolved.IsZero() && at.Sub(st.lastResolved) < cd {
		return SuppressCooldown
	}
	return ""
}

// oneShot rule types are not subject to the cooldown (they fire once per event or certificate).
func oneShot(ruleType string) bool { return ruleType == "cert_expiry" || ruleType == "route_change" }

func (e *RuleEngine) silences() []SilenceScope {
	list, err := e.st.Silences(e.now())
	if err != nil {
		e.log.Warn("reading silences failed", "err", err)
		return nil
	}
	out := make([]SilenceScope, 0, len(list))
	for _, s := range list {
		out = append(out, SilenceScope{TargetID: s.TargetID, Rule: s.Rule, Start: s.StartsAt, End: s.EndsAt})
	}
	return out
}

// activate turns a pending condition into an alert: firing (and notified), or recorded as
// suppressed with the reason.
func (e *RuleEngine) activate(st *ruleState, o obs) {
	start := firstTime(st.since, o.at)
	reason := e.suppressReason(st, o.at)
	a := &store.Alert{
		Rule: st.rule.Name, RuleType: st.rtype, State: StateFiring, SuppressedReason: reason,
		StartedAt: start.UTC(), Baseline: o.baseline, Message: o.msg,
	}
	if st.rtype == RuleLocalConnectivity {
		a.Rule = RuleLocalConnectivity
	}
	if reason != "" {
		a.State = "suppressed"
	}
	if st.key.target != 0 {
		t := st.key.target
		a.TargetID = &t
	}
	if o.hasValue {
		v, p := o.value, o.value
		a.Value, a.PeakValue = &v, &p
		st.peak = o.value
	}
	st.details = o.details
	st.alert = a
	st.since, st.clearSince = time.Time{}, time.Time{}
	a.DetailsJSON = st.detailsJSON(o.unit)
	e.save(st, a.State == StateFiring)
	if reason == SuppressLocalOutage {
		e.recordLocalSuppressed(st)
	}
	e.log.Info("alert "+a.State, "rule", a.Rule, "target", st.tname, "reason", reason, "message", a.Message)
}

func (st *ruleState) detailsJSON(unit string) string {
	m := map[string]any{}
	for k, v := range st.details {
		m[k] = v
	}
	if unit != "" {
		m["unit"] = unit
	} else if st.alert != nil {
		var old map[string]any
		if json.Unmarshal([]byte(st.alert.DetailsJSON), &old) == nil {
			if u, ok := old["unit"]; ok {
				m["unit"] = u
			}
		}
	}
	if st.label != "" {
		m["probe"] = st.label
	}
	if st.key.subject != 0 {
		m["probe_id"] = st.key.subject
	}
	if st.rtype == "http_latency" || st.rtype == "dns_latency" {
		m["mad"] = st.baseMAD
		m["threshold"] = st.threshold
		if _, ok := m["metric"]; !ok {
			m["metric"] = st.rule.Metric
		}
	}
	if !st.certNotAfter.IsZero() {
		m["not_after_ms"] = st.certNotAfter.UnixMilli()
	}
	if st.rtype == RuleLocalConnectivity && st.alert != nil {
		// keep the suppressed list the local alert accumulated
		var old map[string]any
		if json.Unmarshal([]byte(st.alert.DetailsJSON), &old) == nil {
			if s, ok := old["suppressed"]; ok {
				m["suppressed"] = s
			}
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// resolve ends the active alert. A firing alert becomes resolved and a "resolved" notification
// is sent (cooldown and silences never hold it back: the firing one was sent); a suppressed one
// just gets its end time.
func (e *RuleEngine) resolve(st *ruleState, at time.Time) {
	a := st.alert
	if a == nil {
		return
	}
	end := firstTime(st.clearSince, at)
	if end.Before(a.StartedAt) {
		end = a.StartedAt
	}
	end = end.UTC()
	a.EndedAt = &end
	wasFiring := a.State == StateFiring
	if wasFiring {
		a.State = StateResolved
		st.lastResolved = at
	}
	e.save(st, wasFiring)
	e.log.Info("alert resolved", "rule", a.Rule, "target", st.tname, "was", map[bool]string{true: "firing", false: "suppressed"}[wasFiring])
	st.alert = nil
	st.since, st.clearSince = time.Time{}, time.Time{}
	st.peak = 0
	st.certChanged = 0
}

// maybePromote turns a suppressed alert into a firing one when what suppressed it (a silence, a
// maintenance window or the cooldown) is over while its condition still holds. Alerts suppressed
// by a local outage stay suppressed: they belong to that outage.
func (e *RuleEngine) maybePromote(st *ruleState, at time.Time) {
	a := st.alert
	if a == nil || a.State != "suppressed" || a.SuppressedReason == SuppressLocalOutage || a.EndedAt != nil {
		return
	}
	if e.suppressReason(st, at) != "" {
		return
	}
	a.State = StateFiring
	a.SuppressedReason = ""
	e.save(st, true)
	e.log.Info("suppression over; alert is now firing", "rule", a.Rule, "target", st.tname)
}

// save persists the alert row, queues the notification matching its state when notify is set
// and tells the UI.
func (e *RuleEngine) save(st *ruleState, notify bool) {
	a := st.alert
	if a == nil {
		return
	}
	a.DetailsJSON = st.detailsJSON("")
	if err := e.st.SaveAlert(a); err != nil {
		e.log.Error("saving alert failed", "rule", a.Rule, "err", err)
		return
	}
	st.lastSaved = firstTime(e.cur, e.now())
	st.dirty = false
	if notify {
		n := e.notification(st, a)
		e.sender.Enqueue(n, e.channelsFor(st.rule))
	}
	if e.sink != nil {
		e.sink.AlertChanged(a.ID)
	}
}

// notification builds the outbox payload for the alert's current state.
func (e *RuleEngine) notification(st *ruleState, a *store.Alert) Notification {
	n := Notification{
		AlertID: a.ID, TargetID: a.TargetID, Target: st.tname, Rule: a.Rule, RuleType: a.RuleType,
		State: StateFiring, Value: a.Value, PeakValue: a.PeakValue, Baseline: a.Baseline,
		Message: a.Message, StartedAt: a.StartedAt, EndedAt: a.EndedAt,
	}
	if a.State == StateResolved {
		n.State = StateResolved
	}
	if st.rtype == "route_change" {
		n.State = StateEvent
	}
	var d struct {
		Unit string `json:"unit"`
	}
	_ = json.Unmarshal([]byte(a.DetailsJSON), &d)
	n.Unit = d.Unit
	if a.DetailsJSON != "" {
		n.Details = json.RawMessage(a.DetailsJSON)
	}
	now := e.now()
	n.Link = deepLink(e.cfg.publicURL, a.TargetID, a.StartedAt, a.EndedAt, now)
	if st.rtype == RuleLocalConnectivity {
		n.Target = "local connection"
	}
	return n
}

// channelsFor lists the channels a rule notifies: its notify list, or every configured channel.
func (e *RuleEngine) channelsFor(r config.RuleConfig) []string {
	avail := e.sender.Channels()
	if len(r.Notify) == 0 {
		return avail
	}
	var out []string
	for _, want := range r.Notify {
		for _, have := range avail {
			if want == have {
				out = append(out, want)
			}
		}
	}
	return out
}

// recordLocalSuppressed lists a suppressed per-target alert in the local alert's details.
func (e *RuleEngine) recordLocalSuppressed(st *ruleState) {
	ls := e.localState
	if ls == nil || ls.alert == nil || st.alert == nil {
		return
	}
	var d map[string]any
	if json.Unmarshal([]byte(ls.alert.DetailsJSON), &d) != nil || d == nil {
		d = map[string]any{}
	}
	list, _ := d["suppressed"].([]any)
	list = append(list, map[string]any{"alert_id": st.alert.ID, "target": st.tname, "rule": st.alert.Rule})
	d["suppressed"] = list
	b, _ := json.Marshal(d)
	ls.alert.DetailsJSON = string(b)
	if err := e.st.SaveAlert(ls.alert); err != nil {
		e.log.Error("saving local alert failed", "err", err)
		return
	}
	if e.sink != nil {
		e.sink.AlertChanged(ls.alert.ID)
	}
}

func (st *ruleState) String() string {
	return fmt.Sprintf("%s/%s/%d", st.rule.Name, st.tname, st.key.subject)
}

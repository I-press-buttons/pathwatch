package alert

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestSustainThenResolve(t *testing.T) {
	h := newHarness(t, baseYAML)
	// two degraded minutes are not enough for sustain: 3m
	h.minute(at(0), LocalState{}, degradedMinute(1, "cf", 7))
	h.minute(at(1), LocalState{}, degradedMinute(1, "cf", 7))
	want(t, len(h.alerts()) == 0, "alert before sustain elapsed")
	// a clean minute restarts the pending condition
	h.minute(at(2), LocalState{}, cleanMinute(1, "cf"))
	h.minute(at(3), LocalState{}, degradedMinute(1, "cf", 7))
	h.minute(at(4), LocalState{}, degradedMinute(1, "cf", 7))
	want(t, len(h.alerts()) == 0, "pending was not reset by the clean minute")
	h.minute(at(5), LocalState{}, degradedMinute(1, "cf", 8))
	al := h.alerts()
	want(t, len(al) == 1 && al[0].State == "firing", "want one firing alert, got %+v", al)
	a := al[0]
	want(t, a.Rule == "path-degraded" && a.RuleType == "path_degradation", "rule %s/%s", a.Rule, a.RuleType)
	want(t, a.StartedAt.Equal(at(3)), "started_at %v, want the first degraded minute %v", a.StartedAt, at(3))
	want(t, a.TargetID != nil && *a.TargetID == 1, "target id")
	want(t, strings.Contains(a.Message, "hop"), "message %q", a.Message)
	want(t, h.sink.seen(a.ID), "sink not told about the alert")

	// it resolves only after the clean state holds for sustain
	h.minute(at(6), LocalState{}, cleanMinute(1, "cf"))
	h.minute(at(7), LocalState{}, cleanMinute(1, "cf"))
	want(t, h.alerts()[0].State == "firing", "resolved too early")
	h.minute(at(8), LocalState{}, cleanMinute(1, "cf"))
	a = h.alerts()[0]
	want(t, a.State == "resolved" && a.EndedAt != nil, "state %s", a.State)
	want(t, a.EndedAt.Equal(at(6)), "ended_at %v, want the first clean minute %v", *a.EndedAt, at(6))

	h.flush()
	n := h.hook.notes()
	want(t, len(n) == 2 && n[0].State == "firing" && n[1].State == "resolved", "notifications %v", h.hook.states())
	want(t, n[1].StartedAt.Equal(at(3)) && n[1].EndedAt != nil && n[1].EndedAt.Equal(at(6)), "resolved notification must carry the real start/end")
	want(t, n[1].Duration() == 3*time.Minute, "duration %v", n[1].Duration())
	want(t, h.sink.seen(a.ID), "sink")
}

func TestLossHysteresisCooldownAndResolvedAfterCooldown(t *testing.T) {
	h := newHarness(t, baseYAML)
	min := 0
	feed := func(lost int) {
		h.minute(at(min), LocalState{}, lossMinute(1, "cf", 100, lost))
		min++
	}
	for i := 0; i < 4; i++ {
		feed(0)
	}
	want(t, len(h.alerts()) == 0, "alert before the window was full")
	feed(0) // window now covers 5 minutes
	feed(60)
	al := h.alerts()
	want(t, len(al) == 1 && al[0].State == "firing", "a 12%% window loss over a 10%% threshold must fire: %+v", al)
	want(t, strings.Contains(al[0].Message, "12%"), "message %q", al[0].Message)
	first := al[0].ID
	want(t, al[0].StartedAt.Equal(at(5)), "started_at %v want first lossy minute", al[0].StartedAt)

	// 7%% steady loss: below the trigger (10%%) but above the clear threshold (5%%): stays firing
	for i := 0; i < 8; i++ {
		feed(7)
	}
	want(t, h.alerts()[0].State == "firing", "hysteresis: must stay firing at 7%%")
	want(t, len(h.alerts()) == 1, "no second alert while firing")
	// clean for a full window: resolves
	for i := 0; i < 5; i++ {
		feed(0)
	}
	a := h.alerts()[0]
	want(t, a.State == "resolved", "state %s", a.State)
	resolvedAt := at(min - 1).Add(time.Minute)

	// a new breach inside the cooldown is recorded as suppressed(cooldown), not sent
	for i := 0; i < 2; i++ {
		feed(100)
	}
	al = h.alerts()
	want(t, len(al) == 2, "want 2 alerts, got %d", len(al))
	want(t, al[1].State == "suppressed" && al[1].SuppressedReason == "cooldown", "second alert %s/%s", al[1].State, al[1].SuppressedReason)
	h.flush()
	want(t, strings.Join(h.hook.states(), ",") == "firing,resolved", "cooldown suppressed alert must not notify: %v", h.hook.states())

	// the loss goes on past the cooldown: the suppression ends and the alert fires for real
	for h.clk.Now().Before(resolvedAt.Add(31 * time.Minute)) {
		feed(100)
	}
	al = h.alerts()
	want(t, len(al) == 2 && al[1].State == "firing" && al[1].SuppressedReason == "", "promotion after cooldown: %+v", al[1])
	h.flush()
	want(t, strings.Join(h.hook.states(), ",") == "firing,resolved,firing", "got %v", h.hook.states())

	// resolve it again: the resolved notification is always sent
	for i := 0; i < 6; i++ {
		feed(0)
	}
	h.flush()
	want(t, strings.Join(h.hook.states(), ",") == "firing,resolved,firing,resolved", "got %v", h.hook.states())
	want(t, h.alerts()[0].ID == first, "first alert id")
}

func TestResolvedNotSuppressedByCooldown(t *testing.T) {
	// the cooldown applies to new alerts only: a firing alert always resolves with a notification,
	// even if it resolves inside the cooldown of the previous alert of the same rule.
	h := newHarness(t, baseYAML)
	min := 0
	feed := func(lost int) {
		h.minute(at(min), LocalState{}, lossMinute(1, "cf", 100, lost))
		min++
	}
	for i := 0; i < 5; i++ {
		feed(0)
	}
	feed(80)
	for i := 0; i < 5; i++ {
		feed(0)
	}
	want(t, h.alerts()[0].State == "resolved", "first alert resolved")
	feed(100) // suppressed (cooldown)
	st := h.eng.states[stateKey{1, "end-loss", 0}]
	want(t, st != nil && st.alert != nil && st.alert.State == "suppressed", "cooldown state")
	// force the cooldown to be over by shortening it through a reload, then let it promote
	cfg := mustConfig(t, strings.Replace(baseYAML, "cooldown: 30m", "cooldown: 1m", 1))
	h.cfg = cfg
	h.eng.Reload(cfg)
	feed(100)
	feed(100)
	want(t, h.alerts()[1].State == "firing", "promoted: %s", h.alerts()[1].State)
	for i := 0; i < 6; i++ {
		feed(0)
	}
	h.flush()
	byAlert := map[int64][]string{}
	for _, n := range h.hook.notes() {
		byAlert[n.AlertID] = append(byAlert[n.AlertID], n.State)
	}
	want(t, len(byAlert) == 2, "notifications for two alerts: %v", byAlert)
	for id, st := range byAlert {
		want(t, strings.Join(st, ",") == "firing,resolved", "alert %d: %v (resolved is never suppressed and never overtakes firing)", id, st)
	}
}

func TestMonitorGapNeverTriggersOrResolves(t *testing.T) {
	h := newHarness(t, baseYAML)
	// pending path degradation interrupted by a gap restarts
	h.minute(at(0), LocalState{}, degradedMinute(1, "cf", 3))
	h.minute(at(1), LocalState{}, degradedMinute(1, "cf", 3))
	h.minute(at(30), LocalState{}, degradedMinute(1, "cf", 3)) // 28 minutes of nothing in between
	want(t, len(h.alerts()) == 0, "a gap must not count toward sustain")
	h.minute(at(31), LocalState{}, degradedMinute(1, "cf", 3))
	h.minute(at(32), LocalState{}, degradedMinute(1, "cf", 3))
	al := h.alerts()
	want(t, len(al) == 1 && al[0].State == "firing", "fires after sustain of real data: %+v", al)
	want(t, al[0].StartedAt.Equal(at(30)), "started after the gap: %v", al[0].StartedAt)

	// a firing alert is not resolved by the gap, and the clear-hold restarts after it
	h.minute(at(33), LocalState{}, cleanMinute(1, "cf"))
	h.minute(at(34), LocalState{}, cleanMinute(1, "cf"))
	h.minute(at(80), LocalState{}, cleanMinute(1, "cf")) // gap
	want(t, h.alerts()[0].State == "firing", "must not resolve across a gap")
	h.minute(at(81), LocalState{}, cleanMinute(1, "cf"))
	h.minute(at(82), LocalState{}, cleanMinute(1, "cf"))
	want(t, h.alerts()[0].State == "resolved", "resolves after sustain of real data")
	want(t, h.alerts()[0].EndedAt.Equal(at(80)), "ended_at %v", h.alerts()[0].EndedAt)
}

func TestRestartRestoresActiveAlertsAndCooldown(t *testing.T) {
	h := newHarness(t, baseYAML)
	min := 0
	feed := func(lost int) {
		h.minute(at(min), LocalState{}, lossMinute(1, "cf", 100, lost))
		min++
	}
	for i := 0; i < 5; i++ {
		feed(0)
	}
	feed(90)
	h.flush()
	al := h.alerts()
	want(t, len(al) == 1 && al[0].State == "firing", "firing before restart")
	id := al[0].ID
	want(t, strings.Join(h.hook.states(), ",") == "firing", "sent once")

	h.restart("")
	// the new engine has no window data yet; the condition simply continues
	for i := 0; i < 3; i++ {
		feed(90)
	}
	al = h.alerts()
	want(t, len(al) == 1 && al[0].ID == id, "restart must not re-fire or duplicate: %+v", al)
	h.flush()
	want(t, strings.Join(h.hook.states(), ",") == "firing", "no second firing notification: %v", h.hook.states())

	// the restored alert resolves normally
	for i := 0; i < 8; i++ {
		feed(0)
	}
	al = h.alerts()
	want(t, al[0].State == "resolved", "restored alert resolves: %s", al[0].State)
	h.flush()
	want(t, strings.Join(h.hook.states(), ",") == "firing,resolved", "got %v", h.hook.states())

	// cooldown survives a restart too
	h.restart("")
	for i := 0; i < 6; i++ {
		feed(0)
	}
	feed(100)
	al = h.alerts()
	want(t, len(al) == 2 && al[1].State == "suppressed" && al[1].SuppressedReason == "cooldown", "cooldown restored: %+v", al)
}

func TestFailureRulesConsecutiveAndResolve(t *testing.T) {
	yaml := `
alerts:
  rules:
    - name: http-down
      type: http_failure
      consecutive: 3
`
	h := newHarness(t, yaml)
	probe := func(ts time.Time, ok bool) {
		s := ProbeSample{TargetID: 1, ProbeID: 7, Type: "http", TS: ts, OK: ok}
		if !ok {
			s.Status, s.Error = 500, ""
		}
		h.eng.HandleProbe(s)
	}
	// minute 0: ok, fail, fail; minute 1: ok (streak broken) fail fail; minute 2: fail
	probe(at(0).Add(5*time.Second), true)
	probe(at(0).Add(35*time.Second), false)
	probe(at(1).Add(5*time.Second), false)
	probe(at(1).Add(35*time.Second), true)
	probe(at(2).Add(5*time.Second), false)
	probe(at(2).Add(35*time.Second), false)
	probe(at(3).Add(5*time.Second), false)
	h.minute(at(0), LocalState{}, httpMinute(1, "cf", 7, 50))
	h.minute(at(1), LocalState{}, httpMinute(1, "cf", 7, 50))
	h.minute(at(2), LocalState{}, httpMinute(1, "cf", 7, 50))
	want(t, len(h.alerts()) == 0, "fails were not consecutive; got %+v", h.alerts())
	// the third failure in a row lands in minute 3, which is analysed after it ends
	probe(at(3).Add(35*time.Second), false)
	h.minute(at(3), LocalState{}, httpMinute(1, "cf", 7, 50))
	al := h.alerts()
	want(t, len(al) == 1 && al[0].State == "firing", "alert %+v", al)
	want(t, al[0].StartedAt.Equal(at(2).Add(5*time.Second)), "started at first failure of the streak: %v", al[0].StartedAt)
	want(t, strings.Contains(al[0].Message, "HTTP status 500"), "message %q", al[0].Message)
	want(t, al[0].Value != nil && *al[0].Value >= 3, "value")

	// recovery needs `consecutive` successes
	probe(at(4).Add(5*time.Second), true)
	probe(at(4).Add(35*time.Second), true)
	h.minute(at(4), LocalState{}, httpMinute(1, "cf", 7, 50))
	want(t, h.alerts()[0].State == "firing", "two successes are not enough")
	probe(at(5).Add(5*time.Second), true)
	h.minute(at(5), LocalState{}, httpMinute(1, "cf", 7, 50))
	a := h.alerts()[0]
	want(t, a.State == "resolved" && a.EndedAt.Equal(at(4).Add(5*time.Second)), "resolved at the first success: %+v", a)
	h.flush()
	want(t, strings.Join(h.hook.states(), ",") == "firing,resolved", "got %v", h.hook.states())
}

func TestProbeStreakBrokenByStall(t *testing.T) {
	yaml := `
alerts:
  rules:
    - name: tcp-down
      type: tcp_failure
      consecutive: 3
`
	h := newHarness(t, yaml)
	p := func(ts time.Time) {
		h.eng.HandleProbe(ProbeSample{TargetID: 1, ProbeID: 9, Type: "tcp", TS: ts, OK: false, Error: "connection refused"})
	}
	for i := 0; i < 5; i++ {
		p(t0.Add(time.Duration(i) * 10 * time.Second))
	}
	// the monitor was stalled for 20 minutes: the next failure does not extend the streak
	p(t0.Add(20 * time.Minute))
	p(t0.Add(20*time.Minute + 10*time.Second))
	h.minute(at(20), LocalState{}, TargetMinute{TargetID: 1, Name: "cf", TCP: []ProbeMinute{{ProbeID: 9, Type: "tcp", Label: "TCP :443", N: 2, Errors: 2}}})
	al := h.alerts()
	for _, a := range al {
		if a.StartedAt.After(at(20)) {
			t.Fatalf("a stalled streak must not fire after the gap: %+v", a)
		}
	}
	// the first streak (5 failures) is analysed with its own minute; it fired before the stall
	want(t, len(al) == 1 && al[0].StartedAt.Equal(t0), "pre-stall streak: %+v", al)
}

func TestPerTargetDisableAndOverride(t *testing.T) {
	yaml := `
targets:
  - name: quiet
    host: 127.0.0.1
    alerts:
      disable: [path_degradation]
      override:
        end-loss: { threshold_pct: 50 }
  - name: loud
    host: 127.0.0.2
alerts:
  cooldown: 30m
  rules:
    - name: end-loss
      type: final_hop_loss
      threshold_pct: 10
      window: 5m
    - name: path-degraded
      type: path_degradation
      sustain: 1m
`
	h := newHarness(t, yaml)
	for i := 0; i < 6; i++ {
		lm := func(id int64, name string) TargetMinute {
			m := lossMinute(id, name, 100, 20)
			m.Degradation = &Degradation{StartTTL: 4}
			return m
		}
		h.minute(at(i), LocalState{}, lm(1, "quiet"), lm(2, "loud"))
	}
	got := map[string]bool{}
	for _, a := range h.alerts() {
		got[a.Rule+"/"+map[int64]string{1: "quiet", 2: "loud"}[*a.TargetID]] = true
	}
	want(t, got["end-loss/loud"] && got["path-degraded/loud"], "loud target gets both rules: %v", got)
	want(t, !got["end-loss/quiet"], "quiet's end-loss override (50%%) must not fire at 20%%: %v", got)
	want(t, !got["path-degraded/quiet"], "quiet disabled path_degradation by type: %v", got)
}

func TestTCPSourceUsedForICMPUnresponsive(t *testing.T) {
	h := newHarness(t, baseYAML)
	m := func(src string, lost int) TargetMinute {
		tm := lossMinute(1, "cf", 100, lost)
		tm.E2ESource = src
		return tm
	}
	for i := 0; i < 7; i++ {
		h.minute(at(i), LocalState{}, m("last_hop", 100)) // an intermediate router: never alerts
	}
	want(t, len(h.alerts()) == 0, "last-hop loss must not alert")
	for i := 7; i < 14; i++ {
		h.minute(at(i), LocalState{}, m("tcp", 100))
	}
	al := h.alerts()
	want(t, len(al) == 1 && al[0].Rule == "end-loss", "tcp loss alerts: %+v", al)
	want(t, strings.Contains(al[0].Message, "TCP probe"), "message %q", al[0].Message)
}

func TestRuleChannelRouting(t *testing.T) {
	yaml := `
alerts:
  rules:
    - name: end-loss
      type: final_hop_loss
      threshold_pct: 10
      window: 2m
      notify: [email]
    - name: path-degraded
      type: path_degradation
      sustain: 1m
`
	h := newHarness(t, yaml)
	for i := 0; i < 3; i++ {
		tm := lossMinute(1, "cf", 100, 50)
		tm.Degradation = &Degradation{StartTTL: 3}
		h.minute(at(i), LocalState{}, tm)
	}
	h.flush()
	var email, hook []string
	for _, n := range h.mail.notes() {
		email = append(email, n.Rule)
	}
	for _, n := range h.hook.notes() {
		hook = append(hook, n.Rule)
	}
	sort.Strings(email)
	want(t, strings.Join(email, ",") == "end-loss,path-degraded", "email gets end-loss (routed) and path-degraded (default all): %v", email)
	want(t, strings.Join(hook, ",") == "path-degraded", "webhook must not get end-loss: %v", hook)
	d := h.outbox()
	var channels []string
	for _, a := range h.alerts() {
		for _, x := range d[a.ID] {
			channels = append(channels, a.Rule+":"+x.Channel+":"+x.Status)
		}
	}
	want(t, len(channels) == 3, "deliveries %v", channels)
}

func TestRemovedRuleResolvesItsAlert(t *testing.T) {
	h := newHarness(t, baseYAML)
	for i := 0; i < 4; i++ {
		h.minute(at(i), LocalState{}, degradedMinute(1, "cf", 5))
	}
	want(t, len(h.alerts()) == 1 && h.alerts()[0].State == "firing", "firing")
	cfg := mustConfig(t, `
alerts:
  rules:
    - name: end-loss
      type: final_hop_loss
      threshold_pct: 10
      window: 5m
`)
	h.eng.Reload(cfg)
	want(t, h.alerts()[0].State == "resolved", "alert of a removed rule resolves, got %s", h.alerts()[0].State)
}

func TestAlertDetailsJSONAndUnit(t *testing.T) {
	h := newHarness(t, baseYAML)
	for i := 0; i < 4; i++ {
		h.minute(at(i), LocalState{}, degradedMinute(1, "cf", 5))
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(h.alerts()[0].DetailsJSON), &d); err != nil {
		t.Fatal(err)
	}
	want(t, d["unit"] == "hop", "details %v", d)
}

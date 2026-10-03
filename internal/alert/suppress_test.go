package alert

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/store"
)

func breach(h *harness, from, n int, local LocalState) {
	for i := from; i < from+n; i++ {
		h.minute(at(i), local, lossMinute(1, "cf", 100, 100))
	}
}

func warm(h *harness, n int) {
	for i := 0; i < n; i++ {
		h.minute(at(-n+i), LocalState{}, lossMinute(1, "cf", 100, 0))
	}
}

func TestSilenceSuppressesButRecords(t *testing.T) {
	h := newHarness(t, baseYAML)
	warm(h, 6)
	tid := int64(1)
	rule := "end-loss"
	if _, err := h.st.CreateSilence(store.Silence{TargetID: &tid, Rule: &rule, StartsAt: at(-10), EndsAt: at(60), Reason: "router upgrade", CreatedBy: "ui"}); err != nil {
		t.Fatal(err)
	}
	breach(h, 0, 2, LocalState{})
	al := h.alerts()
	want(t, len(al) == 1, "the alert is still recorded: %+v", al)
	want(t, al[0].State == "suppressed" && al[0].SuppressedReason == "silence", "state %s reason %s", al[0].State, al[0].SuppressedReason)
	h.flush()
	want(t, len(h.hook.notes()) == 0 && len(h.mail.notes()) == 0, "a silenced alert must not be sent")
	d := h.outbox()
	want(t, len(d[al[0].ID]) == 0, "nothing queued in the outbox")
	want(t, h.sink.seen(al[0].ID), "the UI still hears about suppressed alerts")

	// when it ends, the suppressed alert gets an end time and no notification
	for i := 2; i < 12; i++ {
		h.minute(at(i), LocalState{}, lossMinute(1, "cf", 100, 0))
	}
	a := h.alerts()[0]
	want(t, a.State == "suppressed" && a.EndedAt != nil, "ended suppressed alert: %+v", a)
	h.flush()
	want(t, len(h.hook.notes()) == 0, "no resolved notification for an alert that was never sent")
}

func TestSilenceScopes(t *testing.T) {
	h := newHarness(t, baseYAML)
	warm(h, 6)
	other := int64(2)
	rule := "path-degraded"
	// a silence for another target, and one for another rule, must not suppress end-loss on target 1
	h.st.CreateSilence(store.Silence{TargetID: &other, StartsAt: at(-10), EndsAt: at(60), CreatedBy: "ui"})
	h.st.CreateSilence(store.Silence{Rule: &rule, StartsAt: at(-10), EndsAt: at(60), CreatedBy: "ui"})
	breach(h, 0, 1, LocalState{})
	al := h.alerts()
	want(t, len(al) == 1 && al[0].State == "firing", "unrelated silences: %+v", al)

	// a rule-type scoped silence works as well as a rule-name one
	h2 := newHarness(t, baseYAML)
	warm(h2, 6)
	typ := "final_hop_loss"
	h2.st.CreateSilence(store.Silence{Rule: &typ, StartsAt: at(-10), EndsAt: at(60), CreatedBy: "ui"})
	breach(h2, 0, 1, LocalState{})
	al = h2.alerts()
	want(t, len(al) == 1 && al[0].SuppressedReason == "silence", "type-scoped silence: %+v", al)
}

func TestMaintenanceWindowSuppresses(t *testing.T) {
	yaml := baseYAML + `
  maintenance_windows:
    - name: nightly
      days: [mon, tue, wed, thu, fri, sat, sun]
      start: "00:00"
      end: "23:59"
`
	h := newHarness(t, yaml)
	warm(h, 6)
	breach(h, 0, 1, LocalState{})
	al := h.alerts()
	want(t, len(al) == 1 && al[0].State == "suppressed" && al[0].SuppressedReason == "maintenance", "alerts %+v", al)
	h.flush()
	want(t, len(h.hook.notes()) == 0, "maintenance window suppresses delivery")
}

func TestSilencedAlertFiresWhenSilenceEnds(t *testing.T) {
	h := newHarness(t, baseYAML)
	warm(h, 6)
	h.st.CreateSilence(store.Silence{StartsAt: at(-10), EndsAt: at(4).Add(30 * time.Second), CreatedBy: "ui"})
	breach(h, 0, 3, LocalState{})
	want(t, h.alerts()[0].State == "suppressed", "suppressed during the silence")
	breach(h, 3, 4, LocalState{})
	a := h.alerts()[0]
	want(t, a.State == "firing" && a.SuppressedReason == "", "the condition outlived the silence: %+v", a)
	h.flush()
	n := h.hook.notes()
	want(t, len(n) == 1 && n[0].State == "firing" && n[0].StartedAt.Equal(at(0)), "notified once with the real start: %+v", n)
}

func TestLocalOutageSuppressesPerTargetAlerts(t *testing.T) {
	h := newHarness(t, baseYAML)
	warm(h, 6)
	local := LocalState{Down: true, Since: at(0), Reason: "gateway"}
	breach(h, 0, 2, local)
	al := h.alerts()
	want(t, len(al) == 2, "local alert plus the suppressed per-target alert: %+v", al)
	var loc, tgt store.Alert
	for _, a := range al {
		if a.RuleType == RuleLocalConnectivity {
			loc = a
		} else {
			tgt = a
		}
	}
	want(t, loc.State == "firing" && loc.TargetID == nil && loc.Rule == "local_connectivity", "local alert %+v", loc)
	want(t, loc.StartedAt.Equal(at(0)), "local started_at %v", loc.StartedAt)
	want(t, tgt.State == "suppressed" && tgt.SuppressedReason == "local_outage", "target alert %s/%s", tgt.State, tgt.SuppressedReason)
	var d struct {
		Reason     string `json:"reason"`
		Suppressed []struct {
			AlertID int64  `json:"alert_id"`
			Target  string `json:"target"`
			Rule    string `json:"rule"`
		} `json:"suppressed"`
	}
	if err := json.Unmarshal([]byte(h.alerts()[indexOf(h.alerts(), loc.ID)].DetailsJSON), &d); err != nil {
		t.Fatal(err)
	}
	want(t, d.Reason == "gateway" && len(d.Suppressed) == 1 && d.Suppressed[0].AlertID == tgt.ID && d.Suppressed[0].Rule == "end-loss" && d.Suppressed[0].Target == "cf", "details %+v", d)

	// recovery: the local alert resolves with a notification; the per-target one never notified
	for i := 2; i < 6; i++ {
		h.minute(at(i), LocalState{}, lossMinute(1, "cf", 100, 0))
	}
	h.flush()
	n := h.hook.notes()
	want(t, len(n) == 2 && n[0].State == "firing" && n[1].State == "resolved" && n[0].RuleType == RuleLocalConnectivity, "notifications %v", h.hook.states())
	want(t, n[1].EndedAt != nil && n[1].EndedAt.Before(at(5)), "real end time %v", n[1].EndedAt)
	want(t, len(suppressedFromDetails(n[1].Details)) == 1, "the resolved notification lists the suppressed alert")
	loc = h.alerts()[indexOf(h.alerts(), loc.ID)]
	want(t, loc.State == "resolved", "local alert state %s", loc.State)
}

func TestAlertStartedBeforeLocalOutageStaysFiring(t *testing.T) {
	h := newHarness(t, baseYAML)
	warm(h, 6)
	breach(h, 0, 1, LocalState{})
	want(t, h.alerts()[0].State == "firing", "fired before the outage was detected")
	breach(h, 1, 2, LocalState{Down: true, Since: at(1), Reason: "all_targets"})
	for _, a := range h.alerts() {
		if a.RuleType != RuleLocalConnectivity {
			want(t, a.State == "firing", "only alerts that start during the outage are suppressed: %+v", a)
		}
	}
}

func TestLocalAlertSilenced(t *testing.T) {
	h := newHarness(t, baseYAML)
	warm(h, 2)
	h.st.CreateSilence(store.Silence{StartsAt: at(-10), EndsAt: at(60), CreatedBy: "ui"})
	h.minute(at(0), LocalState{Down: true, Since: at(0), Reason: "gateway"}, lossMinute(1, "cf", 100, 100))
	al := h.alerts()
	want(t, len(al) == 1 && al[0].RuleType == RuleLocalConnectivity && al[0].State == "suppressed" && al[0].SuppressedReason == "silence", "%+v", al)
}

func TestRestartKeepsLocalAlert(t *testing.T) {
	h := newHarness(t, baseYAML)
	h.minute(at(0), LocalState{Down: true, Since: at(0), Reason: "gateway"}, lossMinute(1, "cf", 100, 100))
	id := h.alerts()[0].ID
	h.restart("")
	h.minute(at(1), LocalState{Down: true, Since: at(0), Reason: "gateway"}, lossMinute(1, "cf", 100, 100))
	want(t, len(h.alerts()) == 1, "no duplicate local alert after a restart")
	h.minute(at(2), LocalState{}, lossMinute(1, "cf", 100, 0))
	a := h.alerts()[0]
	want(t, a.ID == id && a.State == "resolved", "restored local alert resolves: %+v", a)
	h.flush()
	want(t, strings.Join(h.hook.states(), ",") == "firing,resolved", "got %v", h.hook.states())
}

func indexOf(al []store.Alert, id int64) int {
	for i, a := range al {
		if a.ID == id {
			return i
		}
	}
	return -1
}

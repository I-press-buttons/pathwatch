package alert

import (
	"strings"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/store"
)

const certYAML = `
alerts:
  rules:
    - name: cert
      type: cert_expiry
      warn_before: 14d
    - name: route
      type: route_change
      notify: [webhook]
`

func certSample(ts time.Time, notAfter time.Time) ProbeSample {
	return ProbeSample{TargetID: 1, ProbeID: 4, Type: "http", TS: ts, OK: true, TotalMS: 50, CertNotAfter: notAfter}
}

func TestCertExpiryFiresOncePerCertificate(t *testing.T) {
	h := newHarness(t, certYAML)
	cert := t0.Add(10 * 24 * time.Hour) // 10 days left: inside the 14-day warning
	for i := 0; i < 4; i++ {
		h.eng.HandleProbe(certSample(at(i).Add(10*time.Second), cert))
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 4, 50))
	}
	al := h.alerts()
	want(t, len(al) == 1 && al[0].RuleType == "cert_expiry" && al[0].State == "firing", "alerts %+v", al)
	want(t, strings.Contains(al[0].Message, "expires in 10 days"), "message %q", al[0].Message)
	want(t, al[0].Value != nil && *al[0].Value > 9.9 && *al[0].Value < 10.1, "value is the days left")
	h.flush()
	want(t, len(h.hook.notes()) == 1, "one notification for the certificate")

	// a restart does not re-fire for the same certificate
	h.restart("")
	for i := 4; i < 7; i++ {
		h.eng.HandleProbe(certSample(at(i).Add(10*time.Second), cert))
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 4, 50))
	}
	want(t, len(h.alerts()) == 1, "no duplicate after restart: %d", len(h.alerts()))

	// the certificate is renewed (seen on two samples): the alert resolves
	renewed := t0.Add(90 * 24 * time.Hour)
	for i := 7; i < 10; i++ {
		h.eng.HandleProbe(certSample(at(i).Add(10*time.Second), renewed))
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 4, 50))
	}
	a := h.alerts()[0]
	want(t, a.State == "resolved", "resolved on certificate change: %s", a.State)
	h.flush()
	want(t, strings.Join(h.hook.states(), ",") == "firing,resolved", "got %v", h.hook.states())

	// after another restart the old certificate does not alert again; a new near-expiry one does
	h.restart("")
	h.eng.HandleProbe(certSample(at(11).Add(10*time.Second), cert))
	h.minute(at(11), LocalState{}, httpMinute(1, "cf", 4, 50))
	want(t, len(h.alerts()) == 1, "an already alerted certificate never alerts twice")
	near := t0.Add(5 * 24 * time.Hour)
	h.eng.HandleProbe(certSample(at(12).Add(10*time.Second), near))
	h.minute(at(12), LocalState{}, httpMinute(1, "cf", 4, 50))
	want(t, len(h.alerts()) == 2, "a different certificate alerts: %d", len(h.alerts()))
}

func TestCertFarFromExpiryDoesNotAlert(t *testing.T) {
	h := newHarness(t, certYAML)
	h.eng.HandleProbe(certSample(at(0).Add(10*time.Second), t0.Add(60*24*time.Hour)))
	h.minute(at(0), LocalState{}, httpMinute(1, "cf", 4, 50))
	want(t, len(h.alerts()) == 0, "60 days left is outside warn_before")
}

func addRouteChange(t *testing.T, h *harness, target int64, ts time.Time) int64 {
	t.Helper()
	id, err := h.st.InsertEvent(store.Event{TargetID: &target, Kind: store.EventRouteChange, From: ts, Details: []byte(`{"from_path":1,"to_path":2,"resolved_ip":"1.1.1.1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestRouteChangeIsAOneShotAlert(t *testing.T) {
	h := newHarness(t, certYAML)
	evID := addRouteChange(t, h, 1, t0.Add(10*time.Second))
	h.minute(at(0), LocalState{}, cleanMinute(1, "t1"))
	al := h.alerts()
	want(t, len(al) == 1 && al[0].RuleType == "route_change", "alerts %+v", al)
	a := al[0]
	want(t, a.State == "resolved" && a.EndedAt != nil && a.EndedAt.Equal(a.StartedAt), "resolves immediately: %+v", a)
	want(t, a.StartedAt.Equal(t0.Add(10*time.Second)), "started at the event time")
	want(t, strings.Contains(a.Message, "path"), "message %q", a.Message)
	// handled once
	h.minute(at(1), LocalState{}, cleanMinute(1, "t1"))
	want(t, len(h.alerts()) == 1, "no duplicates")
	h.flush()
	n := h.hook.notes()
	want(t, len(n) == 1 && n[0].State == StateEvent, "one event notification (webhook only): %v", h.hook.states())
	want(t, len(h.mail.notes()) == 0, "route is routed to the webhook only")
	// and not again after a restart
	h.restart("")
	h.minute(at(2), LocalState{}, cleanMinute(1, "t1"))
	want(t, len(h.alerts()) == 1, "restart must not replay event %d", evID)
	// a second change is a second alert
	addRouteChange(t, h, 1, h.clk.Now())
	h.minute(at(3), LocalState{}, cleanMinute(1, "t1"))
	want(t, len(h.alerts()) == 2, "second route change")
}

func TestRouteChangeDisabledAndPerTarget(t *testing.T) {
	h := newHarness(t, `
targets:
  - name: t1
    host: 127.0.0.1
    alerts:
      disable: [route_change]
alerts:
  rules:
    - name: route
      type: route_change
`)
	addRouteChange(t, h, 1, t0.Add(5*time.Second))
	h.minute(at(0), LocalState{}, cleanMinute(1, "t1"))
	want(t, len(h.alerts()) == 0, "disabled for this target")

	h2 := newHarness(t, `
alerts:
  rules:
    - name: route
      type: route_change
      enabled: false
`)
	addRouteChange(t, h2, 1, t0.Add(5*time.Second))
	h2.minute(at(0), LocalState{}, cleanMinute(1, "t1"))
	want(t, len(h2.alerts()) == 0, "route_change is off with enabled: false")
}

func TestRouteChangeDuringLocalOutageIsSuppressed(t *testing.T) {
	h := newHarness(t, certYAML)
	addRouteChange(t, h, 1, t0.Add(5*time.Second))
	h.minute(at(0), LocalState{Down: true, Since: at(0), Reason: "gateway"}, cleanMinute(1, "t1"))
	var got store.Alert
	for _, a := range h.alerts() {
		if a.RuleType == "route_change" {
			got = a
		}
	}
	want(t, got.State == "suppressed" && got.SuppressedReason == "local_outage", "%+v", got)
}

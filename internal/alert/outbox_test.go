package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

func TestBackoffSchedule(t *testing.T) {
	wantD := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute, 15 * time.Minute}
	for i, w := range wantD {
		if got := Backoff(i + 1); got != w {
			t.Errorf("Backoff(%d) = %v, want %v", i+1, got, w)
		}
	}
	if Backoff(0) != 30*time.Second || Backoff(500) != 15*time.Minute {
		t.Error("Backoff bounds")
	}
}

type hookServer struct {
	ts     *httptest.Server
	status atomic.Int32
	mu     sync.Mutex
	bodies [][]byte
	hdrs   []http.Header
}

func newHookServer(t *testing.T, status int) *hookServer {
	t.Helper()
	h := &hookServer{}
	h.status.Store(int32(status))
	h.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.bodies = append(h.bodies, b)
		h.hdrs = append(h.hdrs, r.Header.Clone())
		h.mu.Unlock()
		w.WriteHeader(int(h.status.Load()))
	}))
	t.Cleanup(h.ts.Close)
	return h
}

func (h *hookServer) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bodies)
}

func outboxSetup(t *testing.T, srv *hookServer, maxAge time.Duration) (*Sender, *store.Store, *fakeClock, *recSink) {
	t.Helper()
	clk := &fakeClock{t: t0}
	st, err := store.Open(filepath.Join(t.TempDir(), "o.db"), store.Options{Logger: quietLog(), NoBackground: true, FlushInterval: 20 * time.Millisecond, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	sink := &recSink{}
	s := NewSender(st, sink, quietLog(), clk.Now)
	ws, err := NewWebhookSender(config.WebhookConfig{URLEnv: "HOOK", Preset: "generic"}, nil, func(string) string { return srv.ts.URL })
	if err != nil {
		t.Fatal(err)
	}
	s.setChannels(map[string]channelSender{ChannelWebhook: ws}, maxAge)
	return s, st, clk, sink
}

func sampleNote(alertID int64, state string) Notification {
	end := t0.Add(-2 * time.Hour)
	n := Notification{
		AlertID: alertID, Target: "cloudflare", Rule: "http-slow", RuleType: "http_latency", State: state, Unit: "ms",
		Message: "HTTP total 412ms vs baseline 85ms", StartedAt: t0.Add(-3 * time.Hour),
	}
	if state == StateResolved {
		n.EndedAt = &end
	}
	return n
}

func TestOutboxRetriesWithBackoffThenDeliversWithRealTimestamps(t *testing.T) {
	srv := newHookServer(t, 503)
	s, st, clk, sink := outboxSetup(t, srv, 24*time.Hour)
	s.Enqueue(sampleNote(12, StateResolved), []string{ChannelWebhook})
	rows := func() store.OutboxRow {
		r, err := st.OutboxRowByID(1)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	want(t, rows().Status == store.OutboxQueued, "starts queued: %s", rows().Status)

	delays := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute}
	for i, d := range delays {
		want(t, s.ProcessDue(context.Background()) == 1, "attempt %d", i+1)
		r := rows()
		want(t, r.Status == store.OutboxRetrying && r.Attempts == i+1, "attempt %d: %+v", i+1, r)
		want(t, r.NextAttemptAt.Equal(clk.Now().Add(d)), "next attempt after %v, got %v", d, r.NextAttemptAt.Sub(clk.Now()))
		want(t, r.LastError == "webhook returned HTTP 503", "last_error %q", r.LastError)
		want(t, s.ProcessDue(context.Background()) == 0, "not due before the backoff elapsed")
		clk.Add(d)
	}
	want(t, srv.count() == 4, "requests %d", srv.count())

	// the webhook recovers (the connection is back): delivered, with the original timestamps
	srv.status.Store(200)
	want(t, s.ProcessDue(context.Background()) == 1, "delivery attempt")
	r := rows()
	want(t, r.Status == store.OutboxDelivered && r.Attempts == 5, "row %+v", r)
	var body map[string]any
	if err := json.Unmarshal(srv.bodies[4], &body); err != nil {
		t.Fatal(err)
	}
	n := sampleNote(12, StateResolved)
	want(t, body["started_at"] == n.StartedAt.UTC().Format(time.RFC3339) && body["ended_at"] == n.EndedAt.UTC().Format(time.RFC3339), "timestamps %v %v", body["started_at"], body["ended_at"])
	want(t, int64(body["started_at_ms"].(float64)) == n.StartedAt.UnixMilli(), "unix ms")
	want(t, body["duration_seconds"].(float64) == 3600, "duration %v", body["duration_seconds"])
	want(t, sink.seen(12), "the UI is told delivery status changed")
	want(t, s.ProcessDue(context.Background()) == 0, "nothing left")
}

func TestOutboxExpires(t *testing.T) {
	srv := newHookServer(t, 500)
	s, st, clk, _ := outboxSetup(t, srv, time.Hour)
	s.Enqueue(sampleNote(1, StateFiring), []string{ChannelWebhook})
	s.ProcessDue(context.Background())
	clk.Add(30 * time.Minute)
	s.ProcessDue(context.Background())
	r, _ := st.OutboxRowByID(1)
	want(t, r.Status == store.OutboxRetrying, "still retrying inside max_age: %s", r.Status)
	// the next attempt is clamped to the expiry time
	want(t, !r.NextAttemptAt.After(r.CreatedAt.Add(time.Hour)), "next attempt %v beyond max_age", r.NextAttemptAt)
	clk.Add(31 * time.Minute)
	n := srv.count()
	s.ProcessDue(context.Background())
	r, _ = st.OutboxRowByID(1)
	want(t, r.Status == store.OutboxExpired && r.LastError != "", "expired row %+v", r)
	want(t, srv.count() == n, "no delivery attempt after expiry")
	clk.Add(time.Hour)
	want(t, s.ProcessDue(context.Background()) == 0, "expired rows are final")
	d, _ := st.Deliveries([]int64{1})
	want(t, len(d[1]) == 1 && d[1][0].Status == "expired" && d[1][0].Attempts >= 2, "API view %+v", d[1])
}

func TestOutboxSurvivesRestartAndKeepsOrder(t *testing.T) {
	srv := newHookServer(t, 500)
	s, st, clk, sink := outboxSetup(t, srv, 24*time.Hour)
	s.Enqueue(sampleNote(3, StateFiring), []string{ChannelWebhook})
	s.Enqueue(sampleNote(3, StateResolved), []string{ChannelWebhook})
	s.ProcessDue(context.Background())
	want(t, srv.count() == 1, "only the firing row is attempted while it is pending; resolved must not overtake it (got %d requests)", srv.count())

	// "restart": a brand-new sender on the same database finds the pending rows
	srv.status.Store(200)
	s2 := NewSender(st, sink, quietLog(), clk.Now)
	ws, _ := NewWebhookSender(config.WebhookConfig{URLEnv: "HOOK"}, nil, func(string) string { return srv.ts.URL })
	s2.setChannels(map[string]channelSender{ChannelWebhook: ws}, 24*time.Hour)
	clk.Add(time.Minute)
	s2.ProcessDue(context.Background())
	want(t, srv.count() == 3, "firing retried then resolved delivered: %d requests", srv.count())
	var first, second map[string]any
	json.Unmarshal(srv.bodies[1], &first)
	json.Unmarshal(srv.bodies[2], &second)
	want(t, first["state"] == "firing" && second["state"] == "resolved", "order %v then %v", first["state"], second["state"])
	d, _ := st.Deliveries([]int64{3})
	want(t, len(d[3]) == 2 && d[3][0].Status == "delivered" && d[3][1].Status == "delivered", "deliveries %+v", d[3])
}

func TestOutboxUnconfiguredChannelRetries(t *testing.T) {
	srv := newHookServer(t, 200)
	s, st, clk, _ := outboxSetup(t, srv, 24*time.Hour)
	s.setChannels(map[string]channelSender{}, 24*time.Hour)
	s.Enqueue(sampleNote(1, StateFiring), []string{ChannelEmail})
	s.ProcessDue(context.Background())
	r, _ := st.OutboxRowByID(1)
	want(t, r.Status == store.OutboxRetrying && r.LastError != "", "row %+v", r)
	clk.Add(time.Minute)
	want(t, s.ProcessDue(context.Background()) == 1, "retried after the backoff")
}

func TestOutboxBrokenPayloadFails(t *testing.T) {
	srv := newHookServer(t, 200)
	s, st, _, _ := outboxSetup(t, srv, 24*time.Hour)
	if _, err := st.EnqueueOutbox(5, ChannelWebhook, "not json", t0); err != nil {
		t.Fatal(err)
	}
	s.ProcessDue(context.Background())
	r, _ := st.OutboxRowByID(1)
	want(t, r.Status == store.OutboxFailed, "status %s", r.Status)
}

func TestSenderLoopDelivers(t *testing.T) {
	srv := newHookServer(t, 200)
	clk := time.Now
	st, err := store.Open(filepath.Join(t.TempDir(), "l.db"), store.Options{Logger: quietLog(), NoBackground: true, FlushInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := NewSender(st, nil, quietLog(), clk)
	ws, _ := NewWebhookSender(config.WebhookConfig{URLEnv: "HOOK"}, nil, func(string) string { return srv.ts.URL })
	s.setChannels(map[string]channelSender{ChannelWebhook: ws}, time.Hour)
	s.Start()
	defer s.Close()
	s.Enqueue(sampleNote(1, StateFiring), []string{ChannelWebhook})
	deadline := time.Now().Add(5 * time.Second)
	for srv.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	want(t, srv.count() == 1, "the sender goroutine delivers on wake-up")
}

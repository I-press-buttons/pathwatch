package alert

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

func TestSendTestDeliversOverTheChannelDirectly(t *testing.T) {
	var bodies []string
	status := http.StatusNoContent
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(status)
	}))
	defer ts.Close()
	t.Setenv("PATHWATCH_TEST_HOOK", ts.URL+"/hook/secret-token")

	clk := &fakeClock{t: t0}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"), store.Options{Logger: quietLog(), NoBackground: true, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := NewSender(st, nil, quietLog(), clk.Now)
	cfg, err := config.Parse(nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "https://nas.local:8095/"
	cfg.Alerts.Notify.Webhook = &config.WebhookConfig{URLEnv: "PATHWATCH_TEST_HOOK", Preset: "generic"}
	s.Configure(cfg)

	if err := s.SendTest(context.Background(), ChannelWebhook); err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("webhook received %d requests, want 1", len(bodies))
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(bodies[0]), &got); err != nil {
		t.Fatal(err)
	}
	want(t, got["state"] == StateEvent && got["rule_type"] == RuleTypeTest && got["alert_id"] == float64(0), "test payload %v", got)
	want(t, got["link"] == "https://nas.local:8095/#/alerts", "link %v", got["link"])
	want(t, strings.Contains(got["message"].(string), "webhook channel works"), "message %v", got["message"])
	// nothing goes through the outbox
	if rows, _ := st.DueOutbox(t0.Add(24*time.Hour), 10); len(rows) != 0 {
		t.Errorf("test notification was queued in the outbox: %v", rows)
	}

	status = http.StatusBadRequest
	err = s.SendTest(context.Background(), ChannelWebhook)
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("failing webhook: err %v, want HTTP 400", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Errorf("error leaks the webhook URL: %v", err)
	}

	if err := s.SendTest(context.Background(), ChannelEmail); !errors.Is(err, ErrChannelNotConfigured) {
		t.Errorf("unconfigured channel: err %v, want ErrChannelNotConfigured", err)
	}
}

func TestTestNotificationRendersInEveryPreset(t *testing.T) {
	n := TestNotification(ChannelWebhook, "", t0)
	want(t, n.Link == "" && n.EndedAt != nil && n.Duration() == 0, "notification %+v", n)
	for _, preset := range []string{"discord", "slack", "ntfy", "generic"} {
		w, err := NewWebhookSender(config.WebhookConfig{URLEnv: "X", Preset: preset}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, hdr, err := w.Render(n)
		// ntfy carries the title in a header and the message in the body
		if err != nil || !strings.Contains(string(body)+hdr["Title"], "test-notification") {
			t.Errorf("%s: err %v body %s headers %v", preset, err, body, hdr)
		}
	}
	if !strings.Contains(Subject(n), "EVENT pathwatch: test-notification") {
		t.Errorf("email subject %q", Subject(n))
	}
}

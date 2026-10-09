package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func decodeInto(t *testing.T, b []byte, v *map[string]any) map[string]any {
	t.Helper()
	*v = nil
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("bad json %v: %s", err, b)
	}
	return *v
}

type fakeNotifier struct {
	mu       sync.Mutex
	channels []string
	errs     map[string]error
	sent     []string
}

func (f *fakeNotifier) Channels() []string { return f.channels }
func (f *fakeNotifier) SendTest(_ context.Context, ch string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, ch)
	return f.errs[ch]
}

func TestChannelsAndTestNotifications(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	clock := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	f.srv.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }

	t.Setenv("PATHWATCH_TEST_HOOK_EMPTY", "")
	cfg := *f.mgr.File()
	cfg.Alerts.Notify.Webhook = &config.WebhookConfig{URLEnv: "PATHWATCH_TEST_HOOK_EMPTY", Preset: "discord"}
	cfg.Alerts.Notify.Email = &config.EmailConfig{SMTPHost: "smtp.example.com", TLS: "starttls", From: "pw@example.com", To: []string{"a@example.com", "b@example.com"}}
	if err := f.mgr.ReloadFile(&cfg); err != nil {
		t.Fatal(err)
	}
	fn := &fakeNotifier{channels: []string{"webhook", "email"}, errs: map[string]error{"email": errors.New("smtp connect: connection refused")}}
	f.srv.d.Notifier = fn
	if _, err := f.st.EnqueueOutbox(7, "webhook", "{}", clock); err != nil {
		t.Fatal(err)
	}

	var list []map[string]any
	if resp := f.getJSON("/api/channels", &list); resp.StatusCode != 200 || len(list) != 2 {
		t.Fatalf("GET /api/channels: %d %v", resp.StatusCode, list)
	}
	hook, mail := list[0], list[1]
	if hook["name"] != "webhook" || hook["configured"] != true || hook["active"] != true || !strings.Contains(hook["summary"].(string), "discord preset") {
		t.Errorf("webhook channel %v", hook)
	}
	if w := hook["warnings"].([]any); len(w) != 1 || !strings.Contains(w[0].(string), "PATHWATCH_TEST_HOOK_EMPTY is empty") {
		t.Errorf("webhook warnings %v", w)
	}
	if d, _ := hook["last_delivery"].(map[string]any); d == nil || d["status"] != "queued" || d["alert_id"] != float64(7) {
		t.Errorf("webhook last delivery %v", hook["last_delivery"])
	}
	if mail["summary"] != "smtp.example.com:587 · starttls · 2 recipients" || mail["last_delivery"] != nil || mail["last_test"] != nil {
		t.Errorf("email channel %v", mail)
	}

	// unknown, then a successful test, then a test too soon after it
	if resp, b := f.postJSON("/api/channels/sms/test", nil); resp.StatusCode != 404 {
		t.Errorf("unknown channel: %d %s", resp.StatusCode, b)
	}
	var res map[string]any
	resp, b := f.postJSON("/api/channels/webhook/test", nil)
	if resp.StatusCode != 200 || decodeInto(t, b, &res)["ok"] != true || res["error"] != nil {
		t.Fatalf("webhook test: %d %s", resp.StatusCode, b)
	}
	resp, b = f.postJSON("/api/channels/webhook/test", nil)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "10" {
		t.Errorf("second test right away: %d %s (Retry-After %q)", resp.StatusCode, b, resp.Header.Get("Retry-After"))
	}
	advance(channelTestGap)
	if resp, b := f.postJSON("/api/channels/webhook/test", nil); resp.StatusCode != 200 {
		t.Errorf("test after the gap: %d %s", resp.StatusCode, b)
	}

	// a failing channel is a successful request carrying the channel's error
	resp, b = f.postJSON("/api/channels/email/test", nil)
	if resp.StatusCode != 200 || decodeInto(t, b, &res)["ok"] != false || res["error"] != "smtp connect: connection refused" {
		t.Errorf("failing email test: %d %s", resp.StatusCode, b)
	}
	f.getJSON("/api/channels", &list)
	if lt, _ := list[1]["last_test"].(map[string]any); lt == nil || lt["ok"] != false || lt["error"] != "smtp connect: connection refused" {
		t.Errorf("email last_test %v", list[1]["last_test"])
	}
	if lt, _ := list[0]["last_test"].(map[string]any); lt == nil || lt["ok"] != true {
		t.Errorf("webhook last_test %v", list[0]["last_test"])
	}

	// a channel the sender does not have
	fn.channels = []string{"webhook"}
	if resp, b := f.postJSON("/api/channels/email/test", nil); resp.StatusCode != http.StatusConflict || !strings.Contains(errMsg(b), "not configured") {
		t.Errorf("unconfigured channel: %d %s", resp.StatusCode, b)
	}
	f.getJSON("/api/channels", &list)
	if list[1]["active"] != false || len(list[1]["warnings"].([]any)) == 0 {
		t.Errorf("configured but rejected email channel %v", list[1])
	}
	if got := strings.Join(fn.sent, ","); got != "webhook,webhook,email" {
		t.Errorf("sent %q", got)
	}
}

func TestTestNotificationIsSameOriginOnly(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	fn := &fakeNotifier{channels: []string{"webhook"}}
	f.srv.d.Notifier = fn
	req, _ := http.NewRequest("POST", f.ts.URL+"/api/channels/webhook/test", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || len(fn.sent) != 0 {
		t.Errorf("cross-site test: %d, sent %v", resp.StatusCode, fn.sent)
	}
}

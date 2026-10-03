package alert

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func noteFor(state string) Notification {
	tid := int64(3)
	v, b, p := 412.0, 85.0, 530.0
	start := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	n := Notification{
		AlertID: 12, TargetID: &tid, Target: "cloudflare", Rule: "http-slow", RuleType: "http_latency", State: state,
		Value: &v, PeakValue: &p, Baseline: &b, Unit: "ms", Message: "HTTP total 412ms vs baseline 85ms",
		StartedAt: start, CreatedAt: start.Add(7 * time.Minute),
		Link: "https://nas.local:8080/#/target/3?from=1&to=2",
	}
	if state == StateResolved {
		end := start.Add(5 * time.Minute)
		n.EndedAt = &end
	}
	return n
}

func render(t *testing.T, cfg config.WebhookConfig, n Notification) ([]byte, map[string]string) {
	t.Helper()
	w, err := NewWebhookSender(cfg, nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	body, h, err := w.Render(n)
	if err != nil {
		t.Fatal(err)
	}
	return body, h
}

func TestWebhookGenericPreset(t *testing.T) {
	body, h := render(t, config.WebhookConfig{Preset: "generic"}, noteFor(StateResolved))
	want(t, h["Content-Type"] == "application/json", "content type %q", h["Content-Type"])
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]any{
		"target": "cloudflare", "rule": "http-slow", "rule_type": "http_latency", "state": "resolved",
		"value": 412.0, "baseline": 85.0, "peak_value": 530.0, "message": "HTTP total 412ms vs baseline 85ms",
		"started_at": "2026-03-10T12:00:00Z", "ended_at": "2026-03-10T12:05:00Z",
		"started_at_ms": float64(time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC).UnixMilli()),
		"duration":      "5m", "duration_seconds": 300.0, "link": "https://nas.local:8080/#/target/3?from=1&to=2",
	} {
		want(t, m[k] == v, "%s = %v (%T), want %v", k, m[k], m[k], v)
	}
	want(t, m["ended_at_ms"] != nil, "ended_at_ms")
	// firing: no end
	body, _ = render(t, config.WebhookConfig{Preset: "generic"}, noteFor(StateFiring))
	m = map[string]any{}
	json.Unmarshal(body, &m)
	want(t, m["state"] == "firing" && m["ended_at"] == nil && m["ended_at_ms"] == nil, "firing payload %v", m)
	want(t, m["duration_seconds"] == 420.0, "ongoing duration %v", m["duration_seconds"])
}

func TestWebhookDiscordPreset(t *testing.T) {
	body, _ := render(t, config.WebhookConfig{Preset: "discord"}, noteFor(StateFiring))
	var m struct {
		Content string `json:"content"`
		Embeds  []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Color       int    `json:"color"`
			URL         string `json:"url"`
			Fields      []struct{ Name, Value string }
		} `json:"embeds"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	want(t, strings.Contains(m.Content, "FIRING cloudflare: http-slow"), "content %q", m.Content)
	want(t, len(m.Embeds) == 1 && m.Embeds[0].Color == 0xE74C3C && m.Embeds[0].Description == "HTTP total 412ms vs baseline 85ms" && m.Embeds[0].URL != "", "embed %+v", m.Embeds)
	body, _ = render(t, config.WebhookConfig{Preset: "discord"}, noteFor(StateResolved))
	json.Unmarshal(body, &m)
	want(t, m.Embeds[0].Color == 0x2ECC71, "resolved is green: %x", m.Embeds[0].Color)
	want(t, strings.Contains(m.Content, "RESOLVED"), "content %q", m.Content)
}

func TestWebhookSlackPreset(t *testing.T) {
	n := noteFor(StateFiring)
	n.Message = "a <b> & c"
	body, h := render(t, config.WebhookConfig{Preset: "slack"}, n)
	want(t, h["Content-Type"] == "application/json", "ct")
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	want(t, len(m) == 1, "slack-compatible: just text, got %v", m)
	want(t, strings.Contains(m["text"], "*FIRING cloudflare: http-slow*") && strings.Contains(m["text"], "a &lt;b&gt; &amp; c") && strings.Contains(m["text"], "<https://nas.local:8080/#/target/3?from=1&to=2|"), "text %q", m["text"])
}

func TestWebhookNtfyPreset(t *testing.T) {
	body, h := render(t, config.WebhookConfig{Preset: "ntfy"}, noteFor(StateFiring))
	want(t, h["Content-Type"] == "text/plain; charset=utf-8", "ct %q", h["Content-Type"])
	want(t, h["Title"] == "FIRING cloudflare: http-slow" && h["Priority"] == "high" && h["Tags"] == "rotating_light", "headers %v", h)
	want(t, h["Click"] == "https://nas.local:8080/#/target/3?from=1&to=2", "click")
	want(t, strings.HasPrefix(string(body), "HTTP total 412ms vs baseline 85ms\n") && strings.Contains(string(body), "Started: 2026-03-10T12:00:00Z"), "body %q", body)
	_, h = render(t, config.WebhookConfig{Preset: "ntfy"}, noteFor(StateResolved))
	want(t, h["Priority"] == "default" && h["Tags"] == "white_check_mark", "resolved headers %v", h)
	n := noteFor(StateFiring)
	n.Target = "evil\r\nX-Injected: 1"
	_, h = render(t, config.WebhookConfig{Preset: "ntfy"}, n)
	want(t, !strings.ContainsAny(h["Title"], "\r\n"), "header injection %q", h["Title"])
}

func TestWebhookBodyTemplateOverridesPreset(t *testing.T) {
	cfg := config.WebhookConfig{Preset: "discord", BodyTemplate: `{"text": {{json .Title}}, "target": {{json .Target}}, "state": "{{.State}}", "value": {{.Value}}, "ms": {{.StartedAtMS}}, "end": "{{.EndedAt}}", "dur": "{{.Duration}}", "vt": "{{.ValueText}}", "u": "{{upper .Rule}}"}`}
	body, h := render(t, cfg, noteFor(StateResolved))
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("template output is not JSON: %s", body)
	}
	want(t, m["text"] == "RESOLVED cloudflare: http-slow" && m["state"] == "resolved" && m["value"] == 412.0 && m["end"] == "2026-03-10T12:05:00Z" && m["dur"] == "5m" && m["vt"] == "412 ms" && m["u"] == "HTTP-SLOW", "body %s", body)
	want(t, h["Content-Type"] == "application/json", "json body detected: %q", h["Content-Type"])
	body, h = render(t, config.WebhookConfig{BodyTemplate: "{{.Title}}: {{.Message}}"}, noteFor(StateFiring))
	want(t, string(body) == "FIRING cloudflare: http-slow: HTTP total 412ms vs baseline 85ms" && h["Content-Type"] == "text/plain; charset=utf-8", "plain template %q %v", body, h)
	if _, err := NewWebhookSender(config.WebhookConfig{BodyTemplate: "{{.Nope"}, nil, nil); err == nil {
		t.Error("a broken template must be rejected")
	}
	// a template that fails at execution time is a permanent error
	w, _ := NewWebhookSender(config.WebhookConfig{BodyTemplate: "{{.Message.Foo}}"}, nil, nil)
	if _, _, err := w.Render(noteFor(StateFiring)); err == nil || !IsPermanent(err) {
		t.Errorf("execution error should be permanent, got %v", err)
	}
}

func TestWebhookSendHeadersAndURLFromEnv(t *testing.T) {
	var got *http.Request
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		gotBody = make([]byte, r.ContentLength)
		r.Body.Read(gotBody)
		w.WriteHeader(204)
	}))
	defer ts.Close()
	env := map[string]string{"HOOK_URL": ts.URL + "/secret/path", "TOKEN": "s3cr3t"}
	getenv := func(k string) string { return env[k] }
	w, err := NewWebhookSender(config.WebhookConfig{
		URLEnv: "HOOK_URL", Preset: "slack",
		Headers: map[string]string{"Authorization": "Bearer ${TOKEN}", "X-Static": "v", "X-Multi": "a $TOKEN b\r\nInjected: 1"},
	}, nil, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Send(context.Background(), noteFor(StateFiring)); err != nil {
		t.Fatal(err)
	}
	want(t, got.Method == "POST" && got.URL.Path == "/secret/path", "method/path %s %s", got.Method, got.URL.Path)
	want(t, got.Header.Get("Authorization") == "Bearer s3cr3t" && got.Header.Get("X-Static") == "v", "headers %v", got.Header)
	want(t, !strings.Contains(got.Header.Get("X-Multi"), "\n") && got.Header.Get("Injected") == "", "header injection: %q", got.Header.Get("X-Multi"))
	want(t, got.Header.Get("Content-Type") == "application/json", "content type")
	want(t, strings.Contains(string(gotBody), `"text"`), "body %s", gotBody)
}

func TestWebhookFailuresNeverLeakTheURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	url := ts.URL + "/api/webhooks/123456/SECRETTOKEN"
	w, _ := NewWebhookSender(config.WebhookConfig{URLEnv: "U"}, nil, func(string) string { return url })
	err := w.Send(context.Background(), noteFor(StateFiring))
	want(t, err != nil && err.Error() == "webhook returned HTTP 500", "non-2xx is a failure: %v", err)
	ts.Close()
	err = w.Send(context.Background(), noteFor(StateFiring))
	want(t, err != nil && !strings.Contains(err.Error(), "SECRETTOKEN") && !strings.Contains(err.Error(), "/api/webhooks"), "connection error leaked the URL: %v", err)

	w, _ = NewWebhookSender(config.WebhookConfig{URLEnv: "MISSING"}, nil, func(string) string { return "" })
	err = w.Send(context.Background(), noteFor(StateFiring))
	want(t, err != nil && strings.Contains(err.Error(), "MISSING"), "missing env: %v", err)
	w, _ = NewWebhookSender(config.WebhookConfig{URLEnv: "BAD"}, nil, func(string) string { return "ftp://secret-host/token" })
	err = w.Send(context.Background(), noteFor(StateFiring))
	want(t, err != nil && !strings.Contains(err.Error(), "token"), "bad URL error must not echo it: %v", err)
}

func TestWebhookTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	block := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer ts.Close()
	defer close(block)
	w, _ := NewWebhookSender(config.WebhookConfig{URLEnv: "U"}, nil, func(string) string { return ts.URL })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := w.Send(ctx, noteFor(StateFiring))
	want(t, err != nil && time.Since(start) < 3*time.Second, "a hanging receiver must fail fast: %v", err)
}

func TestDeepLink(t *testing.T) {
	tid := int64(7)
	end := t0.Add(time.Hour)
	l := deepLink("https://nas.local:8080/", &tid, t0, &end, t0.Add(2*time.Hour))
	want(t, l == "https://nas.local:8080/#/target/7?from="+itoa(t0.Add(-10*time.Minute).UnixMilli())+"&to="+itoa(end.Add(10*time.Minute).UnixMilli()), "link %s", l)
	want(t, deepLink("", &tid, t0, nil, t0) == "", "no public_url, no link")
	want(t, deepLink("https://x", nil, t0, nil, t0) == "https://x/#/alerts", "global alert links to the alerts page")
	l = deepLink("https://x", &tid, t0, nil, t0.Add(time.Minute))
	want(t, strings.Contains(l, "&to="+itoa(t0.Add(time.Minute).UnixMilli())), "firing alert ends at now: %s", l)
}

func itoa(v int64) string { b, _ := json.Marshal(v); return string(b) }

func TestFormatDuration(t *testing.T) {
	for in, want := range map[time.Duration]string{
		0: "0s", 45 * time.Second: "45s", 5 * time.Minute: "5m", 5*time.Minute + 3*time.Second: "5m3s",
		2 * time.Hour: "2h", 2*time.Hour + 10*time.Minute + 30*time.Second: "2h10m", 26 * time.Hour: "26h",
	} {
		if got := FormatDuration(in); got != want {
			t.Errorf("FormatDuration(%v) = %q, want %q", in, got, want)
		}
	}
}

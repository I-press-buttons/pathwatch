package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

// webhookTimeout bounds one webhook delivery attempt.
const webhookTimeout = 10 * time.Second

// permanentError marks a delivery failure that retrying cannot fix (a broken template, an
// unreadable payload). The outbox marks such rows failed instead of retrying them.
type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// IsPermanent reports whether err should not be retried.
func IsPermanent(err error) bool {
	var p permanentError
	return errors.As(err, &p)
}

// WebhookSender delivers notifications as HTTP POSTs. The URL, custom header values and the
// error messages are never logged or stored beyond what is returned here: URLs and headers are
// secrets (Discord and Slack webhook URLs embed their token).
type WebhookSender struct {
	cfg    config.WebhookConfig
	tmpl   *template.Template
	client *http.Client
	getenv func(string) string
}

// NewWebhookSender prepares a sender. client and getenv may be nil.
func NewWebhookSender(cfg config.WebhookConfig, client *http.Client, getenv func(string) string) (*WebhookSender, error) {
	if client == nil {
		client = &http.Client{Timeout: webhookTimeout}
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	w := &WebhookSender{cfg: cfg, client: client, getenv: getenv}
	if cfg.BodyTemplate != "" {
		t, err := config.ParseWebhookTemplate(cfg.BodyTemplate)
		if err != nil {
			return nil, fmt.Errorf("webhook body_template: %w", err)
		}
		w.tmpl = t
	}
	return w, nil
}

// TemplateData is what a webhook body_template receives.
type TemplateData struct {
	AlertID         int64
	Title           string // "FIRING cloudflare: http-slow"
	State           string // firing | resolved | event
	Target          string
	TargetID        int64 // 0 when the alert has no target
	Rule            string
	RuleType        string
	Message         string
	Value           float64
	PeakValue       float64
	Baseline        float64
	Unit            string
	ValueText       string // "412 ms"
	BaselineText    string
	StartedAt       string // RFC3339 (UTC)
	StartedAtMS     int64
	EndedAt         string // "" while firing
	EndedAtMS       int64  // 0 while firing
	Duration        string // "5m3s"
	DurationSeconds int64
	Link            string // "" without public_url
	Details         string // JSON
}

func templateData(n Notification) TemplateData {
	d := TemplateData{
		AlertID: n.AlertID, Title: n.Title(), State: n.State, Target: n.Target, Rule: n.Rule, RuleType: n.RuleType,
		Message: n.Message, Unit: n.Unit, ValueText: n.ValueText(), BaselineText: n.BaselineText(),
		StartedAt: n.StartedAt.UTC().Format(time.RFC3339), StartedAtMS: n.StartedAt.UnixMilli(),
		Duration: FormatDuration(n.Duration()), DurationSeconds: int64(n.Duration() / time.Second),
		Link: n.Link, Details: string(n.Details),
	}
	if n.TargetID != nil {
		d.TargetID = *n.TargetID
	}
	if n.Value != nil {
		d.Value = *n.Value
	}
	if n.PeakValue != nil {
		d.PeakValue = *n.PeakValue
	}
	if n.Baseline != nil {
		d.Baseline = *n.Baseline
	}
	if n.EndedAt != nil {
		d.EndedAt, d.EndedAtMS = n.EndedAt.UTC().Format(time.RFC3339), n.EndedAt.UnixMilli()
	}
	return d
}

// Render builds the request body and headers for a notification: the body_template when set,
// otherwise the preset's body. Custom headers from the config are added by Send.
func (w *WebhookSender) Render(n Notification) ([]byte, map[string]string, error) {
	if w.tmpl != nil {
		var buf bytes.Buffer
		if err := w.tmpl.Execute(&buf, templateData(n)); err != nil {
			return nil, nil, permanentError{fmt.Errorf("body_template: %w", err)}
		}
		ct := "text/plain; charset=utf-8"
		if t := bytes.TrimSpace(buf.Bytes()); len(t) > 0 && (t[0] == '{' || t[0] == '[') {
			ct = "application/json"
		}
		return buf.Bytes(), map[string]string{"Content-Type": ct}, nil
	}
	switch w.cfg.Preset {
	case "discord":
		return renderDiscord(n)
	case "slack":
		return renderSlack(n)
	case "ntfy":
		return renderNtfy(n)
	}
	return renderGeneric(n)
}

func jsonBody(v any) ([]byte, map[string]string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, nil, permanentError{err}
	}
	return b, map[string]string{"Content-Type": "application/json"}, nil
}

func renderGeneric(n Notification) ([]byte, map[string]string, error) {
	m := map[string]any{
		"source": "pathwatch", "alert_id": n.AlertID, "target": n.Target, "target_id": n.TargetID,
		"rule": n.Rule, "rule_type": n.RuleType, "state": n.State,
		"value": n.Value, "peak_value": n.PeakValue, "baseline": n.Baseline, "unit": n.Unit,
		"started_at": n.StartedAt.UTC().Format(time.RFC3339), "started_at_ms": n.StartedAt.UnixMilli(),
		"ended_at": nil, "ended_at_ms": nil,
		"duration": FormatDuration(n.Duration()), "duration_seconds": int64(n.Duration() / time.Second),
		"message": n.Message, "link": n.Link,
	}
	if n.EndedAt != nil {
		m["ended_at"], m["ended_at_ms"] = n.EndedAt.UTC().Format(time.RFC3339), n.EndedAt.UnixMilli()
	}
	if len(n.Details) > 0 {
		m["details"] = n.Details
	}
	return jsonBody(m)
}

// summaryLine is the one-line text used by the chat presets.
func summaryLine(n Notification) string {
	s := n.Title() + " - " + n.Message
	if n.State == StateResolved {
		s += " (lasted " + FormatDuration(n.Duration()) + ")"
	}
	return s
}

func stateColor(state string) int {
	switch state {
	case StateFiring:
		return 0xE74C3C // red
	case StateResolved:
		return 0x2ECC71 // green
	}
	return 0x3498DB // blue (events)
}

func truncate(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}

func renderDiscord(n Notification) ([]byte, map[string]string, error) {
	fields := []map[string]any{
		{"name": "Target", "value": truncate(n.Target, 200), "inline": true},
		{"name": "Rule", "value": truncate(n.Rule, 200), "inline": true},
		{"name": "Started", "value": n.StartedAt.UTC().Format(time.RFC3339), "inline": true},
	}
	if n.EndedAt != nil {
		fields = append(fields, map[string]any{"name": "Ended", "value": n.EndedAt.UTC().Format(time.RFC3339), "inline": true})
	}
	fields = append(fields, map[string]any{"name": "Duration", "value": FormatDuration(n.Duration()), "inline": true})
	if v := n.ValueText(); v != "" {
		fields = append(fields, map[string]any{"name": "Value", "value": v, "inline": true})
	}
	if v := n.BaselineText(); v != "" {
		fields = append(fields, map[string]any{"name": "Baseline", "value": v, "inline": true})
	}
	embed := map[string]any{
		"title":       truncate(n.Title(), 250),
		"description": truncate(n.Message, 3500),
		"color":       stateColor(n.State),
		"timestamp":   n.CreatedAt.UTC().Format(time.RFC3339),
		"fields":      fields,
	}
	if n.Link != "" {
		embed["url"] = n.Link
	}
	return jsonBody(map[string]any{
		"username": "pathwatch",
		"content":  truncate(summaryLine(n), 1900),
		"embeds":   []any{embed},
	})
}

var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func renderSlack(n Notification) ([]byte, map[string]string, error) {
	text := "*" + slackEscaper.Replace(n.Title()) + "*\n" + slackEscaper.Replace(n.Message)
	if n.State == StateResolved {
		text += " (lasted " + FormatDuration(n.Duration()) + ")"
	}
	if n.Link != "" {
		text += "\n<" + n.Link + "|Open in pathwatch>"
	}
	return jsonBody(map[string]any{"text": text})
}

func headerSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

func renderNtfy(n Notification) ([]byte, map[string]string, error) {
	prio, tags := "default", "information_source"
	switch n.State {
	case StateFiring:
		prio, tags = "high", "rotating_light"
	case StateResolved:
		tags = "white_check_mark"
	}
	var b strings.Builder
	b.WriteString(n.Message)
	b.WriteString("\n")
	if v := n.ValueText(); v != "" {
		b.WriteString("Value: " + v)
		if bl := n.BaselineText(); bl != "" {
			b.WriteString(" (baseline " + bl + ")")
		}
		b.WriteString("\n")
	}
	b.WriteString("Started: " + n.StartedAt.UTC().Format(time.RFC3339) + "\n")
	if n.EndedAt != nil {
		b.WriteString("Ended: " + n.EndedAt.UTC().Format(time.RFC3339) + "\n")
	}
	b.WriteString("Duration: " + FormatDuration(n.Duration()) + "\n")
	h := map[string]string{
		"Content-Type": "text/plain; charset=utf-8",
		"Title":        headerSafe(n.Title()),
		"Priority":     prio,
		"Tags":         tags,
	}
	if n.Link != "" {
		h["Click"] = headerSafe(n.Link)
	}
	return []byte(b.String()), h, nil
}

// Send delivers one notification. Errors never contain the webhook URL.
func (w *WebhookSender) Send(ctx context.Context, n Notification) error {
	target := strings.TrimSpace(w.getenv(w.cfg.URLEnv))
	if target == "" {
		return fmt.Errorf("webhook URL environment variable %s is empty", w.cfg.URLEnv)
	}
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("webhook URL in %s is not a valid http(s) URL", w.cfg.URLEnv)
	}
	body, hdr, err := w.Render(n)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return errors.New("cannot build webhook request")
	}
	req.Header.Set("User-Agent", "pathwatch")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for k, v := range w.cfg.Headers {
		req.Header.Set(strings.TrimSpace(k), headerSafe(os.Expand(v, w.getenv)))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL the net/http error embeds
		}
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

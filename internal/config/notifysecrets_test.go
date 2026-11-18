package config

import (
	"strings"
	"testing"
	"time"
)

func TestRedactAndRestoreNotify(t *testing.T) {
	stored := NotifySettings{
		Webhook: &WebhookConfig{URL: "https://hooks.example/T0K3N", Preset: "slack",
			Headers: map[string]string{"X-Token": "literal-secret", "Authorization": "Bearer ${PATHWATCH_NOTIFY_TOKEN}"}},
		Email: &EmailConfig{SMTPHost: "smtp.example", SMTPPort: 587, Username: "me", Password: "hunter2", From: "a@x", To: []string{"b@x"}},
	}
	red := RedactNotify(stored)
	if red.Webhook.URL != HeaderPlaceholder || red.Webhook.Headers["X-Token"] != HeaderPlaceholder || red.Email.Password != HeaderPlaceholder {
		t.Fatalf("not redacted: %+v %+v", red.Webhook, red.Email)
	}
	if red.Webhook.Headers["Authorization"] != "Bearer ${PATHWATCH_NOTIFY_TOKEN}" {
		t.Errorf("a pure reference should stay visible: %q", red.Webhook.Headers["Authorization"])
	}
	if stored.Webhook.URL != "https://hooks.example/T0K3N" || stored.Webhook.Headers["X-Token"] != "literal-secret" || stored.Email.Password != "hunter2" {
		t.Fatal("RedactNotify modified its input")
	}

	// sending the redacted form back keeps every secret
	got, err := RestoreNotify(red, stored)
	if err != nil {
		t.Fatal(err)
	}
	if got.Webhook.URL != stored.Webhook.URL || got.Webhook.Headers["X-Token"] != "literal-secret" || got.Email.Password != "hunter2" {
		t.Errorf("not restored: %+v %+v", got.Webhook, got.Email)
	}

	// a new webhook URL: the stored header secret is not sent to it
	moved := RedactNotify(stored)
	moved.Webhook.URL = "https://attacker.example/"
	if _, err := RestoreNotify(moved, stored); err == nil || !strings.Contains(err.Error(), "X-Token") {
		t.Errorf("header secret followed a new URL: %v", err)
	}
	// a new SMTP server: the stored password is not sent to it
	moved = RedactNotify(stored)
	moved.Email.SMTPHost = "attacker.example"
	if _, err := RestoreNotify(moved, stored); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("password followed a new SMTP server: %v", err)
	}
	moved = RedactNotify(stored)
	moved.Email.SMTPPort = 2525
	if _, err := RestoreNotify(moved, stored); err == nil {
		t.Error("password followed a new SMTP port")
	}
	moved = RedactNotify(stored)
	moved.Email.TLS = "none"
	if _, err := RestoreNotify(moved, stored); err == nil {
		t.Error("password followed a switch to an unencrypted connection")
	}
	// nothing stored
	if _, err := RestoreNotify(red, NotifySettings{}); err == nil {
		t.Error("placeholder URL with nothing stored accepted")
	}
}

func TestCheckNotifyEnv(t *testing.T) {
	file := NotifyConfig{
		Webhook: &WebhookConfig{URLEnv: "SLACK_URL", Headers: map[string]string{"Authorization": "Bearer ${SLACK_TOKEN}"}},
		Email:   &EmailConfig{SMTPHost: "smtp.example", SMTPPort: 587, UsernameEnv: "SMTP_USER", PasswordEnv: "SMTP_PASS"},
	}
	ok := []NotifySettings{
		{}, // no channels
		{Webhook: &WebhookConfig{URL: "https://h.example/", Headers: map[string]string{"X": "${PATHWATCH_NOTIFY_X}", "Y": "plain"}}},
		{Webhook: &WebhookConfig{URLEnv: "PATHWATCH_NOTIFY_URL"}},
		// the config file's own references, unchanged destination
		{Webhook: file.Webhook.clone()},
		{Email: file.Email.clone()},
		{Email: &EmailConfig{SMTPHost: "SMTP.example", SMTPPort: 587, UsernameEnv: "SMTP_USER", PasswordEnv: "PATHWATCH_NOTIFY_PASS"}},
		// the defaults applied (tls: starttls) still match the file's unset value
		{Email: &EmailConfig{SMTPHost: "smtp.example", SMTPPort: 587, TLS: "starttls", UsernameEnv: "SMTP_USER", PasswordEnv: "SMTP_PASS"}},
	}
	for i, n := range ok {
		if err := CheckNotifyEnv(n, file); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := []NotifySettings{
		{Webhook: &WebhookConfig{URLEnv: "PATHWATCH_PASSWORD"}},
		{Webhook: &WebhookConfig{URL: "https://h.example/", Headers: map[string]string{"X": "${PATHWATCH_PASSWORD}"}}},
		{Webhook: &WebhookConfig{URL: "https://h.example/", Headers: map[string]string{"X": "a$HOME"}}},
		// the file's header reference, sent to a different URL
		{Webhook: &WebhookConfig{URL: "https://attacker.example/", Headers: map[string]string{"Authorization": "Bearer ${SLACK_TOKEN}"}}},
		// the file's SMTP credentials, sent to a different server
		{Email: &EmailConfig{SMTPHost: "attacker.example", SMTPPort: 587, UsernameEnv: "SMTP_USER", PasswordEnv: "SMTP_PASS"}},
		{Email: &EmailConfig{SMTPHost: "smtp.example", SMTPPort: 587, PasswordEnv: "PATHWATCH_PASSWORD"}},
		// the file's SMTP credentials over an unencrypted connection
		{Email: &EmailConfig{SMTPHost: "smtp.example", SMTPPort: 587, TLS: "none", UsernameEnv: "SMTP_USER", PasswordEnv: "SMTP_PASS"}},
	}
	for i, n := range bad {
		if err := CheckNotifyEnv(n, file); err == nil {
			t.Errorf("bad[%d] accepted", i)
		}
	}
	if err := CheckNotifyEnv(bad[0], NotifyConfig{}); err == nil || !strings.Contains(err.Error(), NotifyEnvPrefix) {
		t.Errorf("message should name the prefix: %v", err)
	}
}

func TestWithOverridesNewSections(t *testing.T) {
	c, err := Parse([]byte(`
storage:
  raw_retention: 2d
enrich:
  reverse_dns: false
alerts:
  maintenance_windows:
    - {name: nightly, days: [mon], start: "02:00", end: "03:00"}
  heartbeat:
    url: https://hc.example/ping
  notify:
    webhook:
      url_env: HOOK
`), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	// nothing edited: the file applies
	e, err := c.WithOverrides(Overrides{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Alerts.MaintenanceWindows) != 1 || e.Alerts.Notify.Webhook.URLEnv != "HOOK" || e.ReverseDNSEnabled() || e.Storage.RawRetention.D() != 48*time.Hour {
		t.Fatalf("file not applied: %+v", e.Alerts)
	}

	mw := []MaintenanceWindow{}
	o := Overrides{
		Maintenance: &mw,
		Notify:      &NotifySettings{Webhook: &WebhookConfig{URL: "https://h.example/x"}, OutboxMaxAge: Duration(time.Hour)},
		Heartbeat:   &HeartbeatConfig{},
		Retention:   &RetentionSettings{Raw: Duration(3 * time.Hour)},
		Enrich:      &EnrichSettings{ReverseDNS: true},
	}
	e, err = c.WithOverrides(o, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Alerts.MaintenanceWindows) != 0 || e.Alerts.Heartbeat.URL != "" || !e.ReverseDNSEnabled() {
		t.Errorf("overrides not applied: %+v", e.Alerts)
	}
	if w := e.Alerts.Notify.Webhook; w.URL != "https://h.example/x" || w.URLEnv != "" || w.Preset != "generic" {
		t.Errorf("webhook: %+v", w)
	}
	if o.Notify.Webhook.Preset != "" || c.Alerts.Notify.Webhook.URL != "" {
		t.Error("applying defaults wrote through to the overrides or the file config")
	}
	if e.Alerts.Outbox.MaxAge.D() != time.Hour || e.Storage.RawRetention.D() != 3*time.Hour || e.Storage.Rollup1mRetention.D() != 0 {
		t.Errorf("outbox/retention: %v %v %v", e.Alerts.Outbox.MaxAge, e.Storage.RawRetention.D(), e.Storage.Rollup1mRetention.D())
	}

	bad := Overrides{Notify: &NotifySettings{Webhook: &WebhookConfig{URL: "https://h.example/", URLEnv: "PATHWATCH_NOTIFY_URL"}}}
	if _, err := c.WithOverrides(bad, nil, nil); err == nil {
		t.Error("webhook with both a URL and a variable accepted")
	}
	bad = Overrides{Notify: &NotifySettings{Webhook: &WebhookConfig{URL: "ftp://h.example/"}}}
	if _, err := c.WithOverrides(bad, nil, nil); err == nil {
		t.Error("non-http webhook URL accepted")
	}
	bad = Overrides{Retention: &RetentionSettings{Raw: Duration(time.Minute)}}
	if _, err := c.WithOverrides(bad, nil, nil); err == nil {
		t.Error("raw retention under 1h accepted")
	}
	badMW := []MaintenanceWindow{{Name: "x", Days: []string{"funday"}, Start: "1", End: "2"}}
	if _, err := c.WithOverrides(Overrides{Maintenance: &badMW}, nil, nil); err == nil {
		t.Error("invalid maintenance window accepted")
	}
}

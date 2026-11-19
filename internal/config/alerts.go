package config

import (
	"encoding/json"
	"strings"
	"text/template"
	"time"
)

// AlertsConfig holds the alert rules, noise control and notification channels.
type AlertsConfig struct {
	Rules              []RuleConfig        `yaml:"rules"`
	Cooldown           Duration            `yaml:"cooldown"`
	ClearRatio         float64             `yaml:"clear_ratio"`
	MaintenanceWindows []MaintenanceWindow `yaml:"maintenance_windows"`
	Heartbeat          HeartbeatConfig     `yaml:"heartbeat"`
	Outbox             OutboxConfig        `yaml:"outbox"`
	Notify             NotifyConfig        `yaml:"notify"`
}

// RuleConfig is one global alert rule. Only the parameters relevant to Type are used.
type RuleConfig struct {
	Name    string   `yaml:"name" json:"name"`
	Type    string   `yaml:"type" json:"type"`
	Enabled *bool    `yaml:"enabled" json:"enabled,omitempty"`
	Notify  []string `yaml:"notify" json:"notify,omitempty"`

	Consecutive    int      `yaml:"consecutive" json:"consecutive,omitempty"`
	Metric         string   `yaml:"metric" json:"metric,omitempty"`
	BaselineWindow Duration `yaml:"baseline_window" json:"baseline_window_ms,omitempty"`
	MinBaseline    Duration `yaml:"min_baseline" json:"min_baseline_ms,omitempty"`
	Multiplier     float64  `yaml:"multiplier" json:"multiplier,omitempty"`
	MinDelta       Duration `yaml:"min_delta" json:"min_delta_ms,omitempty"`
	Sustain        Duration `yaml:"sustain" json:"sustain_ms,omitempty"`
	ThresholdPct   float64  `yaml:"threshold_pct" json:"threshold_pct,omitempty"`
	Window         Duration `yaml:"window" json:"window_ms,omitempty"`
	WarnBefore     Duration `yaml:"warn_before" json:"warn_before_ms,omitempty"`
}

// IsEnabled reports whether the rule is enabled (default true).
func (r RuleConfig) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// RuleOverride is a per-target override of rule parameters (pointer = "set").
type RuleOverride struct {
	Consecutive    *int      `yaml:"consecutive" json:"consecutive,omitempty"`
	Metric         *string   `yaml:"metric" json:"metric,omitempty"`
	BaselineWindow *Duration `yaml:"baseline_window" json:"baseline_window_ms,omitempty"`
	MinBaseline    *Duration `yaml:"min_baseline" json:"min_baseline_ms,omitempty"`
	Multiplier     *float64  `yaml:"multiplier" json:"multiplier,omitempty"`
	MinDelta       *Duration `yaml:"min_delta" json:"min_delta_ms,omitempty"`
	Sustain        *Duration `yaml:"sustain" json:"sustain_ms,omitempty"`
	ThresholdPct   *float64  `yaml:"threshold_pct" json:"threshold_pct,omitempty"`
	Window         *Duration `yaml:"window" json:"window_ms,omitempty"`
	WarnBefore     *Duration `yaml:"warn_before" json:"warn_before_ms,omitempty"`
}

// IsZero reports whether the override sets nothing.
func (o RuleOverride) IsZero() bool { return o == RuleOverride{} }

// Apply returns r with the override's set fields applied.
func (o RuleOverride) Apply(r RuleConfig) RuleConfig {
	if o.Consecutive != nil {
		r.Consecutive = *o.Consecutive
	}
	if o.Metric != nil {
		r.Metric = *o.Metric
	}
	if o.BaselineWindow != nil {
		r.BaselineWindow = *o.BaselineWindow
	}
	if o.MinBaseline != nil {
		r.MinBaseline = *o.MinBaseline
	}
	if o.Multiplier != nil {
		r.Multiplier = *o.Multiplier
	}
	if o.MinDelta != nil {
		r.MinDelta = *o.MinDelta
	}
	if o.Sustain != nil {
		r.Sustain = *o.Sustain
	}
	if o.ThresholdPct != nil {
		r.ThresholdPct = *o.ThresholdPct
	}
	if o.Window != nil {
		r.Window = *o.Window
	}
	if o.WarnBefore != nil {
		r.WarnBefore = *o.WarnBefore
	}
	return r
}

// TargetAlerts disables or overrides rules for one target. Keys and list entries
// may be rule names or rule types.
type TargetAlerts struct {
	Disable  []string                `yaml:"disable" json:"disable,omitempty"`
	Override map[string]RuleOverride `yaml:"override" json:"override,omitempty"`
}

// AlertSettings is the rules part of the alerts section as the web UI edits it: the rules,
// their thresholds, and the noise control. Notifications (NotifySettings), maintenance windows
// and the heartbeat are separate settings sections.
type AlertSettings struct {
	Rules      []RuleConfig `json:"rules"`
	Cooldown   Duration     `json:"cooldown_ms"`
	ClearRatio float64      `json:"clear_ratio"`
}

// Settings returns the UI-editable part of the alerts section.
func (a AlertsConfig) Settings() AlertSettings {
	return AlertSettings{Rules: append([]RuleConfig{}, a.Rules...), Cooldown: a.Cooldown, ClearRatio: a.ClearRatio}
}

// MaintenanceWindow is a recurring silence defined in config.
type MaintenanceWindow struct {
	Name     string   `yaml:"name" json:"name"`
	Days     []string `yaml:"days" json:"days"`
	Start    string   `yaml:"start" json:"start"`
	End      string   `yaml:"end" json:"end"`
	Timezone string   `yaml:"timezone" json:"timezone,omitempty"`
}

// HeartbeatConfig is a dead-man's switch URL.
type HeartbeatConfig struct {
	URL      string   `yaml:"url" json:"url"`
	Interval Duration `yaml:"interval" json:"interval_ms"`
}

// OutboxConfig tunes notification delivery retries.
type OutboxConfig struct {
	MaxAge Duration `yaml:"max_age"`
}

// NotifyConfig lists notification channels.
type NotifyConfig struct {
	Webhook *WebhookConfig `yaml:"webhook" json:"webhook"`
	Email   *EmailConfig   `yaml:"email" json:"email"`
}

// NotifySettings is the part of the alerts section the web UI edits as "notifications": the
// channels and how long undelivered notifications are retried.
type NotifySettings struct {
	Webhook      *WebhookConfig `json:"webhook"`
	Email        *EmailConfig   `json:"email"`
	OutboxMaxAge Duration       `json:"outbox_max_age_ms"`
}

// NotifySettings returns the notification channels and the outbox age, as the UI edits them.
// The channels are copies: changing them does not change a.
func (a AlertsConfig) NotifySettings() NotifySettings {
	return NotifySettings{Webhook: a.Notify.Webhook.clone(), Email: a.Notify.Email.clone(), OutboxMaxAge: a.Outbox.MaxAge}
}

// WebhookConfig configures the webhook channel. In the config file the URL comes from an env var
// (URLEnv); a webhook set up in the web UI may instead store the URL itself (URL). Header values
// may reference environment variables ($NAME or ${NAME}), expanded when a notification is sent.
// BodyTemplate is an optional Go text/template that replaces the preset's body.
type WebhookConfig struct {
	URLEnv       string            `yaml:"url_env" json:"url_env,omitempty"`
	URL          string            `yaml:"-" json:"url,omitempty"`
	Preset       string            `yaml:"preset" json:"preset"`
	Headers      map[string]string `yaml:"headers" json:"headers,omitempty"`
	BodyTemplate string            `yaml:"body_template" json:"body_template,omitempty"`
}

func (w *WebhookConfig) clone() *WebhookConfig {
	if w == nil {
		return nil
	}
	c := *w
	if w.Headers != nil {
		c.Headers = make(map[string]string, len(w.Headers))
		for k, v := range w.Headers {
			c.Headers[k] = v
		}
	}
	return &c
}

// EmailConfig configures the SMTP channel. In the config file credentials come from env vars;
// an email channel set up in the web UI may instead store them (Username, Password).
type EmailConfig struct {
	SMTPHost    string   `yaml:"smtp_host" json:"smtp_host"`
	SMTPPort    int      `yaml:"smtp_port" json:"smtp_port,omitempty"`
	TLS         string   `yaml:"tls" json:"tls"`
	UsernameEnv string   `yaml:"username_env" json:"username_env,omitempty"`
	PasswordEnv string   `yaml:"password_env" json:"password_env,omitempty"`
	Username    string   `yaml:"-" json:"username,omitempty"`
	Password    string   `yaml:"-" json:"password,omitempty"`
	From        string   `yaml:"from" json:"from"`
	To          []string `yaml:"to" json:"to"`
}

func (e *EmailConfig) clone() *EmailConfig {
	if e == nil {
		return nil
	}
	c := *e
	c.To = append([]string(nil), e.To...)
	return &c
}

// RuleTypes lists the known rule types.
var RuleTypes = []string{
	"http_failure", "http_latency", "final_hop_loss", "path_degradation",
	"tcp_failure", "dns_failure", "dns_latency", "cert_expiry", "route_change",
	"public_ip_change", "monitor_health",
}

func (a *AlertsConfig) applyDefaults() {
	if a.Cooldown == 0 {
		a.Cooldown = Duration(30 * time.Minute)
	}
	if a.ClearRatio == 0 {
		a.ClearRatio = 0.7
	}
	if a.Heartbeat.Interval == 0 {
		a.Heartbeat.Interval = Duration(5 * time.Minute)
	}
	if a.Outbox.MaxAge == 0 {
		a.Outbox.MaxAge = Duration(24 * time.Hour)
	}
	if a.Notify.Webhook != nil && a.Notify.Webhook.Preset == "" {
		a.Notify.Webhook.Preset = "generic"
	}
	if a.Notify.Email != nil && a.Notify.Email.TLS == "" {
		a.Notify.Email.TLS = "starttls"
	}
	for i := range a.Rules {
		r := &a.Rules[i]
		if r.Name == "" {
			r.Name = r.Type
		}
		switch r.Type {
		case "http_failure", "tcp_failure", "dns_failure":
			if r.Consecutive == 0 {
				r.Consecutive = 3
			}
		case "http_latency", "dns_latency":
			if r.Metric == "" {
				r.Metric = "total"
			}
			if r.BaselineWindow == 0 {
				r.BaselineWindow = Duration(24 * time.Hour)
			}
			if r.MinBaseline == 0 {
				r.MinBaseline = Duration(2 * time.Hour)
			}
			if r.Multiplier == 0 {
				r.Multiplier = 3
			}
			if r.MinDelta == 0 {
				r.MinDelta = Duration(50 * time.Millisecond)
			}
			if r.Sustain == 0 {
				r.Sustain = Duration(5 * time.Minute)
			}
		case "final_hop_loss":
			if r.ThresholdPct == 0 {
				r.ThresholdPct = 5
			}
			if r.Window == 0 {
				r.Window = Duration(5 * time.Minute)
			}
		case "path_degradation", "monitor_health":
			if r.Sustain == 0 {
				r.Sustain = Duration(5 * time.Minute)
			}
		case "cert_expiry":
			if r.WarnBefore == 0 {
				r.WarnBefore = Duration(14 * 24 * time.Hour)
			}
		}
	}
}

// WebhookTemplateFuncs are the helper functions available to webhook body templates:
// json (a value as a JSON literal), upper, lower and trim.
func WebhookTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"json": func(v any) (string, error) {
			b, err := json.Marshal(v)
			return string(b), err
		},
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
		"trim":  strings.TrimSpace,
	}
}

// ParseWebhookTemplate parses a webhook body template.
func ParseWebhookTemplate(text string) (*template.Template, error) {
	return template.New("webhook").Funcs(WebhookTemplateFuncs()).Option("missingkey=zero").Parse(text)
}

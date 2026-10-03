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
	Name    string   `yaml:"name"`
	Type    string   `yaml:"type"`
	Enabled *bool    `yaml:"enabled"`
	Notify  []string `yaml:"notify"`

	Consecutive    int      `yaml:"consecutive"`
	Metric         string   `yaml:"metric"`
	BaselineWindow Duration `yaml:"baseline_window"`
	MinBaseline    Duration `yaml:"min_baseline"`
	Multiplier     float64  `yaml:"multiplier"`
	MinDelta       Duration `yaml:"min_delta"`
	Sustain        Duration `yaml:"sustain"`
	ThresholdPct   float64  `yaml:"threshold_pct"`
	Window         Duration `yaml:"window"`
	WarnBefore     Duration `yaml:"warn_before"`
}

// IsEnabled reports whether the rule is enabled (default true).
func (r RuleConfig) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// RuleOverride is a per-target override of rule parameters (pointer = "set").
type RuleOverride struct {
	Consecutive    *int      `yaml:"consecutive"`
	Metric         *string   `yaml:"metric"`
	BaselineWindow *Duration `yaml:"baseline_window"`
	MinBaseline    *Duration `yaml:"min_baseline"`
	Multiplier     *float64  `yaml:"multiplier"`
	MinDelta       *Duration `yaml:"min_delta"`
	Sustain        *Duration `yaml:"sustain"`
	ThresholdPct   *float64  `yaml:"threshold_pct"`
	Window         *Duration `yaml:"window"`
	WarnBefore     *Duration `yaml:"warn_before"`
}

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
	Disable  []string                `yaml:"disable"`
	Override map[string]RuleOverride `yaml:"override"`
}

// MaintenanceWindow is a recurring silence defined in config.
type MaintenanceWindow struct {
	Name     string   `yaml:"name"`
	Days     []string `yaml:"days"`
	Start    string   `yaml:"start"`
	End      string   `yaml:"end"`
	Timezone string   `yaml:"timezone"`
}

// HeartbeatConfig is a dead-man's switch URL.
type HeartbeatConfig struct {
	URL      string   `yaml:"url"`
	Interval Duration `yaml:"interval"`
}

// OutboxConfig tunes notification delivery retries.
type OutboxConfig struct {
	MaxAge Duration `yaml:"max_age"`
}

// NotifyConfig lists notification channels.
type NotifyConfig struct {
	Webhook *WebhookConfig `yaml:"webhook"`
	Email   *EmailConfig   `yaml:"email"`
}

// WebhookConfig configures the webhook channel. The URL comes from an env var. Header values
// may reference environment variables ($NAME or ${NAME}), expanded when a notification is sent.
// BodyTemplate is an optional Go text/template that replaces the preset's body.
type WebhookConfig struct {
	URLEnv       string            `yaml:"url_env"`
	Preset       string            `yaml:"preset"`
	Headers      map[string]string `yaml:"headers"`
	BodyTemplate string            `yaml:"body_template"`
}

// EmailConfig configures the SMTP channel. Credentials come from env vars.
type EmailConfig struct {
	SMTPHost    string   `yaml:"smtp_host"`
	SMTPPort    int      `yaml:"smtp_port"`
	TLS         string   `yaml:"tls"`
	UsernameEnv string   `yaml:"username_env"`
	PasswordEnv string   `yaml:"password_env"`
	From        string   `yaml:"from"`
	To          []string `yaml:"to"`
}

// RuleTypes lists the known rule types.
var RuleTypes = []string{
	"http_failure", "http_latency", "final_hop_loss", "path_degradation",
	"tcp_failure", "dns_failure", "dns_latency", "cert_expiry", "route_change",
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
		case "path_degradation":
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

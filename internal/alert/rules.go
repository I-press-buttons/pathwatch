package alert

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

// Rule type of the built-in local connectivity alert (not configurable).
const RuleLocalConnectivity = "local_connectivity"

// settings is an immutable snapshot of the alerting configuration. The engine swaps it on reload.
type settings struct {
	rules       []config.RuleConfig
	cooldown    time.Duration
	clearRatio  float64
	maint       MaintenanceWindows
	targetRules map[string]config.TargetAlerts // by target name
	publicURL   string
}

func newSettings(cfg *config.Config) *settings {
	s := &settings{
		rules:       append([]config.RuleConfig(nil), cfg.Alerts.Rules...),
		cooldown:    cfg.Alerts.Cooldown.D(),
		clearRatio:  cfg.Alerts.ClearRatio,
		maint:       MaintenanceWindows(append([]config.MaintenanceWindow(nil), cfg.Alerts.MaintenanceWindows...)),
		targetRules: map[string]config.TargetAlerts{},
		publicURL:   cfg.PublicURL,
	}
	if s.clearRatio <= 0 || s.clearRatio >= 1 {
		s.clearRatio = 0.7
	}
	for _, t := range cfg.Targets {
		if len(t.Alerts.Disable) > 0 || len(t.Alerts.Override) > 0 {
			s.targetRules[t.Name] = t.Alerts
		}
	}
	return s
}

// effective returns rule r as it applies to the named target: ok is false when the rule is
// disabled globally or for the target (alerts.disable accepts rule names or types); per-target
// overrides (keyed by rule type or name, the name winning) are applied.
func (s *settings) effective(target string, r config.RuleConfig) (config.RuleConfig, bool) {
	if !r.IsEnabled() {
		return r, false
	}
	ta, ok := s.targetRules[target]
	if !ok || target == "" {
		return r, true
	}
	for _, d := range ta.Disable {
		if d == r.Name || d == r.Type {
			return r, false
		}
	}
	if o, ok := ta.Override[r.Type]; ok {
		r = o.Apply(r)
	}
	if o, ok := ta.Override[r.Name]; ok {
		r = o.Apply(r)
	}
	return r, true
}

// rulesFor lists the effective rules of a type that apply to the target.
func (s *settings) rulesFor(target, ruleType string) []config.RuleConfig {
	var out []config.RuleConfig
	for _, r := range s.rules {
		if r.Type != ruleType {
			continue
		}
		if er, ok := s.effective(target, r); ok {
			out = append(out, er)
		}
	}
	return out
}

// ruleByName finds the effective rule with the given name for a target.
func (s *settings) ruleByName(target, name string) (config.RuleConfig, bool) {
	for _, r := range s.rules {
		if r.Name == name {
			return s.effective(target, r)
		}
	}
	return config.RuleConfig{}, false
}

// madK is the width, in robust standard deviations, of the noise band a latency anomaly must
// clear in addition to multiplier and min_delta (a noisy metric needs a bigger excursion).
const madK = 4.0

// latencyThreshold is the value above which a latency rule's condition holds: the largest of
// multiplier x baseline, baseline + min_delta and baseline + madK robust standard deviations
// (1.4826 x MAD).
func latencyThreshold(r config.RuleConfig, median, mad float64) float64 {
	t := median * r.Multiplier
	if d := median + float64(r.MinDelta.D())/float64(time.Millisecond); d > t {
		t = d
	}
	if m := median + madK*1.4826*mad; m > t {
		t = m
	}
	return t
}

// clearThreshold is the hysteresis threshold: clear_ratio x the trigger threshold. When that
// would not even be above the baseline (a small multiplier), the midpoint between baseline and
// trigger is used so the alert can always clear.
func clearThreshold(trigger, median, ratio float64) float64 {
	c := trigger * ratio
	if c <= median {
		c = median + (trigger-median)*0.5
	}
	return c
}

func fmtMS(v float64) string {
	if v < 10 {
		return fmt.Sprintf("%.1fms", v)
	}
	return fmt.Sprintf("%.0fms", v)
}

func fmtPct(v float64) string {
	if v >= 10 {
		return fmt.Sprintf("%.0f%%", math.Round(v))
	}
	return fmt.Sprintf("%.1f%%", v)
}

func fmtWindow(d time.Duration) string {
	if d%time.Hour == 0 && d >= time.Hour {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
	return d.String()
}

func metricLabel(metric string) string {
	if metric == "ttfb" {
		return "TTFB"
	}
	return "total"
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func failureReason(s ProbeSample) string {
	if s.Error != "" {
		e := s.Error
		if len(e) > 160 {
			e = e[:160]
		}
		return e
	}
	if s.Status != 0 {
		return fmt.Sprintf("HTTP status %d", s.Status)
	}
	return "probe failed"
}

func probeKind(ruleType string) string {
	switch ruleType {
	case "http_failure", "http_latency", "cert_expiry":
		return "HTTP"
	case "tcp_failure":
		return "TCP"
	}
	return "DNS"
}

func daysUntil(t, now time.Time) float64 { return t.Sub(now).Hours() / 24 }

func certMessage(notAfter, now time.Time) string {
	d := daysUntil(notAfter, now)
	date := notAfter.UTC().Format("2006-01-02")
	if d < 0 {
		return fmt.Sprintf("TLS certificate expired on %s", date)
	}
	if d < 1 {
		return fmt.Sprintf("TLS certificate expires in %.0f hours (%s)", math.Max(d*24, 0), date)
	}
	return fmt.Sprintf("TLS certificate expires in %.0f days (%s)", d, date)
}

// suppressedFromDetails lists "target: rule" entries recorded in a local_connectivity alert's
// details (the per-target alerts that began during the outage and were suppressed).
func suppressedFromDetails(details []byte) []string {
	var d struct {
		Suppressed []struct {
			Target string `json:"target"`
			Rule   string `json:"rule"`
		} `json:"suppressed"`
	}
	if len(details) == 0 || json.Unmarshal(details, &d) != nil {
		return nil
	}
	var out []string
	for _, s := range d.Suppressed {
		out = append(out, strings.TrimSpace(s.Target+": "+s.Rule))
	}
	return out
}

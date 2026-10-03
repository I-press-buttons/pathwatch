package config

import (
	"strings"
	"time"
)

// Overrides are the settings edited in the web UI and stored in the database. Each non-nil
// section replaces the same section of the config file; nil means "as in the config file".
type Overrides struct {
	Defaults  *Defaults
	Status    *StatusConfig
	Alerts    *AlertSettings
	DNSProbes *[]DNSProbeConfig
}

// WithOverrides returns the effective configuration: c with the UI overrides applied, the
// config-file targets replaced by their UI-edited definitions (edited, keyed by lower-case
// target name), and the UI targets attached. c is not modified. The result has its defaults
// filled in and is validated; on error it is still returned (for diagnostics) but must not be used.
func (c *Config) WithOverrides(o Overrides, edited map[string]TargetConfig, ui []TargetConfig) (*Config, error) {
	e := *c
	if o.Defaults != nil {
		e.Defaults = *o.Defaults
	}
	if o.Status != nil {
		e.Status = *o.Status
	}
	e.Alerts.Rules = append([]RuleConfig(nil), c.Alerts.Rules...)
	if o.Alerts != nil {
		e.Alerts.Rules = append([]RuleConfig(nil), o.Alerts.Rules...)
		e.Alerts.Cooldown = o.Alerts.Cooldown
		e.Alerts.ClearRatio = o.Alerts.ClearRatio
	}
	e.DNSProbes = append([]DNSProbeConfig(nil), c.DNSProbes...)
	if o.DNSProbes != nil {
		e.DNSProbes = append([]DNSProbeConfig(nil), (*o.DNSProbes)...)
	}
	e.Targets = append([]TargetConfig(nil), c.Targets...)
	for i, tc := range e.Targets {
		if ed, ok := edited[strings.ToLower(tc.Name)]; ok {
			ed.Name = tc.Name // the name links the edit to the file entry
			e.Targets[i] = ed
		}
	}
	e.UITargets = append([]TargetConfig(nil), ui...)
	e.applyDefaults()
	return &e, e.Validate()
}

// NormalizeTarget rewrites a target definition into the shape the UI edits, without changing
// what it means: an icmp-trace probe is listed explicitly when it is implied, target-level
// intervals, timeouts and retries move onto the probes they apply to, and per-target alert
// settings keyed by rule type are expanded to the names of the rules of that type.
func NormalizeTarget(tc TargetConfig, rules []RuleConfig) TargetConfig {
	out := tc
	out.Probes = append([]ProbeConfig(nil), tc.Probes...)
	if len(out.Probes) == 0 {
		out.Probes = []ProbeConfig{{Type: ProbeICMPTrace}}
	}
	for i := range out.Probes {
		p := &out.Probes[i]
		switch p.Type {
		case ProbeICMPTrace:
			if p.Interval == 0 {
				p.Interval = tc.ICMPInterval
			}
			if p.Timeout == 0 {
				p.Timeout = tc.ICMPTimeout
			}
		case ProbeHTTP, ProbeTCP:
			if p.Interval == 0 {
				if p.Type == ProbeHTTP {
					p.Interval = tc.HTTPInterval
				} else {
					p.Interval = tc.TCPInterval
				}
			}
			if p.Retries == nil && tc.Retries != nil {
				v := *tc.Retries
				p.Retries = &v
			}
		}
	}
	out.ICMPInterval, out.ICMPTimeout, out.HTTPInterval, out.TCPInterval, out.Retries = 0, 0, 0, 0, nil

	typeOf := map[string]string{}
	namesOf := map[string][]string{}
	for _, r := range rules {
		typeOf[r.Name] = r.Type
		namesOf[r.Type] = append(namesOf[r.Type], r.Name)
	}
	out.Alerts = TargetAlerts{}
	seen := map[string]bool{}
	for _, d := range tc.Alerts.Disable {
		names := []string{d}
		if _, isName := typeOf[d]; !isName && len(namesOf[d]) > 0 {
			names = namesOf[d]
		}
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				out.Alerts.Disable = append(out.Alerts.Disable, n)
			}
		}
	}
	if len(tc.Alerts.Override) > 0 {
		out.Alerts.Override = map[string]RuleOverride{}
		// type-keyed overrides first, so a name-keyed one wins (as in the rule engine)
		for k, o := range tc.Alerts.Override {
			if _, isName := typeOf[k]; isName || len(namesOf[k]) == 0 {
				continue
			}
			for _, n := range namesOf[k] {
				out.Alerts.Override[n] = mergeOverride(out.Alerts.Override[n], o)
			}
		}
		for k, o := range tc.Alerts.Override {
			if _, isName := typeOf[k]; isName || len(namesOf[k]) == 0 {
				out.Alerts.Override[k] = mergeOverride(out.Alerts.Override[k], o)
			}
		}
	}
	return out
}

// mergeOverride returns base with the fields set in o applied.
func mergeOverride(base, o RuleOverride) RuleOverride {
	if o.Consecutive != nil {
		base.Consecutive = o.Consecutive
	}
	if o.Metric != nil {
		base.Metric = o.Metric
	}
	if o.BaselineWindow != nil {
		base.BaselineWindow = o.BaselineWindow
	}
	if o.MinBaseline != nil {
		base.MinBaseline = o.MinBaseline
	}
	if o.Multiplier != nil {
		base.Multiplier = o.Multiplier
	}
	if o.MinDelta != nil {
		base.MinDelta = o.MinDelta
	}
	if o.Sustain != nil {
		base.Sustain = o.Sustain
	}
	if o.ThresholdPct != nil {
		base.ThresholdPct = o.ThresholdPct
	}
	if o.Window != nil {
		base.Window = o.Window
	}
	if o.WarnBefore != nil {
		base.WarnBefore = o.WarnBefore
	}
	return base
}

// TargetConfigFromResolved converts a resolved target (the form UI targets were stored in
// before they became editable) back into a definition. Values equal to the current defaults
// are left unset, so they keep following the defaults.
func TargetConfigFromResolved(t Target, d Defaults) TargetConfig {
	tc := TargetConfig{Name: t.Name, Host: t.Host, Alerts: t.Alerts}
	ifDiff := func(v time.Duration, def Duration) Duration {
		if v == def.D() {
			return 0
		}
		return Duration(v)
	}
	if t.ICMP != nil {
		p := ProbeConfig{Type: ProbeICMPTrace, Interval: ifDiff(t.ICMP.Interval, d.ICMPInterval)}
		if t.ICMP.Timeout != d.ICMPTimeout.D() && t.ICMP.Timeout != t.ICMP.Interval {
			p.Timeout = Duration(t.ICMP.Timeout)
		}
		tc.Probes = append(tc.Probes, p)
		tc.PathRediscovery = ifDiff(t.ICMP.Rediscovery, d.PathRediscovery)
		if t.ICMP.MaxHops != d.MaxHops {
			tc.MaxHops = t.ICMP.MaxHops
		}
	}
	for _, p := range t.Probes {
		pc := ProbeConfig{Type: p.Type}
		switch p.Type {
		case ProbeHTTP:
			pc.Interval = ifDiff(p.Interval, d.HTTPInterval)
			pc.Timeout = ifDiff(p.Timeout, d.HTTPTimeout)
			pc.URL, pc.Method, pc.ExpectStatus = p.URL, p.Method, IntList(p.ExpectStatus)
			pc.FollowRedirects, pc.Headers, pc.UserAgent = p.FollowRedirects, p.Headers, p.UserAgent
			pc.InsecureSkipVerify, pc.UseEnvProxy = p.InsecureSkipVerify, p.UseEnvProxy
			if p.MaxBody != defaultMaxBody {
				pc.MaxBody = p.MaxBody
			}
			if !p.PinIP {
				f := false
				pc.PinIP = &f
			}
		case ProbeTCP:
			pc.Interval = ifDiff(p.Interval, d.TCPInterval)
			pc.Timeout = ifDiff(p.Timeout, d.TCPTimeout)
			pc.Port = p.Port
		}
		if p.Retries != d.Retries {
			n := p.Retries
			pc.Retries = &n
		}
		tc.Probes = append(tc.Probes, pc)
	}
	return tc
}

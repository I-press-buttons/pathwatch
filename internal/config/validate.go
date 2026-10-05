package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Validate checks the whole configuration and returns all problems found.
func (c *Config) Validate() error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	if host, port, err := net.SplitHostPort(c.Listen); err != nil {
		add("listen %q must be host:port (for example 127.0.0.1:8080)", c.Listen)
	} else {
		_ = host
		if n, perr := strconv.Atoi(port); perr != nil || n < 0 || n > 65535 {
			add("listen %q has an invalid port", c.Listen)
		}
	}
	if c.PublicURL != "" {
		u, err := url.Parse(c.PublicURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("public_url %q must be an http(s) URL", c.PublicURL)
		}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		add("tls.cert_file and tls.key_file must be set together")
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		add("log.level %q must be debug, info, warn or error", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		add("log.format %q must be text or json", c.Log.Format)
	}
	switch c.Probing.ICMPMode {
	case "auto", "raw", "dgram":
	default:
		add("probing.icmp_mode %q must be auto, raw or dgram", c.Probing.ICMPMode)
	}
	for name, d := range map[string]*Duration{
		"storage.raw_retention":       c.Storage.RawRetention,
		"storage.rollup_1m_retention": c.Storage.Rollup1mRetention,
		"storage.rollup_1h_retention": c.Storage.Rollup1hRetention,
	} {
		if d != nil && d.D() < 0 {
			add("%s must not be negative", name)
		}
	}
	if c.Storage.RawRetention.D() != 0 && c.Storage.RawRetention.D() < time.Hour {
		add("storage.raw_retention must be at least 1h (or 0 to keep forever)")
	}

	df := c.Defaults
	if df.MaxHops < 1 || df.MaxHops > 64 {
		add("defaults.max_hops must be between 1 and 64")
	}
	if df.Retries < 0 || df.Retries > MaxRetries {
		add("defaults.retries must be between 0 and %d", MaxRetries)
	}
	if df.ICMPInterval.D() > 0 && df.ICMPInterval.D() < 500*time.Millisecond {
		add("defaults.icmp_interval %v is too small (minimum 500ms)", df.ICMPInterval.D())
	}
	for name, d := range map[string]Duration{"tcp_interval": df.TCPInterval, "http_interval": df.HTTPInterval, "dns_interval": df.DNSInterval} {
		if d.D() > 0 && d.D() < time.Second {
			add("defaults.%s %v is too small (minimum 1s)", name, d.D())
		}
	}
	if df.PathRediscovery.D() > 0 && df.PathRediscovery.D() < 10*time.Second {
		add("defaults.path_rediscovery %v is too small (minimum 10s)", df.PathRediscovery.D())
	}
	if v := c.Status.DegradedLossPct; v <= 0 || v > 100 {
		add("status.degraded_loss_pct must be in (0, 100]")
	}
	if v := c.Status.DegradedHTTPSuccessPct; v <= 0 || v > 100 {
		add("status.degraded_http_success_pct must be in (0, 100]")
	}
	for name, d := range map[string]Duration{
		"icmp_interval": df.ICMPInterval, "icmp_timeout": df.ICMPTimeout, "tcp_interval": df.TCPInterval,
		"tcp_timeout": df.TCPTimeout, "http_interval": df.HTTPInterval, "http_timeout": df.HTTPTimeout,
		"dns_interval": df.DNSInterval, "dns_timeout": df.DNSTimeout, "path_rediscovery": df.PathRediscovery,
	} {
		if d.D() < 0 {
			add("defaults.%s must be positive", name)
		}
	}

	if len(c.Targets) > MaxTargets {
		add("too many targets (%d, max %d)", len(c.Targets), MaxTargets)
	}
	if len(c.DNSProbes) > MaxDNSProbes {
		add("too many DNS probes (%d, max %d)", len(c.DNSProbes), MaxDNSProbes)
	}
	names := map[string]bool{}
	ruleKeys := map[string]bool{}
	for _, k := range c.ruleKeys() {
		ruleKeys[k] = true
	}
	for i, tc := range c.Targets {
		if _, err := ResolveTarget(tc, c.Defaults); err != nil {
			errs = append(errs, fmt.Errorf("targets[%d]: %w", i, err))
		}
		key := strings.ToLower(tc.Name)
		if names[key] {
			add("targets[%d]: duplicate target name %q", i, tc.Name)
		}
		names[key] = true
		for _, d := range tc.Alerts.Disable {
			if !ruleKeys[d] {
				add("targets[%d] (%s): alerts.disable references unknown rule %q", i, tc.Name, d)
			}
		}
		for k := range tc.Alerts.Override {
			if !ruleKeys[k] {
				add("targets[%d] (%s): alerts.override references unknown rule %q", i, tc.Name, k)
			}
		}
	}
	for _, tc := range c.UITargets {
		for _, d := range tc.Alerts.Disable {
			if !ruleKeys[d] {
				add("target %q: alert settings disable unknown rule %q", tc.Name, d)
			}
		}
		for k := range tc.Alerts.Override {
			if !ruleKeys[k] {
				add("target %q: alert settings override unknown rule %q", tc.Name, k)
			}
		}
	}
	dnsNames := map[string]bool{}
	for i, dc := range c.DNSProbes {
		if _, err := ResolveDNSProbe(dc, c.Defaults); err != nil {
			errs = append(errs, fmt.Errorf("dns_probes[%d]: %w", i, err))
		}
		key := strings.ToLower(dc.Name)
		if dnsNames[key] {
			add("dns_probes[%d]: duplicate name %q", i, dc.Name)
		}
		dnsNames[key] = true
	}
	errs = append(errs, c.validateAlerts()...)
	return errors.Join(errs...)
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// ParseWeekday parses a three-letter (or full) lower/upper-case weekday name.
func ParseWeekday(s string) (time.Weekday, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) >= 3 {
		w, ok := weekdays[s[:3]]
		return w, ok
	}
	return 0, false
}

// ParseClock parses "HH:MM" into minutes since midnight.
func ParseClock(s string) (int, bool) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, false
	}
	return t.Hour()*60 + t.Minute(), true
}

func (c *Config) validateAlerts() []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	a := c.Alerts
	if a.ClearRatio <= 0 || a.ClearRatio >= 1 {
		add("alerts.clear_ratio must be between 0 and 1 (exclusive)")
	}
	if a.Cooldown.D() < 0 {
		add("alerts.cooldown must not be negative")
	}
	typeOK := map[string]bool{}
	for _, t := range RuleTypes {
		typeOK[t] = true
	}
	names := map[string]bool{}
	for i, r := range a.Rules {
		if !typeOK[r.Type] {
			add("alerts.rules[%d]: unknown rule type %q (known: %s)", i, r.Type, strings.Join(RuleTypes, ", "))
			continue
		}
		if names[r.Name] {
			add("alerts.rules[%d]: duplicate rule name %q", i, r.Name)
		}
		names[r.Name] = true
		for _, n := range r.Notify {
			if !validNotif[n] {
				add("alerts.rules[%d] (%s): notify channel %q must be webhook or email", i, r.Name, n)
			}
		}
		switch r.Type {
		case "http_failure", "tcp_failure", "dns_failure":
			if r.Consecutive < 1 {
				add("alerts.rules[%d] (%s): consecutive must be >= 1", i, r.Name)
			}
		case "http_latency", "dns_latency":
			if r.Metric != "total" && r.Metric != "ttfb" {
				add("alerts.rules[%d] (%s): metric must be total or ttfb", i, r.Name)
			}
			if r.Multiplier <= 1 {
				add("alerts.rules[%d] (%s): multiplier must be > 1", i, r.Name)
			}
			if r.MinDelta.D() < 0 || r.Sustain.D() <= 0 || r.BaselineWindow.D() <= 0 || r.MinBaseline.D() <= 0 {
				add("alerts.rules[%d] (%s): durations must be positive", i, r.Name)
			}
		case "final_hop_loss":
			if r.ThresholdPct <= 0 || r.ThresholdPct > 100 {
				add("alerts.rules[%d] (%s): threshold_pct must be in (0, 100]", i, r.Name)
			}
			if r.Window.D() <= 0 {
				add("alerts.rules[%d] (%s): window must be positive", i, r.Name)
			}
		case "path_degradation":
			if r.Sustain.D() <= 0 {
				add("alerts.rules[%d] (%s): sustain must be positive", i, r.Name)
			}
		case "cert_expiry":
			if r.WarnBefore.D() <= 0 {
				add("alerts.rules[%d] (%s): warn_before must be positive", i, r.Name)
			}
		}
	}
	mwNames := map[string]bool{}
	for i, w := range a.MaintenanceWindows {
		if w.Name == "" {
			add("alerts.maintenance_windows[%d]: name is required", i)
		}
		if mwNames[w.Name] {
			add("alerts.maintenance_windows[%d]: duplicate name %q", i, w.Name)
		}
		mwNames[w.Name] = true
		if len(w.Days) == 0 {
			add("alerts.maintenance_windows[%d] (%s): days is required", i, w.Name)
		}
		for _, d := range w.Days {
			if _, ok := ParseWeekday(d); !ok {
				add("alerts.maintenance_windows[%d] (%s): invalid day %q (mon..sun)", i, w.Name, d)
			}
		}
		if _, ok := ParseClock(w.Start); !ok {
			add("alerts.maintenance_windows[%d] (%s): start %q must be HH:MM", i, w.Name, w.Start)
		}
		if _, ok := ParseClock(w.End); !ok {
			add("alerts.maintenance_windows[%d] (%s): end %q must be HH:MM", i, w.Name, w.End)
		}
		if w.Timezone != "" {
			if _, err := time.LoadLocation(w.Timezone); err != nil {
				add("alerts.maintenance_windows[%d] (%s): unknown timezone %q", i, w.Name, w.Timezone)
			}
		}
	}
	if a.Heartbeat.URL != "" {
		u, err := url.Parse(a.Heartbeat.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			add("alerts.heartbeat.url must be an http(s) URL")
		}
		if a.Heartbeat.Interval.D() < time.Second {
			add("alerts.heartbeat.interval must be at least 1s")
		}
	}
	if w := a.Notify.Webhook; w != nil {
		switch w.Preset {
		case "discord", "slack", "ntfy", "generic":
		default:
			add("alerts.notify.webhook.preset %q must be discord, slack, ntfy or generic", w.Preset)
		}
		if w.BodyTemplate != "" {
			if _, err := ParseWebhookTemplate(w.BodyTemplate); err != nil {
				add("alerts.notify.webhook.body_template: %v", err)
			}
		}
		for k := range w.Headers {
			if strings.TrimSpace(k) == "" || strings.ContainsAny(k, " \t\r\n:") {
				add("alerts.notify.webhook.headers: invalid header name %q", k)
			}
		}
		if w.URLEnv == "" {
			add("alerts.notify.webhook.url_env is required (webhook URLs are secrets and come from the environment)")
		}
	}
	if e := a.Notify.Email; e != nil {
		switch e.TLS {
		case "starttls", "tls", "none":
		default:
			add("alerts.notify.email.tls %q must be starttls, tls or none", e.TLS)
		}
		if e.SMTPHost == "" || e.From == "" || len(e.To) == 0 {
			add("alerts.notify.email requires smtp_host, from and to")
		}
		if e.SMTPPort < 0 || e.SMTPPort > 65535 {
			add("alerts.notify.email.smtp_port out of range")
		}
	}
	return errs
}

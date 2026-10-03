package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"90s": 90 * time.Second, "5m": 5 * time.Minute, "168h": 168 * time.Hour,
		"7d": 7 * 24 * time.Hour, "1d12h": 36 * time.Hour, "0.5d": 12 * time.Hour, "250ms": 250 * time.Millisecond,
	}
	for in, want := range cases {
		got, err := ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "5x", "d"} {
		if _, err := ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) expected error", bad)
		}
	}
}

func TestMinimalConfigDefaults(t *testing.T) {
	cfg, err := Parse([]byte("targets:\n  - name: a\n    host: 127.0.0.1\n"), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("listen = %q", cfg.Listen)
	}
	ts := cfg.ResolveTargets()
	if len(ts) != 1 || ts[0].ICMP == nil {
		t.Fatalf("targets = %+v", ts)
	}
	if ts[0].ICMP.Interval != 2*time.Second || ts[0].ICMP.MaxHops != 30 || ts[0].ICMP.Rediscovery != 5*time.Minute {
		t.Errorf("icmp defaults = %+v", ts[0].ICMP)
	}
	if cfg.Storage.RawRetention.D() != 7*24*time.Hour || cfg.Storage.Rollup1mRetention.D() != 90*24*time.Hour || cfg.Storage.Rollup1hRetention.D() != 0 {
		t.Errorf("retention defaults wrong: %v %v %v", cfg.Storage.RawRetention.D(), cfg.Storage.Rollup1mRetention.D(), cfg.Storage.Rollup1hRetention.D())
	}
}

const overridesYAML = `
defaults:
  icmp_interval: 3s
  icmp_timeout: 2s
  http_interval: 45s
  tcp_interval: 20s
  max_hops: 20
targets:
  - name: one
    host: example.com
    icmp_interval: 5s
    max_hops: 12
    probes:
      - type: icmp-trace
      - type: http
        url: https://example.com/
        method: head
        expect_status: 200
      - type: http
        url: https://example.com/slow
        interval: 60s
        timeout: 20s
        expect_status: [200, 301]
      - type: tcp
        port: 8443
        interval: 15s
  - name: two
    host: 8.8.8.8
`

func TestOverrides(t *testing.T) {
	cfg, err := Parse([]byte(overridesYAML), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	ts := cfg.ResolveTargets()
	one := ts[0]
	if one.ICMP.Interval != 5*time.Second || one.ICMP.MaxHops != 12 {
		t.Errorf("target-level override not applied: %+v", one.ICMP)
	}
	if one.ICMP.Timeout != 2*time.Second {
		t.Errorf("timeout = %v", one.ICMP.Timeout)
	}
	if len(one.Probes) != 3 {
		t.Fatalf("probes = %d", len(one.Probes))
	}
	if one.Probes[0].Interval != 45*time.Second || one.Probes[0].Method != "HEAD" || len(one.Probes[0].ExpectStatus) != 1 {
		t.Errorf("http defaults: %+v", one.Probes[0])
	}
	if one.Probes[1].Interval != time.Minute || one.Probes[1].Timeout != 20*time.Second || len(one.Probes[1].ExpectStatus) != 2 {
		t.Errorf("probe-level override: %+v", one.Probes[1])
	}
	if one.Probes[2].Interval != 15*time.Second || one.Probes[2].Port != 8443 {
		t.Errorf("tcp: %+v", one.Probes[2])
	}
	if !one.Probes[0].PinIP {
		t.Error("pin_ip should default true")
	}
	two := ts[1]
	if two.ICMP == nil || two.ICMP.Interval != 3*time.Second || two.ICMP.MaxHops != 20 {
		t.Errorf("inherits defaults: %+v", two.ICMP)
	}
}

func TestTimeoutClampedToInterval(t *testing.T) {
	cfg, err := Parse([]byte("defaults:\n  icmp_interval: 1s\n  icmp_timeout: 5s\ntargets:\n  - name: a\n    host: 1.1.1.1\n"), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ResolveTargets()[0].ICMP.Timeout; got != time.Second {
		t.Errorf("timeout = %v, want clamped to 1s", got)
	}
}

func TestStrictAndValidation(t *testing.T) {
	bad := map[string]string{
		"unknown key":       "bogus: 1\n",
		"unknown nested":    "targets:\n  - name: a\n    host: 1.1.1.1\n    hots: x\n",
		"dup names":         "targets:\n  - name: a\n    host: 1.1.1.1\n  - name: A\n    host: 8.8.8.8\n",
		"bad host":          "targets:\n  - name: a\n    host: http://x.com\n",
		"bad probe type":    "targets:\n  - name: a\n    host: 1.1.1.1\n    probes:\n      - type: udp\n",
		"bad url":           "targets:\n  - name: a\n    host: 1.1.1.1\n    probes:\n      - type: http\n        url: ftp://x\n",
		"bad method":        "targets:\n  - name: a\n    host: 1.1.1.1\n    probes:\n      - type: http\n        url: http://x/\n        method: POST\n",
		"bad status":        "targets:\n  - name: a\n    host: 1.1.1.1\n    probes:\n      - type: http\n        url: http://x/\n        expect_status: 99\n",
		"bad port":          "targets:\n  - name: a\n    host: 1.1.1.1\n    probes:\n      - type: tcp\n        port: 70000\n",
		"bad duration":      "defaults:\n  icmp_interval: soon\n",
		"tiny interval":     "defaults:\n  icmp_interval: 100ms\ntargets:\n  - name: a\n    host: 1.1.1.1\n",
		"bad listen":        "listen: nonsense\n",
		"bad log level":     "log:\n  level: loud\n",
		"tls half":          "tls:\n  cert_file: a.pem\n",
		"icmp mode":         "probing:\n  icmp_mode: magic\n",
		"unknown rule type": "alerts:\n  rules:\n    - name: x\n      type: nope\n",
		"dup rule":          "alerts:\n  rules:\n    - name: x\n      type: http_failure\n    - name: x\n      type: tcp_failure\n",
		"bad notify chan":   "alerts:\n  rules:\n    - name: x\n      type: http_failure\n      notify: [pager]\n",
		"bad maint day":     "alerts:\n  maintenance_windows:\n    - name: m\n      days: [xyz]\n      start: \"01:00\"\n      end: \"02:00\"\n",
		"bad maint tz":      "alerts:\n  maintenance_windows:\n    - name: m\n      days: [mon]\n      start: \"01:00\"\n      end: \"02:00\"\n      timezone: Mars/Base\n",
		"dns probe no serv": "dns_probes:\n  - name: d\n    query: example.com\n",
		"dns bad record":    "dns_probes:\n  - name: d\n    server: 1.1.1.1\n    query: example.com\n    record: MX\n",
		"disable unknown":   "targets:\n  - name: a\n    host: 1.1.1.1\n    alerts:\n      disable: [nonexistent]\n",
		"webhook no env":    "alerts:\n  notify:\n    webhook:\n      preset: slack\n",
		"clear ratio":       "alerts:\n  clear_ratio: 1.5\n",
		"two icmp":          "targets:\n  - name: a\n    host: 1.1.1.1\n    probes:\n      - type: icmp-trace\n      - type: icmp-trace\n",
		"dup http probe":    "targets:\n  - name: a\n    host: 1.1.1.1\n    probes:\n      - type: http\n        url: http://x/\n      - type: http\n        url: http://x/\n",
	}
	for name, y := range bad {
		if _, err := Parse([]byte(y), env(nil)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestAlertsSectionAndTargetAlerts(t *testing.T) {
	y := `
targets:
  - name: dns-google
    host: 8.8.8.8
    alerts:
      disable: [route_change]
      override:
        end-loss: { threshold_pct: 10 }
alerts:
  rules:
    - name: end-loss
      type: final_hop_loss
      threshold_pct: 5
      window: 5m
    - name: route
      type: route_change
      enabled: false
      notify: [webhook]
  maintenance_windows:
    - name: isp-nightly
      days: [mon, tue]
      start: "03:00"
      end: "04:00"
      timezone: America/New_York
  notify:
    webhook:
      url_env: HOOK
      preset: ntfy
`
	cfg, err := Parse([]byte(y), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Alerts.Rules) != 2 || cfg.Alerts.Rules[1].IsEnabled() {
		t.Errorf("rules: %+v", cfg.Alerts.Rules)
	}
	ov := cfg.Targets[0].Alerts.Override["end-loss"]
	if r := ov.Apply(cfg.Alerts.Rules[0]); r.ThresholdPct != 10 || r.Window.D() != 5*time.Minute {
		t.Errorf("override apply: %+v", r)
	}
	if cfg.Alerts.Cooldown.D() != 30*time.Minute || cfg.Alerts.ClearRatio != 0.7 {
		t.Errorf("alert defaults: %+v", cfg.Alerts)
	}
}

func TestEnvOverrides(t *testing.T) {
	cfg, err := Parse([]byte("listen: 127.0.0.1:8080\nstorage:\n  path: a.db\n"), env(map[string]string{
		EnvListen: "0.0.0.0:8095", EnvDB: "/data/x.db",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "0.0.0.0:8095" || cfg.Storage.Path != "/data/x.db" {
		t.Errorf("env override: listen=%q db=%q", cfg.Listen, cfg.Storage.Path)
	}
	// invalid override is still validated
	if _, err := Parse(nil, env(map[string]string{EnvListen: "garbage"})); err == nil {
		t.Error("expected invalid PATHWATCH_LISTEN error")
	}
}

func TestLoadFirstRunAndRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "pathwatch.yaml")
	if _, err := Load(path, LoadOptions{Getenv: env(nil)}); err == nil {
		t.Fatal("expected error without CreateIfMissing")
	}
	cfg, err := Load(path, LoadOptions{CreateIfMissing: true, Getenv: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Created {
		t.Error("Created should be true")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("starter config not written")
	}
	if want := filepath.Join(dir, "sub", "pathwatch.db"); cfg.Storage.Path != want {
		t.Errorf("db path = %q, want %q", cfg.Storage.Path, want)
	}
	if n := len(cfg.ResolveTargets()); n != 3 {
		t.Errorf("starter targets = %d, want 3", n)
	}
	cfg2, err := Load(path, LoadOptions{Getenv: env(nil)})
	if err != nil || cfg2.Created {
		t.Fatalf("second load: %v created=%v", err, cfg2 != nil && cfg2.Created)
	}
	// env DB path is not rewritten relative to the config dir
	cfg3, err := Load(path, LoadOptions{Getenv: env(map[string]string{EnvDB: "/tmp/x.db"})})
	if err != nil || cfg3.Storage.Path != "/tmp/x.db" {
		t.Fatalf("env db: %v %q", err, cfg3.Storage.Path)
	}
}

func TestResolveAuth(t *testing.T) {
	dir := t.TempDir()
	mk := func(listen string, e map[string]string) (Auth, error) {
		cfg, err := Parse([]byte("listen: "+listen+"\nstorage:\n  path: "+filepath.Join(dir, "p.db")+"\n"), env(e))
		if err != nil {
			t.Fatal(err)
		}
		return cfg.ResolveAuth(env(e))
	}
	a, err := mk("127.0.0.1:8080", nil)
	if err != nil || a.Enabled {
		t.Errorf("loopback without password: %+v %v", a, err)
	}
	a, _ = mk("127.0.0.1:8080", map[string]string{EnvPassword: "pw"})
	if !a.Enabled || a.User != "admin" || a.Password != "pw" {
		t.Errorf("loopback with password: %+v", a)
	}
	a, _ = mk("0.0.0.0:8095", map[string]string{EnvPassword: "pw", EnvUser: "bob"})
	if !a.Enabled || a.User != "bob" || a.Generated {
		t.Errorf("explicit creds: %+v", a)
	}
	a, err = mk("0.0.0.0:8095", nil)
	if err != nil || !a.Enabled || !a.Generated || len(a.Password) < 16 {
		t.Fatalf("generated: %+v %v", a, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, PasswordFile))
	if err != nil || strings.TrimSpace(string(b)) != a.Password {
		t.Errorf("password file: %q %v", b, err)
	}
	st, _ := os.Stat(filepath.Join(dir, PasswordFile))
	if st.Mode().Perm() != 0o600 {
		t.Errorf("password file mode %v", st.Mode().Perm())
	}
	a2, _ := mk("0.0.0.0:8095", nil)
	if a2.Generated || a2.Password != a.Password {
		t.Errorf("second start should reuse the file: %+v", a2)
	}
}

func TestLoopback(t *testing.T) {
	for l, want := range map[string]bool{
		"127.0.0.1:8080": true, "localhost:80": true, "[::1]:80": true,
		"0.0.0.0:80": false, ":80": false, "192.168.1.5:80": false, "[::]:80": false,
	} {
		if IsLoopbackListen(l) != want {
			t.Errorf("IsLoopbackListen(%q) != %v", l, want)
		}
	}
}

func TestNewUITarget(t *testing.T) {
	cfg, _ := Parse(nil, env(nil))
	tg, err := NewUITarget(UITargetRequest{Name: "my-isp", Host: "example.com", ICMPIntervalMS: 2500, HTTPURL: "https://example.com/", TCPPort: 443}, cfg.Defaults)
	if err != nil {
		t.Fatal(err)
	}
	if tg.Source != SourceUI || tg.ICMP.Interval != 2500*time.Millisecond || len(tg.Probes) != 2 {
		t.Errorf("%+v", tg)
	}
	for _, bad := range []UITargetRequest{
		{Name: "", Host: "x.com"}, {Name: "a", Host: ""}, {Name: "a", Host: "a b"},
		{Name: "a", Host: "x.com", HTTPURL: "nope"}, {Name: "a", Host: "x.com", TCPPort: 99999},
		{Name: "a", Host: "x.com", ICMPIntervalMS: 10},
	} {
		if _, err := NewUITarget(bad, cfg.Defaults); err == nil {
			t.Errorf("expected error for %+v", bad)
		}
	}
}

func TestProbeKeysAndLabels(t *testing.T) {
	p := Probe{Type: ProbeHTTP, Method: "HEAD", URL: "https://x/"}
	if p.Label() != "HEAD https://x/" || p.Key() != "http|HEAD|https://x/" {
		t.Errorf("%q %q", p.Label(), p.Key())
	}
	if (Probe{Type: ProbeTCP, Port: 443}).Label() != "TCP :443" {
		t.Error("tcp label")
	}
}

func TestStarterConfigAlertsSection(t *testing.T) {
	cfg, err := Parse([]byte(StarterConfig), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	var route *RuleConfig
	for i := range cfg.Alerts.Rules {
		if cfg.Alerts.Rules[i].Type == "route_change" {
			route = &cfg.Alerts.Rules[i]
		}
	}
	if route == nil || route.IsEnabled() {
		t.Fatalf("starter config should list route_change disabled: %+v", route)
	}
	// the commented webhook example becomes valid when uncommented
	yaml := strings.Replace(StarterConfig, "  # notify:\n  #   webhook:\n  #     url_env: PATHWATCH_WEBHOOK_URL   # export PATHWATCH_WEBHOOK_URL=https://...\n  #     preset: generic                  # generic | discord | slack | ntfy\n",
		"  notify:\n    webhook:\n      url_env: PATHWATCH_WEBHOOK_URL\n      preset: generic\n", 1)
	if yaml == StarterConfig {
		t.Fatal("the starter config no longer contains the commented webhook example")
	}
	cfg, err = Parse([]byte(yaml), env(nil))
	if err != nil {
		t.Fatalf("uncommented webhook example: %v", err)
	}
	if cfg.Alerts.Notify.Webhook == nil || cfg.Alerts.Notify.Webhook.Preset != "generic" || cfg.Alerts.Notify.Webhook.URLEnv != "PATHWATCH_WEBHOOK_URL" {
		t.Fatalf("webhook not parsed: %+v", cfg.Alerts.Notify.Webhook)
	}
	for _, preset := range []string{"discord", "slack", "ntfy"} {
		if !strings.Contains(StarterConfig, preset) {
			t.Errorf("starter config does not mention the %s preset", preset)
		}
	}
}

func TestWebhookBodyTemplateAndHeadersValidated(t *testing.T) {
	base := "alerts:\n  notify:\n    webhook:\n      url_env: HOOK\n"
	if _, err := Parse([]byte(base+"      body_template: '{{.Title}} {{json .Message}}'\n      headers: {X-Token: \"${TOKEN}\"}\n"), env(nil)); err != nil {
		t.Fatalf("valid template rejected: %v", err)
	}
	if _, err := Parse([]byte(base+"      body_template: '{{.Title'\n"), env(nil)); err == nil || !strings.Contains(err.Error(), "body_template") {
		t.Fatalf("broken template accepted: %v", err)
	}
	if _, err := Parse([]byte(base+"      body_template: '{{nosuchfunc .X}}'\n"), env(nil)); err == nil {
		t.Fatal("unknown template function accepted")
	}
	if _, err := Parse([]byte(base+"      headers: {\"Bad Header\": x}\n"), env(nil)); err == nil || !strings.Contains(err.Error(), "header name") {
		t.Fatalf("bad header name accepted: %v", err)
	}
}

package config

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	ok := map[string]string{
		"example.com":                   "example.com",
		"Example.COM.":                  "example.com.",
		"  nas  ":                       "nas",
		"router.lan":                    "router.lan",
		"_srv.example.org":              "_srv.example.org",
		"1.1.1.1":                       "1.1.1.1",
		"::ffff:10.0.0.1":               "10.0.0.1",
		"2001:DB8::1":                   "2001:db8::1",
		"[2001:db8::1]":                 "2001:db8::1",
		"fe80::1%eth0":                  "fe80::1%eth0",
		"a-b.c-d.example":               "a-b.c-d.example",
		"xn--bcher-kva.example":         "xn--bcher-kva.example",
		"3com.example":                  "3com.example",
		strings.Repeat("a", 63) + ".io": strings.Repeat("a", 63) + ".io",
	}
	for in, want := range ok {
		got, err := NormalizeHost(in)
		if err != nil || got != want {
			t.Errorf("NormalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := map[string]string{
		"":                              "required",
		"https://example.com/":          "without \"https://\"",
		"example.com:443":               "remove the port",
		"example.com/path":              "without a path",
		"300.1.1.1":                     "invalid IPv4",
		"10.0.0":                        "invalid IPv4",
		"exa mple.com":                  "spaces",
		"a..b":                          "empty label",
		"-bad.example":                  "may only contain",
		"[not-an-ip]":                   "invalid IPv6",
		"2001:db8::zz":                  "invalid IPv6",
		strings.Repeat("a", 64) + ".io": "may only contain",
	}
	for in, frag := range bad {
		_, err := NormalizeHost(in)
		if err == nil || !strings.Contains(err.Error(), frag) {
			t.Errorf("NormalizeHost(%q) error = %v; want it to mention %q", in, err, frag)
		}
	}
	for in, want := range map[string]string{"1.2.3.4": HostIPv4, "2001:db8::1": HostIPv6, "[::1]": HostIPv6, "example.com.": HostHostname} {
		if got := HostKind(in); got != want {
			t.Errorf("HostKind(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveTargetNormalizesHost(t *testing.T) {
	d := mustDefaults(t)
	tg, err := ResolveTarget(TargetConfig{Name: "v6", Host: "[2001:DB8::1]"}, d)
	if err != nil || tg.Host != "2001:db8::1" {
		t.Fatalf("got %q, %v", tg.Host, err)
	}
	if _, err := ResolveTarget(TargetConfig{Name: "x", Host: "http://example.com"}, d); err == nil {
		t.Fatal("a URL is not a host")
	}
}

func mustDefaults(t *testing.T) Defaults {
	t.Helper()
	cfg, err := Parse(nil, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Defaults
}

func intp(v int) *int { return &v }

func TestRetriesInheritance(t *testing.T) {
	cfg, err := Parse([]byte(`
defaults:
  retries: 2
targets:
  - name: a
    host: example.com
    probes:
      - type: http
        url: https://example.com/
      - type: tcp
        port: 443
        retries: 0
  - name: b
    host: example.com
    retries: 1
    probes:
      - type: tcp
dns_probes:
  - name: r
    server: 192.168.1.1
    query: example.com
`), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	ts := cfg.ResolveTargets()
	if ts[0].Probes[0].Retries != 2 || ts[0].Probes[1].Retries != 0 {
		t.Errorf("target a retries: %d, %d", ts[0].Probes[0].Retries, ts[0].Probes[1].Retries)
	}
	if ts[1].Probes[0].Retries != 1 {
		t.Errorf("target b retries: %d", ts[1].Probes[0].Retries)
	}
	if d := cfg.ResolveDNSProbes(); d[0].Retries != 2 {
		t.Errorf("dns retries: %d", d[0].Retries)
	}
	for _, y := range []string{"defaults:\n  retries: 11\n", "targets:\n  - name: a\n    host: a.example\n    retries: -1\n"} {
		if _, err := Parse([]byte(y), env(nil)); err == nil || !strings.Contains(err.Error(), "retries") {
			t.Errorf("%q: want a retries error, got %v", y, err)
		}
	}
}

func TestDurationJSON(t *testing.T) {
	var v struct {
		A Duration `json:"a"`
		B Duration `json:"b"`
		C Duration `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a": 1500, "b": "2m", "c": null}`), &v); err != nil {
		t.Fatal(err)
	}
	if v.A.D() != 1500*time.Millisecond || v.B.D() != 2*time.Minute || v.C != 0 {
		t.Fatalf("got %+v", v)
	}
	b, _ := json.Marshal(v)
	if string(b) != `{"a":1500,"b":120000,"c":0}` {
		t.Fatalf("marshal: %s", b)
	}
	for _, bad := range []string{`{"a": -1}`, `{"a": "nope"}`, `{"a": true}`} {
		if err := json.Unmarshal([]byte(bad), &v); err == nil {
			t.Errorf("%s: expected error", bad)
		}
	}
}

func TestWithOverrides(t *testing.T) {
	file, err := Parse([]byte(`
defaults:
  icmp_interval: 2s
targets:
  - name: Alpha
    host: alpha.example
alerts:
  rules:
    - name: end-loss
      type: final_hop_loss
      threshold_pct: 5
`), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	ov := Overrides{
		Defaults: &Defaults{ICMPInterval: Duration(5 * time.Second), Retries: 1},
		Status:   &StatusConfig{DegradedLossPct: 2},
		Alerts:   &AlertSettings{Rules: []RuleConfig{{Name: "loss", Type: "final_hop_loss", ThresholdPct: 1}}},
	}
	edited := map[string]TargetConfig{"alpha": {Name: "ignored", Host: "192.0.2.1"}}
	ui := []TargetConfig{{Name: "ui", Host: "ui.example", Alerts: TargetAlerts{Disable: []string{"loss"}}}}
	eff, err := file.WithOverrides(ov, edited, ui)
	if err != nil {
		t.Fatal(err)
	}
	if eff.Defaults.ICMPInterval.D() != 5*time.Second || eff.Defaults.MaxHops != 30 || eff.Defaults.Retries != 1 {
		t.Errorf("defaults not applied/filled: %+v", eff.Defaults)
	}
	if eff.Status.DegradedLossPct != 2 || eff.Status.DegradedHTTPSuccessPct != 95 {
		t.Errorf("status: %+v", eff.Status)
	}
	if len(eff.Alerts.Rules) != 1 || eff.Alerts.Rules[0].Window.D() != 5*time.Minute || eff.Alerts.Cooldown.D() != 30*time.Minute {
		t.Errorf("alerts: %+v", eff.Alerts)
	}
	if eff.Targets[0].Name != "Alpha" || eff.Targets[0].Host != "192.0.2.1" {
		t.Errorf("edited target: %+v", eff.Targets[0])
	}
	if file.Targets[0].Host != "alpha.example" || file.Alerts.Rules[0].Name != "end-loss" || file.Defaults.ICMPInterval.D() != 2*time.Second {
		t.Error("the file config was modified")
	}
	// a UI target that references a rule the overrides removed is an error
	ui[0].Alerts.Disable = []string{"end-loss"}
	if _, err := file.WithOverrides(ov, nil, ui); err == nil || !strings.Contains(err.Error(), "end-loss") {
		t.Errorf("want unknown rule error, got %v", err)
	}
	if _, err := file.WithOverrides(Overrides{Status: &StatusConfig{DegradedLossPct: 150}}, nil, nil); err == nil {
		t.Error("loss threshold above 100 accepted")
	}
}

func TestNormalizeTarget(t *testing.T) {
	rules := []RuleConfig{{Name: "end-loss", Type: "final_hop_loss"}, {Name: "slow", Type: "http_latency"}, {Name: "slow2", Type: "http_latency"}}
	ten, five := 10.0, 5
	tc := TargetConfig{
		Name: "t", Host: "h.example", ICMPInterval: Duration(5 * time.Second), HTTPInterval: Duration(time.Minute), Retries: intp(2),
		Probes: []ProbeConfig{{Type: ProbeICMPTrace}, {Type: ProbeHTTP, URL: "https://h.example/"}, {Type: ProbeTCP, Port: 22, Retries: intp(0)}},
		Alerts: TargetAlerts{
			Disable:  []string{"http_latency"},
			Override: map[string]RuleOverride{"final_hop_loss": {ThresholdPct: &ten}, "end-loss": {Consecutive: &five}},
		},
	}
	n := NormalizeTarget(tc, rules)
	d := mustDefaults(t)
	a, err1 := ResolveTarget(tc, d)
	b, err2 := ResolveTarget(NormalizeTarget(tc, rules), d)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if a.Host != b.Host || len(b.Probes) != 2 || *a.ICMP != *b.ICMP || a.Probes[0].Interval != b.Probes[0].Interval || a.Probes[0].Retries != 2 || b.Probes[0].Retries != 2 || b.Probes[1].Retries != 0 {
		t.Fatalf("meaning changed:\n%+v\n%+v", a, b)
	}
	if n.ICMPInterval != 0 || n.HTTPInterval != 0 || n.Retries != nil || n.Probes[0].Interval.D() != 5*time.Second || n.Probes[1].Interval.D() != time.Minute {
		t.Errorf("target-level settings not moved: %+v", n)
	}
	if strings.Join(n.Alerts.Disable, ",") != "slow,slow2" {
		t.Errorf("disable: %v", n.Alerts.Disable)
	}
	o := n.Alerts.Override["end-loss"]
	if o.ThresholdPct == nil || *o.ThresholdPct != 10 || o.Consecutive == nil || *o.Consecutive != 5 || len(n.Alerts.Override) != 1 {
		t.Errorf("override: %+v", n.Alerts.Override)
	}
	if tc.ICMPInterval == 0 || tc.Alerts.Disable[0] != "http_latency" {
		t.Error("input modified")
	}
}

func TestTargetConfigFromResolved(t *testing.T) {
	d := mustDefaults(t)
	legacy, err := NewUITarget(UITargetRequest{Name: "old", Host: "example.com", ICMPIntervalMS: 5000, HTTPURL: "https://example.com/", TCPPort: 22}, d)
	if err != nil {
		t.Fatal(err)
	}
	tc := TargetConfigFromResolved(legacy, d)
	if tc.Probes[0].Type != ProbeICMPTrace || tc.Probes[0].Interval.D() != 5*time.Second || tc.Probes[1].Interval != 0 || tc.Probes[2].Port != 22 {
		t.Fatalf("got %+v", tc)
	}
	again, err := ResolveUITarget(tc, d)
	if err != nil {
		t.Fatal(err)
	}
	if *again.ICMP != *legacy.ICMP || again.Probes[0].Key() != legacy.Probes[0].Key() || again.Probes[1].Key() != legacy.Probes[1].Key() {
		t.Fatalf("round trip changed the target:\n%+v\n%+v", legacy, again)
	}
}

func TestResolveUITargetBounds(t *testing.T) {
	d := mustDefaults(t)
	if _, err := ResolveUITarget(TargetConfig{Name: "x", Host: "x.example", Probes: []ProbeConfig{{Type: ProbeICMPTrace, Interval: Duration(48 * time.Hour)}}}, d); err == nil {
		t.Error("48h interval accepted")
	}
	tg, err := ResolveUITarget(TargetConfig{Name: " x ", Host: " X.example "}, d)
	if err != nil || tg.Name != "x" || tg.Host != "x.example" || tg.Source != SourceUI {
		t.Errorf("got %+v, %v", tg, err)
	}
}

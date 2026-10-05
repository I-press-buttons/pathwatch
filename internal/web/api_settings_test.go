package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func TestEditTargetAPI(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	// full definition
	resp, b := f.postJSON("/api/targets", map[string]any{
		"name": "edge", "host": "[2001:DB8::1]",
		"probes": []map[string]any{
			{"type": "icmp-trace", "interval_ms": 1000, "timeout_ms": 800},
			{"type": "tcp", "port": 443, "interval_ms": 5000, "timeout_ms": 1000, "retries": 2},
		},
	})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var tj map[string]any
	_ = json.Unmarshal(b, &tj)
	if tj["host"] != "2001:db8::1" || tj["host_kind"] != "ipv6" || tj["icmp_interval_ms"] != 1000.0 {
		t.Fatalf("created: %s", b)
	}
	id := itoa(int64(tj["id"].(float64)))

	// unknown fields are refused, as are both forms at once
	if resp, b := f.postJSON("/api/targets", map[string]any{"name": "x", "host": "x.example", "intervall_ms": 5}); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "intervall_ms") {
		t.Errorf("unknown field: %d %s", resp.StatusCode, b)
	}
	if resp, _ := f.postJSON("/api/targets", map[string]any{"name": "x", "host": "x.example", "tcp_port": 22, "probes": []any{}}); resp.StatusCode != 400 {
		t.Errorf("mixed forms: %d", resp.StatusCode)
	}
	if resp, b := f.postJSON("/api/targets", map[string]any{"name": "x", "host": "https://x.example/"}); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "without") {
		t.Errorf("URL host: %d %s", resp.StatusCode, b)
	}

	var cfg struct {
		Source     string         `json:"source"`
		Overridden bool           `json:"overridden"`
		Target     map[string]any `json:"target"`
	}
	if resp := f.getJSON("/api/targets/"+id+"/config", &cfg); resp.StatusCode != 200 || cfg.Source != "ui" || cfg.Overridden {
		t.Fatalf("config: %d %+v", resp.StatusCode, cfg)
	}
	probes := cfg.Target["probes"].([]any)
	if len(probes) != 2 || probes[1].(map[string]any)["retries"] != 2.0 {
		t.Fatalf("probes: %+v", probes)
	}

	// edit: rename, change host, timeout and retries
	cfg.Target["name"] = "edge-2"
	cfg.Target["host"] = "pathwatch.test"
	probes[1].(map[string]any)["retries"] = 0
	probes[1].(map[string]any)["timeout_ms"] = 2000
	resp, b = f.do("PUT", "/api/targets/"+id, "application/json", cfg.Target)
	if resp.StatusCode != 200 {
		t.Fatalf("update: %d %s", resp.StatusCode, b)
	}
	_ = json.Unmarshal(b, &tj)
	if tj["name"] != "edge-2" || tj["host_kind"] != "hostname" {
		t.Errorf("updated: %s", b)
	}
	st, _ := f.sched.State(int64(tj["id"].(float64)))
	if st.Spec.Probes[0].Retries != 0 || st.Spec.Probes[0].Timeout.Milliseconds() != 2000 {
		t.Errorf("running spec: %+v", st.Spec.Probes[0])
	}
	cfg.Target["host"] = "300.1.1.1"
	if resp, b := f.do("PUT", "/api/targets/"+id, "application/json", cfg.Target); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "IPv4") {
		t.Errorf("bad host: %d %s", resp.StatusCode, b)
	}
	if resp, _ := f.do("PUT", "/api/targets/99999", "application/json", cfg.Target); resp.StatusCode != 404 {
		t.Errorf("missing target: %d", resp.StatusCode)
	}
	if resp, _ := f.do("DELETE", "/api/targets/"+id+"/override", "", nil); resp.StatusCode != 409 {
		t.Errorf("revert of a UI target: %d", resp.StatusCode)
	}
	if resp, _ := f.do("PUT", "/api/targets/"+id, "text/plain", "{}"); resp.StatusCode != 415 {
		t.Errorf("content type: %d", resp.StatusCode)
	}
}

func TestSettingsAPI(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	var s struct {
		Defaults   sectionJSONT `json:"defaults"`
		Status     sectionJSONT `json:"status"`
		Alerts     sectionJSONT `json:"alerts"`
		DNSProbes  sectionJSONT `json:"dns_probes"`
		RuleTypes  []string     `json:"rule_types"`
		MaxRetries int          `json:"max_retries"`
	}
	f.getJSON("/api/settings", &s)
	if s.Defaults.Source != "file" || s.Defaults.Value["icmp_interval_ms"] != 2000.0 || s.MaxRetries != 10 || len(s.RuleTypes) == 0 {
		t.Fatalf("settings: %+v", s)
	}

	d := s.Defaults.Value
	d["retries"] = 3
	d["http_timeout_ms"] = 4000
	resp, b := f.do("PUT", "/api/settings/defaults", "application/json", d)
	if resp.StatusCode != 200 {
		t.Fatalf("put defaults: %d %s", resp.StatusCode, b)
	}
	_ = json.Unmarshal(b, &s)
	if s.Defaults.Source != "ui" || s.Defaults.Value["retries"] != 3.0 || s.Defaults.File["retries"] != 0.0 {
		t.Errorf("after put: %+v", s.Defaults)
	}
	d["retries"] = 99
	if resp, b := f.do("PUT", "/api/settings/defaults", "application/json", d); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "retries") {
		t.Errorf("bad retries: %d %s", resp.StatusCode, b)
	}
	if resp, _ := f.do("PUT", "/api/settings/defaults", "application/json", map[string]any{"icmp_intervall_ms": 1}); resp.StatusCode != 400 {
		t.Errorf("unknown field: %d", resp.StatusCode)
	}

	if resp, b := f.do("PUT", "/api/settings/status", "application/json", map[string]any{"degraded_loss_pct": 2, "degraded_http_success_pct": 99}); resp.StatusCode != 200 {
		t.Fatalf("status: %d %s", resp.StatusCode, b)
	}
	var st map[string]any
	f.getJSON("/api/status", &st)
	if th := st["status_thresholds"].(map[string]any); th["degraded_loss_pct"] != 2.0 {
		t.Errorf("status thresholds: %+v", th)
	}

	rules := []map[string]any{{"name": "loss", "type": "final_hop_loss", "threshold_pct": 1.5, "window_ms": 120000}}
	resp, b = f.do("PUT", "/api/settings/alerts", "application/json", map[string]any{"rules": rules, "cooldown_ms": 600000, "clear_ratio": 0.5})
	if resp.StatusCode != 200 {
		t.Fatalf("alerts: %d %s", resp.StatusCode, b)
	}
	_ = json.Unmarshal(b, &s)
	r0 := s.Alerts.Value["rules"].([]any)[0].(map[string]any)
	if r0["threshold_pct"] != 1.5 || s.Alerts.Value["cooldown_ms"] != 600000.0 {
		t.Errorf("alerts value: %+v", s.Alerts.Value)
	}
	rules[0]["type"] = "nonsense"
	if resp, b := f.do("PUT", "/api/settings/alerts", "application/json", map[string]any{"rules": rules, "clear_ratio": 0.5}); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "nonsense") {
		t.Errorf("bad rule: %d %s", resp.StatusCode, b)
	}

	dns := []map[string]any{{"name": "pihole", "server": "192.0.2.53", "query": "example.com", "retries": 1}}
	if resp, b := f.do("PUT", "/api/settings/dns_probes", "application/json", dns); resp.StatusCode != 200 {
		t.Fatalf("dns: %d %s", resp.StatusCode, b)
	}
	if ds := f.sched.DNSStates(); len(ds) != 1 || ds[0].Spec.Retries != 1 {
		t.Errorf("dns running: %+v", ds)
	}

	for _, sec := range []string{"defaults", "status", "alerts", "dns_probes"} {
		if resp, _ := f.do("DELETE", "/api/settings/"+sec, "", nil); resp.StatusCode != 200 {
			t.Errorf("revert %s: %d", sec, resp.StatusCode)
		}
	}
	f.getJSON("/api/settings", &s)
	if s.Defaults.Source != "file" || s.Alerts.Source != "file" || s.Status.Source != "file" || s.DNSProbes.Source != "file" {
		t.Errorf("after revert: %+v", s)
	}
	if resp, _ := f.do("PUT", "/api/settings/nope", "application/json", map[string]any{}); resp.StatusCode != 404 {
		t.Errorf("unknown section: %d", resp.StatusCode)
	}
}

type sectionJSONT struct {
	Source string          `json:"source"`
	Value  map[string]any  `json:"-"`
	File   map[string]any  `json:"-"`
	RawV   json.RawMessage `json:"value"`
	RawF   json.RawMessage `json:"file"`
}

func (s *sectionJSONT) UnmarshalJSON(b []byte) error {
	type plain sectionJSONT
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*s = sectionJSONT(p)
	_ = json.Unmarshal(s.RawV, &s.Value) // objects only; lists stay raw
	_ = json.Unmarshal(s.RawF, &s.File)
	return nil
}

func TestResolveAPI(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	var r map[string]any
	f.getJSON("/api/resolve?host=PathWatch.test", &r)
	if r["valid"] != true || r["kind"] != "hostname" || len(r["addresses"].([]any)) != 2 {
		t.Errorf("fqdn: %+v", r)
	}
	f.getJSON("/api/resolve?host=missing.test", &r)
	if r["resolve_error"] != "no such host" {
		t.Errorf("missing: %+v", r)
	}
	f.getJSON("/api/resolve?host=192.0.2.1", &r)
	if r["kind"] != "ipv4" || r["addresses"].([]any)[0] != "192.0.2.1" {
		t.Errorf("ip: %+v", r)
	}
	r = nil
	f.getJSON("/api/resolve?host=example.com:443", &r)
	if r["valid"] != false || !strings.Contains(r["error"].(string), "port") {
		t.Errorf("port: %+v", r)
	}
}

func TestLimitsAPI(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	tcp := func(n int) []map[string]any {
		ps := make([]map[string]any, n)
		for i := range ps {
			ps[i] = map[string]any{"type": "tcp", "port": 1000 + i}
		}
		return ps
	}
	// probes per target
	if resp, b := f.postJSON("/api/targets", map[string]any{"name": "big", "host": "x.example", "probes": tcp(config.MaxProbesPerTarget + 1)}); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "too many probes") {
		t.Errorf("too many probes: %d %s", resp.StatusCode, b)
	}
	resp, b := f.postJSON("/api/targets", map[string]any{"name": "ok", "host": "x.example", "probes": tcp(config.MaxProbesPerTarget)})
	if resp.StatusCode != 201 {
		t.Fatalf("probes at the cap: %d %s", resp.StatusCode, b)
	}
	var tj map[string]any
	_ = json.Unmarshal(b, &tj)
	id := itoa(int64(tj["id"].(float64)))
	if resp, b := f.do("PUT", "/api/targets/"+id, "application/json", map[string]any{"name": "ok", "host": "x.example", "probes": tcp(config.MaxProbesPerTarget + 1)}); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "too many probes") {
		t.Errorf("update past the cap: %d %s", resp.StatusCode, b)
	}

	// DNS probes
	dns := func(n int) []map[string]any {
		l := make([]map[string]any, n)
		for i := range l {
			l[i] = map[string]any{"name": "p" + itoa(int64(i)), "server": "192.0.2.53", "query": "example.com", "record": "A"}
		}
		return l
	}
	if resp, b := f.do("PUT", "/api/settings/dns_probes", "application/json", dns(config.MaxDNSProbes+1)); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "too many DNS probes") {
		t.Errorf("dns over the cap: %d %s", resp.StatusCode, b)
	}
	if resp, b := f.do("PUT", "/api/settings/dns_probes", "application/json", dns(config.MaxDNSProbes)); resp.StatusCode != 200 {
		t.Errorf("dns at the cap: %d %s", resp.StatusCode, b)
	}

	// total targets
	for i := 1; i < config.MaxTargets; i++ { // "ok" is the first
		if resp, b := f.postJSON("/api/targets", map[string]any{"name": "t" + itoa(int64(i)), "host": "x.example"}); resp.StatusCode != 201 {
			t.Fatalf("target %d: %d %s", i, resp.StatusCode, b)
		}
	}
	if resp, b := f.postJSON("/api/targets", map[string]any{"name": "last", "host": "x.example"}); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "too many targets") {
		t.Errorf("target over the cap: %d %s", resp.StatusCode, b)
	}
}

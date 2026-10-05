package web

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProbeHeaderSecretsAPI(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	resp, b := f.postJSON("/api/targets", map[string]any{
		"name": "api", "host": "api.example",
		"probes": []map[string]any{{
			"type": "http", "url": "http://user:pw123@api.example/health",
			"headers": map[string]string{"X-Api-Key": "s3cret", "X-Token": "${PATHWATCH_PROBE_TOKEN}"},
		}},
	})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	if strings.Contains(string(b), "pw123") {
		t.Errorf("userinfo password in the target response: %s", b)
	}
	var tj map[string]any
	_ = json.Unmarshal(b, &tj)
	idn := int64(tj["id"].(float64))
	id := itoa(idn)

	var cfg struct {
		Target map[string]any `json:"target"`
	}
	resp, raw := f.do("GET", "/api/targets/"+id+"/config", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("config: %d %s", resp.StatusCode, raw)
	}
	if strings.Contains(string(raw), "s3cret") || !strings.Contains(string(raw), "********") || !strings.Contains(string(raw), "${PATHWATCH_PROBE_TOKEN}") {
		t.Fatalf("headers not redacted correctly: %s", raw)
	}
	_ = json.Unmarshal(raw, &cfg)

	// the redacted definition round-trips and keeps the stored secret
	if resp, b := f.do("PUT", "/api/targets/"+id, "application/json", cfg.Target); resp.StatusCode != 200 {
		t.Fatalf("put back: %d %s", resp.StatusCode, b)
	}
	st, _ := f.sched.State(idn)
	if h := st.Spec.Probes[0].Headers; h["X-Api-Key"] != "s3cret" || h["X-Token"] != "${PATHWATCH_PROBE_TOKEN}" {
		t.Fatalf("running headers: %v", h)
	}

	// a changed URL cannot inherit the secret
	cfg.Target["probes"].([]any)[0].(map[string]any)["url"] = "http://evil.example/"
	if resp, b := f.do("PUT", "/api/targets/"+id, "application/json", cfg.Target); resp.StatusCode != 400 || !strings.Contains(errMsg(b), "re-enter") {
		t.Errorf("changed url: %d %s", resp.StatusCode, b)
	}
	st, _ = f.sched.State(idn)
	if st.Spec.Probes[0].Headers["X-Api-Key"] != "s3cret" {
		t.Errorf("secret lost after rejected update: %v", st.Spec.Probes[0].Headers)
	}
	// a new header value replaces it
	cfg.Target["probes"].([]any)[0].(map[string]any)["headers"] = map[string]string{"X-Api-Key": "n3w"}
	if resp, b := f.do("PUT", "/api/targets/"+id, "application/json", cfg.Target); resp.StatusCode != 200 {
		t.Fatalf("new value: %d %s", resp.StatusCode, b)
	}
	st, _ = f.sched.State(idn)
	if st.Spec.Probes[0].Headers["X-Api-Key"] != "n3w" {
		t.Errorf("headers: %v", st.Spec.Probes[0].Headers)
	}
	// the placeholder is not accepted for a new target
	if resp, b := f.postJSON("/api/targets", map[string]any{"name": "n2", "host": "n2.example", "probes": []map[string]any{{"type": "http", "url": "http://n2.example/", "headers": map[string]string{"A": "********"}}}}); resp.StatusCode != 400 {
		t.Errorf("placeholder on create: %d %s", resp.StatusCode, b)
	}
}

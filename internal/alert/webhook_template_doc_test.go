package alert

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

// docBodyTemplate is the body_template example from docs/SPEC.md. Keep them in sync.
const docBodyTemplate = `{"text": {{json .Title}}, "target": {{json .Target}}, "rule": {{json .Rule}}, "state": {{json .State}}, "message": {{json .Message}}, "link": {{json .Link}}, "value": {{.Value}}}`

func TestDocumentedBodyTemplateIsValidJSON(t *testing.T) {
	v := 412.5
	n := Notification{
		AlertID:   7,
		Target:    `my "quoted" target\` + "\nline2",
		Rule:      `rule","injected":"x`,
		RuleType:  "http_latency",
		State:     "firing",
		Value:     &v,
		Message:   "tls: certificate is valid for \"evil.example\", not host\\name\n",
		StartedAt: time.Unix(1700000000, 0).UTC(),
		Link:      `https://nas.local/t/1?a="b"`,
	}
	w, err := NewWebhookSender(config.WebhookConfig{BodyTemplate: docBodyTemplate}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, hdr, err := w.Render(n)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(body) {
		t.Fatalf("rendered body is not valid JSON: %s", body)
	}
	if hdr["Content-Type"] != "application/json" {
		t.Errorf("content type = %q", hdr["Content-Type"])
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["target"] != n.Target || got["rule"] != n.Rule || got["message"] != n.Message || got["link"] != n.Link {
		t.Errorf("values did not round-trip: %v", got)
	}
	if _, injected := got["injected"]; injected {
		t.Error("a value injected an extra JSON field")
	}
}

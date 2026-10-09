package main

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func TestNotifyTest(t *testing.T) {
	hits := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	t.Setenv("PATHWATCH_NOTIFY_TEST_URL", ts.URL)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	parse := func(yaml string) *config.Config {
		t.Helper()
		cfg, err := config.Parse([]byte(yaml), func(string) string { return "" })
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	none := parse("")
	var out bytes.Buffer
	if code := notifyTest(none, "", &out, quiet); code != 1 || !strings.Contains(out.String(), "no notification channels") {
		t.Errorf("no channels: code %d, output %q", code, out.String())
	}

	hook := parse("alerts:\n  notify:\n    webhook:\n      url_env: PATHWATCH_NOTIFY_TEST_URL\n      preset: generic\n")
	out.Reset()
	if code := notifyTest(hook, "", &out, quiet); code != 0 || !strings.HasPrefix(out.String(), "webhook: sent in ") || hits != 1 {
		t.Errorf("webhook: code %d, output %q, hits %d", code, out.String(), hits)
	}
	out.Reset()
	if code := notifyTest(hook, "email", &out, quiet); code != 1 || !strings.Contains(out.String(), "email: not configured") || hits != 1 {
		t.Errorf("--channel email: code %d, output %q", code, out.String())
	}

	t.Setenv("PATHWATCH_NOTIFY_TEST_URL", "")
	out.Reset()
	if code := notifyTest(hook, "webhook", &out, quiet); code != 1 || !strings.Contains(out.String(), "webhook: FAILED") || !strings.Contains(out.String(), "is empty") {
		t.Errorf("empty URL: code %d, output %q", code, out.String())
	}
}

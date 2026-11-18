package web

import (
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func metricsConfig(t *testing.T, enabled bool) *config.Config {
	t.Helper()
	y := "metrics:\n  enabled: false\n"
	if enabled {
		y = "metrics:\n  enabled: true\n"
	}
	cfg, err := config.Parse([]byte(y), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func (f *e2eFixture) metricsServer(t *testing.T, enabled bool, auth config.Auth) http.Handler {
	t.Helper()
	return New(Deps{Store: f.st, Config: metricsConfig(t, enabled), Auth: auth, Version: "1.2.3", Now: func() time.Time { return f.now },
		Static: fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}}}).Handler()
}

func TestMetricsGolden(t *testing.T) {
	f := newE2EFixture(t, nil)
	h := f.metricsServer(t, true, config.Auth{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, loopbackReq("GET", "/metrics"))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("Content-Type %q", ct)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Content-Security-Policy") == "" {
		t.Error("security headers missing on /metrics")
	}
	got := w.Body.String()
	file := filepath.Join("testdata", "metrics_golden.txt")
	if *updateGolden {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("/metrics differs from %s (run with -update after intended changes)\n got:\n%s\nwant:\n%s", file, got, want)
	}
	// every family is declared once and every sample line is well formed
	sample := regexp.MustCompile(`^[a-z0-9_]+(\{([a-z]+="([^"\\\n]|\\.)*",?)+\})? [-+0-9.eE]+$`)
	types := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if strings.HasPrefix(l, "# TYPE ") {
			n := strings.Fields(l)[2]
			if types[n] {
				t.Errorf("duplicate TYPE %s", n)
			}
			types[n] = true
		} else if !strings.HasPrefix(l, "# HELP ") && !sample.MatchString(l) {
			t.Errorf("malformed line %q", l)
		}
		if strings.Contains(l, "NaN") || strings.Contains(l, "Inf") {
			t.Errorf("NaN/Inf emitted: %q", l)
		}
	}
	for _, n := range []string{"pathwatch_build_info", "pathwatch_target_up", "pathwatch_hop_loss_ratio", "pathwatch_probe_total_seconds", "pathwatch_alerts_active", "pathwatch_outbox_pending"} {
		if !types[n] {
			t.Errorf("family %s missing", n)
		}
	}
	if strings.Contains(got, "address=") {
		t.Error("hop addresses must not be labels")
	}
}

func TestMetricsDisabledAndAuth(t *testing.T) {
	f := newE2EFixture(t, nil)
	get := func(h http.Handler, user, pass string) *httptest.ResponseRecorder {
		r := loopbackReq("GET", "/metrics")
		if user != "" {
			r.SetBasicAuth(user, pass)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := get(f.metricsServer(t, false, config.Auth{}), "", ""); w.Code != 404 || strings.Contains(w.Body.String(), "pathwatch_") {
		t.Errorf("disabled: %d %s", w.Code, w.Body.String())
	}
	auth := config.Auth{Enabled: true, User: "admin", Password: "s3cret"}
	h := f.metricsServer(t, true, auth)
	if w := get(h, "", ""); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("no credentials: %d", w.Code)
	}
	if w := get(h, "admin", "wrong"); w.Code != 401 {
		t.Errorf("bad credentials: %d", w.Code)
	}
	if w := get(h, "admin", "s3cret"); w.Code != 200 || !strings.Contains(w.Body.String(), "pathwatch_build_info") {
		t.Errorf("good credentials: %d", w.Code)
	}
	// disabled stays 401 without credentials (no probing for the route) and 404 with them
	hd := f.metricsServer(t, false, auth)
	if w := get(hd, "", ""); w.Code != 401 {
		t.Errorf("disabled without credentials: %d", w.Code)
	}
	if w := get(hd, "admin", "s3cret"); w.Code != 404 {
		t.Errorf("disabled with credentials: %d", w.Code)
	}
	// the Host check applies while auth is off
	r := httptest.NewRequest("GET", "/metrics", nil)
	r.Host = "evil.example.com"
	w := httptest.NewRecorder()
	f.metricsServer(t, true, config.Auth{}).ServeHTTP(w, r)
	if w.Code != http.StatusMisdirectedRequest {
		t.Errorf("rebinding Host: %d", w.Code)
	}
	// the failed-auth limiter backs off repeated wrong guesses
	got429 := false
	for i := 0; i < 6; i++ {
		if get(h, "admin", "nope").Code == 429 {
			got429 = true
		}
	}
	if !got429 {
		t.Error("repeated bad credentials were never rate limited")
	}
}

func TestMetricsEscaping(t *testing.T) {
	if got := escapeLabel("a\\b\"c\nd"); got != `a\\b\"c\nd` {
		t.Errorf("label: %q", got)
	}
	if got := escapeHelp("x\\y\nz \"q\""); got != `x\\y\nz "q"` {
		t.Errorf("help: %q", got)
	}
	d := newMetricsDoc()
	d.declare("pathwatch_x", "gauge", "line1\nline2 \\")
	d.add("pathwatch_x", 1.5, "target", "we\"ird\\na\nme", "host", "h")
	d.add("pathwatch_x", math.NaN())
	want := "# HELP pathwatch_x line1\\nline2 \\\\\n# TYPE pathwatch_x gauge\npathwatch_x{target=\"we\\\"ird\\\\na\\nme\",host=\"h\"} 1.5\n"
	if got := string(d.bytes()); got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if got := probeLabel("GET https://x.example/p?token=abc#f"); got != "GET https://x.example/p" {
		t.Errorf("probe label %q", got)
	}
}

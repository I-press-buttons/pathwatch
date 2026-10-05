package web

import (
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/i-press-buttons/pathwatch/internal/config"
	webui "github.com/i-press-buttons/pathwatch/web"
)

func embeddedUI(t *testing.T) fs.FS {
	t.Helper()
	sub, err := fs.Sub(webui.Static, "static")
	if err != nil {
		t.Fatal(err)
	}
	return sub
}

func checkSecurityHeaders(t *testing.T, name string, h http.Header, wantHSTS bool) {
	t.Helper()
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("%s: X-Content-Type-Options %q", name, got)
	}
	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("%s: X-Frame-Options %q", name, got)
	}
	if got := h.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("%s: Referrer-Policy %q", name, got)
	}
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"frame-ancestors 'none'", "script-src 'self'", "style-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("%s: CSP %q lacks %q", name, csp, want)
		}
	}
	if strings.Contains(csp, "unsafe-") {
		t.Errorf("%s: CSP %q allows unsafe sources", name, csp)
	}
	if got := h.Get("Strict-Transport-Security") != ""; got != wantHSTS {
		t.Errorf("%s: Strict-Transport-Security %q, want present=%v", name, h.Get("Strict-Transport-Security"), wantHSTS)
	}
}

func TestSecurityHeaders(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg, err := config.Parse(nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	open := New(Deps{Static: embeddedUI(t), Logger: log, Config: cfg})
	open.mux.HandleFunc("GET /api/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	open.mux.HandleFunc("GET /api/ping", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
	locked := New(Deps{Static: embeddedUI(t), Logger: log, Auth: config.Auth{Enabled: true, User: "admin", Password: "s3cret-pass"}})

	do := func(h http.Handler, method, target, host string, hdr ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		r.Host = host
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	cases := []struct {
		name string
		w    *httptest.ResponseRecorder
		code int
	}{
		{"ui", do(open.Handler(), "GET", "/", "127.0.0.1:8080"), 200},
		{"spa fallback", do(open.Handler(), "GET", "/targets/1", "127.0.0.1:8080"), 200},
		{"asset", do(open.Handler(), "GET", "/js/app.js", "127.0.0.1:8080"), 200},
		{"asset 304", do(open.Handler(), "GET", "/js/app.js", "127.0.0.1:8080", "If-None-Match", "*"), 304},
		{"api ok", do(open.Handler(), "GET", "/api/ping", "127.0.0.1:8080"), 200},
		{"api 404", do(open.Handler(), "GET", "/api/nope", "127.0.0.1:8080"), 404},
		{"asset 404", do(open.Handler(), "GET", "/js/nope.js", "127.0.0.1:8080"), 404},
		{"api 405", do(open.Handler(), "DELETE", "/api/ping", "127.0.0.1:8080"), 405},
		{"403 cross-site", do(open.Handler(), "POST", "/api/silences", "127.0.0.1:8080", "Sec-Fetch-Site", "cross-site"), 403},
		{"421 foreign host", do(open.Handler(), "GET", "/", "rebind.example"), 421},
		{"panic 500", do(open.Handler(), "GET", "/api/boom", "127.0.0.1:8080"), 500},
		{"401", do(locked.Handler(), "GET", "/", "nas.lan"), 401},
		{"429", func() *httptest.ResponseRecorder {
			var w *httptest.ResponseRecorder
			for i := 0; i < 10; i++ {
				r := httptest.NewRequest("GET", "/", nil)
				r.SetBasicAuth("admin", "wrong")
				w = httptest.NewRecorder()
				locked.Handler().ServeHTTP(w, r)
			}
			return w
		}(), 429},
	}
	for _, c := range cases {
		if c.w.Code != c.code {
			t.Errorf("%s: status %d, want %d", c.name, c.w.Code, c.code)
		}
		checkSecurityHeaders(t, c.name, c.w.Header(), false)
	}

	// HSTS only with built-in TLS.
	cfg.TLS.CertFile, cfg.TLS.KeyFile = "cert.pem", "key.pem"
	tls := New(Deps{Static: embeddedUI(t), Logger: log, Config: cfg})
	checkSecurityHeaders(t, "tls", do(tls.Handler(), "GET", "/", "127.0.0.1:8080").Header(), true)
}

// The strict CSP (no 'unsafe-inline') only works while the shell has no inline script and no
// style attribute.
func TestEmbeddedIndexIsCSPClean(t *testing.T) {
	b, err := fs.ReadFile(embeddedUI(t), "index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	scripts := regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`).FindAllStringSubmatch(html, -1)
	if len(scripts) == 0 {
		t.Error("no <script> found in index.html")
	}
	for _, m := range scripts {
		if !strings.Contains(m[1], "src=") || strings.TrimSpace(m[2]) != "" {
			t.Errorf("inline <script> in index.html: <script%s>%s", m[1], m[2])
		}
	}
	if regexp.MustCompile(`(?i)\sstyle\s*=`).MatchString(html) {
		t.Error("style= attribute in index.html")
	}
	if regexp.MustCompile(`(?i)<style\b`).MatchString(html) {
		t.Error("<style> element in index.html")
	}
	if regexp.MustCompile(`(?i)\son[a-z]+\s*=`).MatchString(html) {
		t.Error("inline event handler in index.html")
	}
	// the theme bootstrap runs from a synchronous classic script in <head>, before the stylesheets
	boot := strings.Index(html, `<script src="js/theme-boot.js"></script>`)
	if boot < 0 || boot > strings.Index(html, "</head>") || boot > strings.Index(html, `rel="stylesheet"`) {
		t.Errorf("js/theme-boot.js is not loaded synchronously early in <head> (at %d)", boot)
	}
	if _, err := fs.Stat(embeddedUI(t), "js/theme-boot.js"); err != nil {
		t.Errorf("theme-boot.js is not embedded: %v", err)
	}
}

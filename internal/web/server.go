// Package web is the HTTP server: Basic auth, optional TLS, the JSON API described in
// docs/API.md, the SSE live stream and the embedded single-page UI.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/enrich"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
	"github.com/i-press-buttons/pathwatch/internal/settings"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// Deps are the server's collaborators.
type Deps struct {
	Store    *store.Store
	Sched    *scheduler.Scheduler
	Analyzer *analyze.Analyzer
	Enrich   *enrich.Enricher  // optional
	Hub      *Hub              // optional (a private hub is created when nil)
	Config   *config.Config    // the configuration (used when Settings is nil)
	Settings *settings.Manager // optional: UI-edited settings and the effective configuration
	Resolver Resolver          // optional: for /api/resolve (default net.DefaultResolver)
	Notifier Notifier          // optional: test notifications (the rule engine's outbox sender)
	Auth     config.Auth
	Version  string
	Logger   *slog.Logger
	Static   fs.FS // the UI files (root contains index.html)
	Now      func() time.Time
}

// Server serves the API and the UI.
type Server struct {
	d       Deps
	log     *slog.Logger
	hub     *Hub
	mux     *http.ServeMux
	now     func() time.Time
	started time.Time
	maint   alert.MaintenanceWindows
	userSum [32]byte
	passSum [32]byte
	files   http.Handler
	limiter *authLimiter
	tests   *channelTests
}

// New builds the server.
func New(d Deps) *Server {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Hub == nil {
		d.Hub = NewHub()
	}
	s := &Server{d: d, log: d.Logger, hub: d.Hub, mux: http.NewServeMux(), now: d.Now, started: d.Now(), limiter: newAuthLimiter(), tests: newChannelTests()}
	if d.Config != nil {
		s.maint = alert.MaintenanceWindows(d.Config.Alerts.MaintenanceWindows)
	}
	s.userSum = sha256.Sum256([]byte(d.Auth.User))
	s.passSum = sha256.Sum256([]byte(d.Auth.Password))
	s.hub.alertJSON = s.alertByID
	if d.Static != nil {
		s.files = newStaticHandler(d.Static, d.Logger)
	}
	s.routes()
	return s
}

// cfg returns the effective configuration.
func (s *Server) cfg() *config.Config {
	if s.d.Settings != nil {
		return s.d.Settings.Effective()
	}
	if s.d.Config != nil {
		return s.d.Config
	}
	return defaultConfig
}

var defaultConfig = func() *config.Config {
	c, _ := config.Parse(nil, func(string) string { return "" })
	return c
}()

// Hub returns the SSE hub (use it as the scheduler Observer and alert AlertSink).
func (s *Server) Hub() *Hub { return s.hub }

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /healthz", s.handleHealthz)
	m.HandleFunc("GET /api/status", s.handleStatus)
	m.HandleFunc("GET /api/targets", s.handleTargets)
	m.HandleFunc("POST /api/targets", s.handleCreateTarget)
	m.HandleFunc("PUT /api/targets/{id}", s.handleUpdateTarget)
	m.HandleFunc("DELETE /api/targets/{id}", s.handleDeleteTarget)
	m.HandleFunc("GET /api/targets/{id}/config", s.handleTargetConfig)
	m.HandleFunc("DELETE /api/targets/{id}/override", s.handleRevertTarget)
	m.HandleFunc("GET /api/settings", s.handleSettings)
	m.HandleFunc("PUT /api/settings/{section}", s.handlePutSetting)
	m.HandleFunc("DELETE /api/settings/{section}", s.handleDeleteSetting)
	m.HandleFunc("GET /api/resolve", s.handleResolve)
	m.HandleFunc("GET /api/channels", s.handleChannels)
	m.HandleFunc("POST /api/channels/{name}/test", s.handleTestChannel)
	m.HandleFunc("POST /api/targets/{id}/pause", s.handlePause(true))
	m.HandleFunc("POST /api/targets/{id}/resume", s.handlePause(false))
	m.HandleFunc("GET /api/overview", s.handleOverview)
	m.HandleFunc("GET /api/targets/{id}/hops", s.handleHops)
	m.HandleFunc("GET /api/targets/{id}/timeline", s.handleTimeline)
	m.HandleFunc("GET /api/targets/{id}/series", s.handleSeries)
	m.HandleFunc("GET /api/targets/{id}/probes", s.handleProbes)
	m.HandleFunc("GET /api/dns", s.handleDNS)
	m.HandleFunc("GET /api/alerts", s.handleAlerts)
	m.HandleFunc("GET /api/events", s.handleEvents)
	m.HandleFunc("GET /api/silences", s.handleSilences)
	m.HandleFunc("POST /api/silences", s.handleCreateSilence)
	m.HandleFunc("DELETE /api/silences/{id}", s.handleDeleteSilence)
	m.HandleFunc("GET /api/stream", s.handleStream)
	m.HandleFunc("/", s.handleUI)
}

// Handler returns the full handler chain (security headers, recover, JSON errors, logging, Host
// check, CSRF check, auth).
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = s.auth(h)
	h = s.sameOrigin(h)
	h = s.hostCheck(h)
	h = s.accessLog(h)
	h = jsonErrors(h)
	h = s.recoverer(h)
	h = s.securityHeaders(h)
	return h
}

// ---------------------------------------------------------------------------
// middleware

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.log.Error("handler panic", "path", r.URL.Path, "panic", rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// accessLog logs requests at debug level. It never logs headers, so credentials cannot leak.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.log.Enabled(r.Context(), slog.LevelDebug) {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(sw, r)
		s.log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "bytes", sw.bytes, "dur", time.Since(start), "remote", r.RemoteAddr)
	})
}

// jsonErrors turns non-JSON error responses of /api/ (such as the mux's plain-text 405) into
// {"error": "..."} bodies.
func jsonErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&errWriter{ResponseWriter: w}, r)
	})
}

type errWriter struct {
	http.ResponseWriter
	replaced bool
}

func (w *errWriter) WriteHeader(code int) {
	if code >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		w.replaced = true
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Del("Content-Length")
		w.ResponseWriter.WriteHeader(code)
		msg := strings.ToLower(http.StatusText(code))
		_ = json.NewEncoder(w.ResponseWriter).Encode(map[string]string{"error": msg})
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *errWriter) Write(b []byte) (int, error) {
	if w.replaced {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *errWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *errWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// sameOrigin rejects cross-site state-changing requests (CSRF). Modern browsers send
// Sec-Fetch-Site; older ones are checked by comparing Origin with the Host the request was made
// to (also honouring X-Forwarded-Host and public_url, for reverse proxies).
func (s *Server) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			switch r.Header.Get("Sec-Fetch-Site") {
			case "same-origin", "none":
			case "":
				if !s.originAllowed(r) {
					writeError(w, http.StatusForbidden, "cross-origin request refused")
					return
				}
			default: // cross-site, same-site
				writeError(w, http.StatusForbidden, "cross-site request refused")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true // not a browser cross-origin request (curl, scripts)
	}
	u, err := url.Parse(o)
	if err != nil || o == "null" {
		return false
	}
	allowed := []string{r.Host}
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		allowed = append(allowed, strings.TrimSpace(strings.Split(fh, ",")[0]))
	}
	if s.d.Config != nil && s.d.Config.PublicURL != "" {
		if pu, err := url.Parse(s.d.Config.PublicURL); err == nil {
			allowed = append(allowed, pu.Host)
		}
	}
	for _, h := range allowed {
		if strings.EqualFold(u.Host, h) {
			return true
		}
	}
	return false
}

// auth enforces HTTP Basic auth (constant-time comparison) on everything except /healthz. Clients
// that keep sending wrong credentials are backed off per address (see authLimiter).
func (s *Server) auth(next http.Handler) http.Handler {
	if !s.d.Auth.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		challenge := func() {
			w.Header().Set("WWW-Authenticate", `Basic realm="pathwatch", charset="UTF-8"`)
			writeError(w, http.StatusUnauthorized, "authentication required")
		}
		if r.Header.Get("Authorization") == "" {
			challenge() // e.g. a browser's first request before the login prompt: not a guess
			return
		}
		u, p, _ := r.BasicAuth()
		good, retry := s.limiter.attempt(s.now(), r.RemoteAddr, u, s.log, func() bool { return s.checkCreds(u, p) })
		switch {
		case good:
			next.ServeHTTP(w, r)
		case retry > 0:
			w.Header().Set("Retry-After", retryAfterSeconds(retry))
			writeError(w, http.StatusTooManyRequests, "too many failed authentication attempts")
		default:
			challenge()
		}
	})
}

func (s *Server) checkCreds(user, pass string) bool {
	us := sha256.Sum256([]byte(user))
	ps := sha256.Sum256([]byte(pass))
	// Evaluate both comparisons unconditionally so timing does not reveal which one failed.
	a := subtle.ConstantTimeCompare(us[:], s.userSum[:])
	b := subtle.ConstantTimeCompare(ps[:], s.passSum[:])
	return a&b == 1
}

// ---------------------------------------------------------------------------
// responses

func writeJSON(w http.ResponseWriter, code int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		writeError(w, http.StatusInternalServerError, "encoding failed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// requireJSON enforces a JSON content type on bodies (blocks simple cross-site form posts).
func requireJSON(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	if strings.TrimSpace(strings.ToLower(ct)) != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	return true
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	return decode(w, r, v, false)
}

// decodeStrict is decodeBody that rejects unknown fields (catches typos in settings).
func decodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	return decode(w, r, v, true)
}

func decode(w http.ResponseWriter, r *http.Request, v any, strict bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	dec := json.NewDecoder(r.Body)
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// UI

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		// Registered API routes only match their own method, so a wrong method lands here.
		w.Header().Set("Allow", "GET, HEAD")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if s.files == nil {
		writeError(w, http.StatusNotFound, "ui not available")
		return
	}
	s.files.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// listen

// ListenAndServe serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) ListenAndServe(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	errCh := make(chan error, 1)
	go func() {
		var err error
		if s.d.Config != nil && s.d.Config.TLS.CertFile != "" {
			err = srv.ServeTLS(ln, s.d.Config.TLS.CertFile, s.d.Config.TLS.KeyFile)
		} else {
			err = srv.Serve(ln)
		}
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	s.hub.Close()
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

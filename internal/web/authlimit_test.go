package web

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type authRig struct {
	srv   *Server
	h     http.Handler
	clock *fakeClock
	logs  *bytes.Buffer
}

func newAuthRig(t *testing.T) *authRig {
	t.Helper()
	r := &authRig{clock: &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}, logs: &bytes.Buffer{}}
	log := slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	r.srv = New(Deps{Auth: config.Auth{Enabled: true, User: "admin", Password: goodPass}, Logger: log, Now: r.clock.Now, Static: fstest.MapFS{"index.html": {Data: []byte("ui")}}})
	r.h = r.srv.Handler()
	return r
}

// do sends one request from remote; pass "" for pass to send no Authorization header at all.
func (r *authRig) do(remote, pass string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = remote
	if pass != "" {
		req.SetBasicAuth("admin", pass)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

const goodPass = "correct-horse-battery"

func TestAuthLimiterBackoff(t *testing.T) {
	r := newAuthRig(t)
	const bad, other = "10.0.0.5:51000", "10.0.0.6:40000"

	for i := 0; i < authFreeFailures; i++ {
		if w := r.do(bad, "wrong"); w.Code != 401 {
			t.Fatalf("failure %d: %d, want 401", i+1, w.Code)
		}
	}
	// backed off: even the right password is refused, without being evaluated
	w := r.do(bad, goodPass)
	if w.Code != 429 {
		t.Fatalf("backed off: %d, want 429", w.Code)
	}
	if ra, err := strconv.Atoi(w.Header().Get("Retry-After")); err != nil || ra < 1 {
		t.Errorf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	if w.Header().Get("WWW-Authenticate") != "" {
		t.Error("429 must not trigger a browser login prompt")
	}
	// other clients are unaffected, with or without the right password
	if w := r.do(other, goodPass); w.Code != 200 {
		t.Errorf("other client with correct credentials: %d", w.Code)
	}
	if w := r.do(other, "wrong"); w.Code != 401 {
		t.Errorf("other client with a wrong password: %d", w.Code)
	}
	// no Authorization header: not a failure and not counted, even while backed off
	if w := r.do(bad, ""); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("no credentials while backed off: %d", w.Code)
	}
	// backoff expires, success resets the counter
	r.clock.Advance(authBackoffBase + time.Millisecond)
	if w := r.do(bad, goodPass); w.Code != 200 {
		t.Fatalf("after backoff: %d, want 200", w.Code)
	}
	if got := len(r.srv.limiter.fails); got != 1 { // only "other" (its one failure) remains
		t.Errorf("tracked clients %d, want 1", got)
	}
	if w := r.do(bad, "wrong"); w.Code != 401 {
		t.Errorf("counter was not reset: %d", w.Code)
	}
}

func TestAuthLimiterBackoffGrowsAndIsCapped(t *testing.T) {
	r := newAuthRig(t)
	const c = "10.0.0.5:1"
	var prev time.Duration
	for i := 0; i < 40; i++ {
		w := r.do(c, "wrong")
		if w.Code != 401 {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
		st := r.srv.limiter.fails[clientKey(c)]
		d := st.until.Sub(r.clock.Now())
		if i >= authFreeFailures-1 && d < prev {
			t.Fatalf("backoff shrank: %v after %v", d, prev)
		}
		if d > authBackoffMax {
			t.Fatalf("backoff %v exceeds the cap", d)
		}
		prev = d
		r.clock.Advance(d)
	}
	if prev != authBackoffMax {
		t.Errorf("backoff settled at %v, want %v", prev, authBackoffMax)
	}
}

func TestAuthLimiterConcurrentGuesses(t *testing.T) {
	r := newAuthRig(t)
	const n = 200
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = r.do("10.0.0.5:2000", fmt.Sprintf("guess-%d", i)).Code
		}()
	}
	wg.Wait()
	got := map[int]int{}
	for _, c := range codes {
		got[c]++
	}
	if got[401] != authFreeFailures || got[429] != n-authFreeFailures {
		t.Errorf("%d concurrent guesses: %v, want exactly %d evaluated", n, got, authFreeFailures)
	}
	if w := r.do("10.0.0.6:1", goodPass); w.Code != 200 {
		t.Errorf("another client: %d", w.Code)
	}
}

func TestAuthLimiterKeyIgnoresForwardedFor(t *testing.T) {
	r := newAuthRig(t)
	for i := 0; i < authFreeFailures; i++ {
		r.do("10.0.0.5:1", "wrong", "X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
	}
	if w := r.do("10.0.0.5:2", "wrong", "X-Forwarded-For", "198.51.100.9"); w.Code != 429 {
		t.Errorf("spoofed X-Forwarded-For escaped the limit: %d", w.Code)
	}
	if w := r.do("10.0.0.9:2", goodPass, "X-Forwarded-For", "10.0.0.5"); w.Code != 200 {
		t.Errorf("X-Forwarded-For made a clean client share a backed-off key: %d", w.Code)
	}
}

func TestClientKey(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.5:1234":                        "10.0.0.5",
		"10.0.0.5":                             "10.0.0.5",
		"[::ffff:10.0.0.5]:80":                 "10.0.0.5",
		"[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:9": "2001:db8:1:2::/64",
		"[2001:db8:1:2::1]:1":                  "2001:db8:1:2::/64",
		"[fe80::1%eth0]:1":                     "fe80::/64",
		"@":                                    "@",
	} {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuthLimiterIPv6SharesAPrefix(t *testing.T) {
	r := newAuthRig(t)
	for i := 0; i < authFreeFailures; i++ {
		r.do(fmt.Sprintf("[2001:db8:1:2::%x]:1", i+1), "wrong")
	}
	if w := r.do("[2001:db8:1:2:ffff::1]:1", goodPass); w.Code != 429 {
		t.Errorf("same /64: %d, want 429", w.Code)
	}
	if w := r.do("[2001:db8:1:3::1]:1", goodPass); w.Code != 200 {
		t.Errorf("other /64: %d, want 200", w.Code)
	}
}

func TestAuthLimiterPrunesAndIsBounded(t *testing.T) {
	r := newAuthRig(t)
	l := r.srv.limiter
	for i := 0; i < authMaxClients+500; i++ {
		r.do(fmt.Sprintf("10.%d.%d.%d:1", i>>16, (i>>8)&255, i&255), "wrong")
		r.clock.Advance(time.Millisecond)
	}
	if got := len(l.fails); got > authMaxClients {
		t.Errorf("limiter holds %d clients, cap %d", got, authMaxClients)
	}
	r.clock.Advance(authIdleExpiry + authBackoffMax)
	r.do("192.0.2.1:1", "wrong")
	if got := len(l.fails); got != 1 {
		t.Errorf("idle clients not pruned: %d left", got)
	}
}

func TestAuthFailureLogging(t *testing.T) {
	r := newAuthRig(t)
	const secret = "hunter2-very-secret"
	r.do("10.0.0.5:7", secret)
	r.do("10.0.0.5:7", secret)
	r.do("10.0.0.6:7", "also-wrong")
	out := r.logs.String()
	if n := strings.Count(out, "authentication failed"); n != 2 { // one per client, not per attempt
		t.Errorf("%d warnings, want 2:\n%s", n, out)
	}
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "remote=10.0.0.5") || !strings.Contains(out, "user=admin") {
		t.Errorf("warning lacks level, remote or user:\n%s", out)
	}
	if strings.Contains(out, secret) || strings.Contains(out, "also-wrong") {
		t.Errorf("a password was logged:\n%s", out)
	}
	// logged again once the interval has passed, with the running count
	r.clock.Advance(authLogEvery)
	r.do("10.0.0.5:7", secret) // the third failure: not backed off yet, so it is evaluated and logged
	if n := strings.Count(r.logs.String(), "authentication failed"); n != 3 {
		t.Errorf("%d warnings after the interval, want 3", n)
	}
	if !strings.Contains(r.logs.String(), "attempts=2") { // the suppressed second one plus this one
		t.Errorf("missing attempt count:\n%s", r.logs.String())
	}
}

func TestAuthOffIsNotLimited(t *testing.T) {
	s := New(Deps{Static: fstest.MapFS{"index.html": {Data: []byte("ui")}}})
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Host = "127.0.0.1:8080"
		req.SetBasicAuth("x", "y")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%d", w.Code)
		}
	}
}

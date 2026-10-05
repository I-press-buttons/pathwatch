package web

import (
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Failed-login limiting: after a few wrong guesses a client is rejected with 429 without its
// credentials being evaluated, for a capped, exponentially growing time.
const (
	authFreeFailures = 3                      // failures before the first backoff
	authBackoffBase  = 250 * time.Millisecond // backoff after the last free failure; doubles per failure
	authBackoffMax   = 5 * time.Minute
	authIdleExpiry   = time.Hour // an entry that has been quiet this long is forgotten
	authMaxClients   = 4096      // size cap, so the limiter cannot be used to exhaust memory
	authPruneEvery   = time.Minute
	authLogEvery     = time.Minute // at most one "authentication failed" warning per client per interval
)

type failState struct {
	n       int       // consecutive failures
	until   time.Time // reject without checking credentials until then
	last    time.Time // last failed attempt
	lastLog time.Time // last warning logged for this client
	unlogd  int       // failures since that warning
}

// authLimiter tracks failed logins per client. The check, the credential evaluation and the
// bookkeeping happen under one lock, so concurrent guesses from one client cannot all get past
// the limit before the first failure is recorded. That also bounds the work done for
// unauthenticated requests: evaluation is two SHA-256 hashes of short inputs, so serialising it
// costs nothing measurable, and nothing sleeps while holding a goroutine or connection.
type authLimiter struct {
	mu        sync.Mutex
	fails     map[string]*failState
	lastPrune time.Time
}

func newAuthLimiter() *authLimiter { return &authLimiter{fails: map[string]*failState{}} }

// clientKey is the limiter key for a RemoteAddr: the IP, with IPv6 collapsed to its /64 (a single
// host or subscriber typically owns a whole /64). X-Forwarded-For is never consulted: it is
// client-controlled.
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.WithZone("").Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

// attempt runs check for one request that presented credentials. It reports ok or, when the
// client is backed off (check is then not called), the time left to wait. A failure is logged at
// warn level, rate-limited per client.
func (l *authLimiter) attempt(now time.Time, remote, user string, log *slog.Logger, check func() bool) (ok bool, retry time.Duration) {
	key := clientKey(remote)
	l.mu.Lock()
	st := l.fails[key]
	if st != nil && now.Before(st.until) {
		retry = st.until.Sub(now)
		l.mu.Unlock()
		return false, retry
	}
	if check() {
		delete(l.fails, key)
		l.mu.Unlock()
		return true, 0
	}
	l.prune(now)
	if st = l.fails[key]; st == nil {
		if len(l.fails) >= authMaxClients {
			l.evictOldest()
		}
		st = &failState{}
		l.fails[key] = st
	}
	st.n++
	st.last = now
	if st.n >= authFreeFailures {
		st.until = now.Add(backoff(st.n))
	}
	st.unlogd++
	logN := 0
	if st.lastLog.IsZero() || now.Sub(st.lastLog) >= authLogEvery {
		logN, st.unlogd, st.lastLog = st.unlogd, 0, now
	}
	n := st.n
	l.mu.Unlock()
	if logN > 0 {
		if len(user) > 64 {
			user = user[:64]
		}
		log.Warn("authentication failed", "remote", key, "user", user, "attempts", logN, "consecutive", n)
	}
	return false, 0
}

func backoff(n int) time.Duration {
	shift := n - authFreeFailures
	if shift > 20 {
		shift = 20
	}
	d := authBackoffBase << shift
	if d > authBackoffMax || d <= 0 {
		d = authBackoffMax
	}
	return d
}

// prune forgets clients that have been quiet for authIdleExpiry. Caller holds l.mu.
func (l *authLimiter) prune(now time.Time) {
	if now.Sub(l.lastPrune) < authPruneEvery {
		return
	}
	l.lastPrune = now
	for k, st := range l.fails {
		if now.Sub(st.last) >= authIdleExpiry && !now.Before(st.until) {
			delete(l.fails, k)
		}
	}
}

// evictOldest drops the least recently failing client. Caller holds l.mu.
func (l *authLimiter) evictOldest() {
	var oldK string
	var oldT time.Time
	first := true
	for k, st := range l.fails {
		if first || st.last.Before(oldT) {
			oldK, oldT, first = k, st.last, false
		}
	}
	if !first {
		delete(l.fails, oldK)
	}
}

func retryAfterSeconds(d time.Duration) string {
	s := int((d + time.Second - 1) / time.Second)
	if s < 1 {
		s = 1
	}
	return strconv.Itoa(s)
}

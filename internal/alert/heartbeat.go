package alert

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

// heartbeatTimeout bounds one heartbeat request.
const heartbeatTimeout = 10 * time.Second

// Heartbeat is the dead-man's switch: while the monitor is healthy it GETs heartbeat.url every
// heartbeat.interval, so an external service (healthchecks.io, Uptime Kuma) can alert when the
// pings stop. It is off without a URL. The URL is a secret and is never logged.
type Heartbeat struct {
	log     *slog.Logger
	healthy func() bool
	client  *http.Client

	mu     sync.Mutex
	url    string
	every  time.Duration
	reload chan struct{}
	stop   chan struct{}
	done   chan struct{}
	last   time.Time
	lastOK bool

	started atomic.Bool
}

// NewHeartbeat creates a heartbeat. healthy reports the /healthz signal (nil = always healthy).
func NewHeartbeat(log *slog.Logger, healthy func() bool) *Heartbeat {
	if log == nil {
		log = slog.Default()
	}
	return &Heartbeat{
		log: log, healthy: healthy, client: &http.Client{Timeout: heartbeatTimeout},
		reload: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{}),
	}
}

// Configure sets the URL and interval (it may be called while running, for SIGHUP reloads).
func (h *Heartbeat) Configure(c config.HeartbeatConfig) {
	h.mu.Lock()
	h.url, h.every = c.URL, c.Interval.D()
	if h.every <= 0 {
		h.every = 5 * time.Minute
	}
	h.mu.Unlock()
	select {
	case h.reload <- struct{}{}:
	default:
	}
}

// Start launches the heartbeat goroutine.
func (h *Heartbeat) Start() {
	if h.started.Swap(true) {
		return
	}
	go h.loop()
}

// Close stops the heartbeat goroutine.
func (h *Heartbeat) Close() {
	select {
	case <-h.stop:
		return
	default:
		close(h.stop)
	}
	if !h.started.Load() {
		return
	}
	select {
	case <-h.done:
	case <-time.After(heartbeatTimeout + time.Second):
	}
}

func (h *Heartbeat) settings() (string, time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.url, h.every
}

func (h *Heartbeat) loop() {
	defer close(h.done)
	for {
		u, every := h.settings()
		wait := every
		if u != "" {
			h.Beat(context.Background())
		} else {
			wait = time.Hour // idle until reconfigured
		}
		t := time.NewTimer(wait)
		select {
		case <-h.stop:
			t.Stop()
			return
		case <-h.reload:
			t.Stop() // re-read the settings; a changed URL or interval takes effect now
		case <-t.C:
		}
	}
}

// Beat sends one heartbeat if a URL is set and the monitor is healthy. It reports whether a
// request was made and succeeded.
func (h *Heartbeat) Beat(ctx context.Context) bool {
	u, _ := h.settings()
	if u == "" {
		return false
	}
	if h.healthy != nil && !h.healthy() {
		h.log.Warn("heartbeat withheld: the monitor is not healthy")
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, heartbeatTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		h.log.Warn("heartbeat failed", "err", "invalid heartbeat url")
		return false
	}
	req.Header.Set("User-Agent", "pathwatch")
	resp, err := h.client.Do(req)
	ok := false
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		h.log.Warn("heartbeat failed", "err", err)
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<14))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			ok = true
		} else {
			h.log.Warn("heartbeat failed", "status", resp.StatusCode)
		}
	}
	h.mu.Lock()
	h.last, h.lastOK = time.Now(), ok
	h.mu.Unlock()
	return ok
}

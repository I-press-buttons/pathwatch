package web

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/config"
)

// Notifier sends test notifications over the alert channels (the rule engine's outbox sender).
type Notifier interface {
	// Channels returns the channels that are configured and usable.
	Channels() []string
	// SendTest delivers a test notification over one channel and returns the channel's error.
	SendTest(ctx context.Context, channel string) error
}

// channelTestGap is the minimum time between two tests of the same channel, so a stuck button or
// a script cannot flood a chat channel or an SMTP server.
const channelTestGap = 10 * time.Second

// channelTestTimeout bounds one test (the email channel allows 30 s per attempt).
const channelTestTimeout = 40 * time.Second

var channelNames = []string{alert.ChannelWebhook, alert.ChannelEmail}

// testResult is the outcome of the last test of a channel (kept in memory only).
type testResult struct {
	OK         bool    `json:"ok"`
	Error      *string `json:"error"`
	At         int64   `json:"at"`
	DurationMs float64 `json:"duration_ms"`
}

// channelTests serializes tests per channel and remembers the last result.
type channelTests struct {
	mu      sync.Mutex
	running map[string]bool
	started map[string]time.Time
	last    map[string]testResult
}

func newChannelTests() *channelTests {
	return &channelTests{running: map[string]bool{}, started: map[string]time.Time{}, last: map[string]testResult{}}
}

// begin reserves a test of channel; it returns how long to wait when one is running or was
// started less than channelTestGap ago.
func (c *channelTests) begin(channel string, now time.Time) (time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running[channel] {
		return channelTestGap, false
	}
	if t, ok := c.started[channel]; ok {
		if wait := channelTestGap - now.Sub(t); wait > 0 {
			return wait, false
		}
	}
	c.running[channel] = true
	c.started[channel] = now
	return 0, true
}

func (c *channelTests) finish(channel string, r testResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running[channel] = false
	c.last[channel] = r
}

func (c *channelTests) lastResult(channel string) *testResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.last[channel]; ok {
		return &r
	}
	return nil
}

// channelJSON describes one notification channel. Secrets (the webhook URL, header values, SMTP
// credentials) are never included; for environment variables only whether they are set.
type channelJSON struct {
	Name         string        `json:"name"`
	Configured   bool          `json:"configured"` // present in the config file
	Active       bool          `json:"active"`     // the sender accepted the configuration
	Summary      string        `json:"summary"`
	Warnings     []string      `json:"warnings"`
	LastDelivery *deliveryJSON `json:"last_delivery"`
	LastTest     *testResult   `json:"last_test"`
}

type deliveryJSON struct {
	AlertID  int64   `json:"alert_id"`
	Status   string  `json:"status"`
	Attempts int     `json:"attempts"`
	At       int64   `json:"at"`
	Error    *string `json:"error"`
}

// handleChannels lists the notification channels with their last delivery and last test.
func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request) {
	notify := s.cfg().Alerts.Notify
	active := map[string]bool{}
	if s.d.Notifier != nil {
		for _, c := range s.d.Notifier.Channels() {
			active[c] = true
		}
	}
	last, err := s.d.Store.LastDeliveries()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	out := make([]channelJSON, 0, len(channelNames))
	for _, name := range channelNames {
		c := channelJSON{Name: name, Active: active[name], Warnings: []string{}, LastTest: s.tests.lastResult(name)}
		switch name {
		case alert.ChannelWebhook:
			if wh := notify.Webhook; wh != nil {
				c.Configured = true
				c.Summary, c.Warnings = webhookSummary(*wh)
			}
		case alert.ChannelEmail:
			if em := notify.Email; em != nil {
				c.Configured = true
				c.Summary, c.Warnings = emailSummary(*em)
			}
		}
		if c.Configured && !c.Active {
			c.Warnings = append(c.Warnings, "the channel configuration was rejected at startup; see the log")
		}
		if d, ok := last[name]; ok {
			c.LastDelivery = &deliveryJSON{AlertID: d.AlertID, Status: d.Status, Attempts: d.Attempts, At: d.At.UnixMilli(), Error: d.LastError}
		}
		out = append(out, c)
	}
	writeJSON(w, http.StatusOK, out)
}

func webhookSummary(wh config.WebhookConfig) (string, []string) {
	parts := []string{}
	if wh.Preset != "" {
		parts = append(parts, wh.Preset+" preset")
	}
	if wh.BodyTemplate != "" {
		parts = append(parts, "custom body_template")
	}
	parts = append(parts, "URL from $"+wh.URLEnv)
	var warn []string
	if wh.URLEnv != "" && strings.TrimSpace(os.Getenv(wh.URLEnv)) == "" {
		warn = append(warn, "environment variable "+wh.URLEnv+" is empty, so nothing can be sent")
	}
	return strings.Join(parts, " · "), nonNil(warn)
}

func emailSummary(em config.EmailConfig) (string, []string) {
	port := em.SMTPPort
	if port == 0 {
		switch em.TLS {
		case "tls":
			port = 465
		case "none":
			port = 25
		default:
			port = 587
		}
	}
	parts := []string{net.JoinHostPort(em.SMTPHost, strconv.Itoa(port))}
	if em.TLS != "" {
		parts = append(parts, em.TLS)
	}
	parts = append(parts, fmt.Sprintf("%d recipient%s", len(em.To), plural(len(em.To))))
	var warn []string
	if em.UsernameEnv != "" && os.Getenv(em.UsernameEnv) == "" {
		warn = append(warn, "environment variable "+em.UsernameEnv+" is empty, so pathwatch will not log in to the SMTP server")
	}
	if em.TLS == "none" {
		warn = append(warn, "tls: none sends mail (and any SMTP password) unencrypted")
	}
	return strings.Join(parts, " · "), nonNil(warn)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// handleTestChannel sends a test notification over one channel and reports the outcome. A
// delivery failure is a successful request: 200 with ok false and the channel's error.
func (s *Server) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	known, active := false, false
	for _, c := range channelNames {
		known = known || c == name
	}
	if !known {
		writeError(w, http.StatusNotFound, "unknown channel "+strconv.Quote(name)+" (webhook or email)")
		return
	}
	if s.d.Notifier == nil {
		writeError(w, http.StatusServiceUnavailable, "notifications are not available on this server")
		return
	}
	for _, c := range s.d.Notifier.Channels() {
		active = active || c == name
	}
	if !active {
		writeError(w, http.StatusConflict, "the "+name+" channel is not configured (alerts.notify."+name+" in the config file)")
		return
	}
	if wait, ok := s.tests.begin(name, s.now()); !ok {
		secs := int((wait + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusTooManyRequests, fmt.Sprintf("the %s channel was tested moments ago; try again in %ds", name, secs))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), channelTestTimeout)
	defer cancel()
	start := time.Now()
	err := s.d.Notifier.SendTest(ctx, name)
	res := testResult{OK: err == nil, At: s.now().UnixMilli(), DurationMs: round3(float64(time.Since(start).Microseconds()) / 1000)}
	if err != nil {
		msg := err.Error()
		if errors.Is(err, alert.ErrChannelNotConfigured) {
			msg = "the " + name + " channel is not configured"
		}
		res.Error = &msg
		s.log.Warn("test notification failed", "channel", name, "err", msg)
	} else {
		s.log.Info("test notification sent", "channel", name)
	}
	s.tests.finish(name, res)
	writeJSON(w, http.StatusOK, res)
}

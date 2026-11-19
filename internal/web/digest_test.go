package web

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/publicip"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

type fakeOutbox struct {
	mu    sync.Mutex
	chs   []string
	notes []alert.Notification
}

func (o *fakeOutbox) Channels() []string { return o.chs }
func (o *fakeOutbox) Enqueue(n alert.Notification, channels []string) {
	o.mu.Lock()
	o.notes = append(o.notes, n)
	o.mu.Unlock()
}

func TestLastDigestSlot(t *testing.T) {
	utc := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	daily := config.DigestConfig{Schedule: "daily", Time: "08:00", Timezone: "UTC"}
	if got := lastDigestSlot(daily, utc("2026-11-19T09:30:00Z")); !got.Equal(utc("2026-11-19T08:00:00Z")) {
		t.Errorf("daily after the time: %v", got)
	}
	if got := lastDigestSlot(daily, utc("2026-11-19T07:59:00Z")); !got.Equal(utc("2026-11-18T08:00:00Z")) {
		t.Errorf("daily before the time: %v", got)
	}
	weekly := config.DigestConfig{Schedule: "weekly", Time: "08:00", Weekday: "mon", Timezone: "UTC"}
	// 2026-11-19 is a Thursday; the Monday before is the 16th
	if got := lastDigestSlot(weekly, utc("2026-11-19T09:30:00Z")); !got.Equal(utc("2026-11-16T08:00:00Z")) {
		t.Errorf("weekly: %v", got)
	}
	if got := lastDigestSlot(weekly, utc("2026-11-16T07:00:00Z")); !got.Equal(utc("2026-11-09T08:00:00Z")) {
		t.Errorf("weekly, same day before the time: %v", got)
	}
	ny := config.DigestConfig{Schedule: "daily", Time: "08:00", Timezone: "America/New_York"}
	if got := lastDigestSlot(ny, utc("2026-11-19T14:00:00Z")); !got.Equal(utc("2026-11-19T13:00:00Z")) {
		t.Errorf("time zone: %v", got)
	}
	if !lastDigestSlot(config.DigestConfig{Schedule: "off", Time: "08:00"}, time.Now()).IsZero() {
		t.Error("off has no slot")
	}
	if got := digestChannels([]string{"webhook", "email"}, []string{"email"}); len(got) != 1 || got[0] != "email" {
		t.Errorf("channels %v", got)
	}
}

func TestDigestPreviewAndSend(t *testing.T) {
	f := newFixture(t, fixtureOpts{startTargets: true})
	out := &fakeOutbox{}
	f.srv.d.Outbox = out
	now := time.Now().UTC()
	if _, err := f.st.InsertEvent(store.Event{Kind: publicip.EventKind, From: now.Add(-time.Hour),
		Details: []byte(`{"family":"ipv4","addr":"198.51.100.7","previous":"203.0.113.1"}`)}); err != nil {
		t.Fatal(err)
	}

	var p map[string]any
	f.getJSON("/api/digest/preview", &p)
	text, _ := p["text"].(string)
	if p["name"] != "daily summary" || !strings.Contains(text, "• alpha:") || !strings.Contains(text, "IPv4 203.0.113.1 → 198.51.100.7") {
		t.Fatalf("preview: %v", p)
	}

	// no channel configured: 409
	resp, _ := f.do(http.MethodPost, "/api/digest/send", "", nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("send without channels: %d", resp.StatusCode)
	}
	f.srv.digestSent = time.Time{}
	out.chs = []string{"webhook"}
	resp, body := f.do(http.MethodPost, "/api/digest/send", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("send: %d %s", resp.StatusCode, body)
	}
	if len(out.notes) != 1 || out.notes[0].RuleType != alert.RuleTypeDigest || out.notes[0].Title() != "pathwatch daily summary" {
		t.Fatalf("queued: %+v", out.notes)
	}
	resp, _ = f.do(http.MethodPost, "/api/digest/send", "", nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second send right away: %d", resp.StatusCode)
	}
}

func TestDigestSchedule(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	out := &fakeOutbox{chs: []string{"email"}}
	cur := time.Date(2026, 11, 19, 7, 59, 0, 0, time.UTC)
	f.srv.now = func() time.Time { return cur }
	if err := f.mgr.SetDigest(&config.DigestConfig{Schedule: "daily", Time: "08:00", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	dg := &digester{s: f.srv, out: out, log: f.srv.log}
	dg.tick() // first run marks the previous slot without sending
	if len(out.notes) != 0 {
		t.Fatal("first run must not send")
	}
	cur = cur.Add(2 * time.Minute)
	dg.tick()
	dg.tick()
	if len(out.notes) != 1 {
		t.Fatalf("one digest at 08:00, got %d", len(out.notes))
	}
	// a restart remembers the sent slot
	st, _ := f.st.Settings()
	if st[digestStateKey] != "2026-11-19T08:00:00Z" {
		t.Fatalf("state %q", st[digestStateKey])
	}
}

func TestPublicIPEndpoint(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	m := publicip.New(publicip.Options{Store: f.st, Lookup: func(_ context.Context, fam string) (netip.Addr, error) {
		if fam == publicip.IPv6 {
			return netip.MustParseAddr("2001:db8::7"), nil
		}
		return netip.MustParseAddr("203.0.113.1"), nil
	}})
	m.Configure(config.PublicIPConfig{Enabled: true, Interval: config.Duration(5 * time.Minute), Source: "opendns"})
	f.srv.d.PublicIP = m
	resp, body := f.do(http.MethodPost, "/api/public-ip/check", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("check: %d %s", resp.StatusCode, body)
	}
	var p struct {
		Enabled bool `json:"enabled"`
		Current []struct {
			Family string  `json:"family"`
			Addr   *string `json:"addr"`
		} `json:"current"`
		History []map[string]any `json:"history"`
	}
	f.getJSON("/api/public-ip", &p)
	if !p.Enabled || len(p.Current) != 2 || p.Current[0].Addr == nil || *p.Current[0].Addr != "203.0.113.1" || *p.Current[1].Addr != "2001:db8::7" {
		t.Fatalf("public ip: %+v", p)
	}
	if len(p.History) != 2 {
		t.Fatalf("history: %v", p.History)
	}
}

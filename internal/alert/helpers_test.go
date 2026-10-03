package alert

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

var t0 = time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC) // a Tuesday

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *fakeClock) Add(d time.Duration) { c.Set(c.Now().Add(d)) }

// memChan is an in-memory notification channel.
type memChan struct {
	mu  sync.Mutex
	got []Notification
	err error
}

func (m *memChan) Send(_ context.Context, n Notification) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.got = append(m.got, n)
	return nil
}

func (m *memChan) notes() []Notification {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Notification(nil), m.got...)
}

func (m *memChan) states() []string {
	var out []string
	for _, n := range m.notes() {
		out = append(out, n.State)
	}
	return out
}

type recSink struct {
	mu  sync.Mutex
	ids []int64
}

func (r *recSink) AlertChanged(id int64) {
	r.mu.Lock()
	r.ids = append(r.ids, id)
	r.mu.Unlock()
}

func (r *recSink) seen(id int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range r.ids {
		if v == id {
			return true
		}
	}
	return false
}

type harness struct {
	t    *testing.T
	st   *store.Store
	clk  *fakeClock
	eng  *RuleEngine
	snd  *Sender
	hook *memChan
	mail *memChan
	sink *recSink
	cfg  *config.Config
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml), func(string) string { return "" })
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// newHarness opens a store and builds an engine on a fake clock with in-memory channels. The
// config's notify section is irrelevant: webhook and email are replaced by memChans.
func newHarness(t *testing.T, yaml string) *harness {
	t.Helper()
	clk := &fakeClock{t: t0}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"), store.Options{
		Logger: quietLog(), NoBackground: true, FlushInterval: 20 * time.Millisecond, Now: clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	h := &harness{t: t, st: st, clk: clk, hook: &memChan{}, mail: &memChan{}, sink: &recSink{}}
	h.cfg = mustConfig(t, yaml)
	for _, n := range []string{"t1", "t2", "t3"} { // targets 1..3 exist in the store
		if _, err := st.SyncConfigTarget(n, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
	}
	h.build()
	return h
}

// build (re)creates the sender and engine on the same store: a process restart.
func (h *harness) build() {
	h.snd = NewSender(h.st, h.sink, quietLog(), h.clk.Now)
	h.snd.setChannels(map[string]channelSender{ChannelWebhook: h.hook, ChannelEmail: h.mail}, h.cfg.Alerts.Outbox.MaxAge.D())
	h.eng = NewRuleEngine(RuleEngineOptions{Store: h.st, Sink: h.sink, Config: h.cfg, Log: quietLog(), Now: h.clk.Now, SyncBaselines: true, Sender: h.snd})
}

func (h *harness) restart(yaml string) {
	h.t.Helper()
	if yaml != "" {
		h.cfg = mustConfig(h.t, yaml)
	}
	h.build()
}

// minute delivers one completed minute at bucket (the clock is set just after the analyzer
// would hand it over).
func (h *harness) minute(bucket time.Time, local LocalState, tms ...TargetMinute) {
	h.t.Helper()
	h.clk.Set(bucket.Add(time.Minute + 5*time.Second))
	h.eng.HandleMinute(Minute{Bucket: bucket, Targets: tms, Local: local})
}

func (h *harness) flush() {
	h.t.Helper()
	h.snd.ProcessDue(context.Background())
}

// alerts returns every alert, oldest first.
func (h *harness) alerts() []store.Alert {
	h.t.Helper()
	l, err := h.st.ListAlerts(1000, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	return l
}

func (h *harness) outbox() map[int64][]store.Delivery {
	h.t.Helper()
	l := h.alerts()
	ids := make([]int64, len(l))
	for i, a := range l {
		ids[i] = a.ID
	}
	d, err := h.st.Deliveries(ids)
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func lossMinute(id int64, name string, sent, lost int) TargetMinute {
	return TargetMinute{
		TargetID: id, Name: name, E2ESource: "icmp",
		E2E:  &Stat{Sent: sent, Lost: lost, LossPct: 100 * float64(lost) / float64(sent)},
		Hops: []HopMinute{{TTL: 1, Class: "ok"}},
	}
}

func degradedMinute(id int64, name string, ttl int) TargetMinute {
	return TargetMinute{TargetID: id, Name: name, Hops: []HopMinute{{TTL: 1, Class: "ok"}}, Degradation: &Degradation{StartTTL: ttl}}
}

func cleanMinute(id int64, name string) TargetMinute {
	return TargetMinute{TargetID: id, Name: name, Hops: []HopMinute{{TTL: 1, Class: "ok"}}}
}

func httpMinute(id int64, name string, probe int64, avgMS float64) TargetMinute {
	return TargetMinute{TargetID: id, Name: name, HTTP: []ProbeMinute{{
		ProbeID: probe, Type: "http", Label: "GET https://x/", N: 2, AvgTotalMS: avgMS, AvgTTFBMS: avgMS / 2, HaveAvg: true,
	}}}
}

func want(t *testing.T, cond bool, f string, a ...any) {
	t.Helper()
	if !cond {
		t.Fatalf(f, a...)
	}
}

const baseYAML = `
alerts:
  cooldown: 30m
  clear_ratio: 0.5
  rules:
    - name: end-loss
      type: final_hop_loss
      threshold_pct: 10
      window: 5m
    - name: path-degraded
      type: path_degradation
      sustain: 3m
`

func newBufLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

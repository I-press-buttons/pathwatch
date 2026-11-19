// Package selfmon watches pathwatch itself: free disk space of the data folder, the database
// size and writer, ICMP rounds that run late or fail to send, and (optionally) the clock offset
// against an NTP server. It turns these into issues for the Monitor health card, /api/system,
// /metrics and the monitor_health alert rule.
package selfmon

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
)

// Severities and states.
const (
	OK   = "ok"
	Warn = "warn"
	Crit = "crit"
)

const (
	collectEvery = 30 * time.Second
	window       = 10 * time.Minute // counters are judged over this window
	ntpEvery     = 15 * time.Minute
	ntpTimeout   = 5 * time.Second
	// lateShare is the share of late or dropped ICMP rounds in the window that counts as a problem.
	lateShare = 0.1
	minLate   = 3
)

// Store is what selfmon reads from the store.
type Store interface {
	File() string
	WriterAlive() bool
	Dropped() int64
	WriteErrors() int64
	LastCommit() time.Duration
}

// Scheduler is what selfmon reads from the scheduler.
type Scheduler interface {
	RoundStats() scheduler.RoundStats
	Healthy() (bool, string)
}

// Issue is one problem with the monitor.
type Issue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Clock is the latest clock check.
type Clock struct {
	Server   string        `json:"server"`
	Checked  time.Time     `json:"-"`
	Offset   time.Duration `json:"-"`
	RTT      time.Duration `json:"-"`
	Err      string        `json:"error,omitempty"`
	Measured bool          `json:"-"`
}

// Snapshot is the monitor's state at one time.
type Snapshot struct {
	At time.Time

	DiskKnown      bool
	DiskFreeBytes  int64
	DiskTotalBytes int64
	DiskFreePct    float64
	DataDir        string

	DBBytes  int64 // database file plus its WAL
	WALBytes int64

	WriterAlive   bool
	DroppedWrites int64 // totals since start
	WriteErrors   int64
	CommitTime    time.Duration

	Rounds          scheduler.RoundStats // totals since start
	RoundsWindow    scheduler.RoundStats // in the last `window`
	SchedulerOK     bool
	SchedulerReason string

	Clock Clock

	Goroutines int
	HeapBytes  uint64
	Uptime     time.Duration

	Issues []Issue
	State  string
}

type sample struct {
	at                 time.Time
	rounds             scheduler.RoundStats
	dropped, writeErrs int64
}

// Options configure a Monitor.
type Options struct {
	Store Store
	Sched Scheduler
	Log   *slog.Logger
	Now   func() time.Time
	// Disk overrides the disk space lookup (tests).
	Disk func(dir string) (free, total int64, ok bool)
	// NTP overrides the clock check (tests).
	NTP func(ctx context.Context, server string) (offset, rtt time.Duration, err error)
}

// Monitor collects snapshots in the background.
type Monitor struct {
	o       Options
	log     *slog.Logger
	started time.Time

	mu      sync.Mutex
	cfg     config.SystemConfig
	hist    []sample
	snap    *Snapshot
	clock   Clock
	ntpBusy bool

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// New creates a monitor.
func New(o Options) *Monitor {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Disk == nil {
		o.Disk = diskSpace
	}
	if o.NTP == nil {
		o.NTP = clockOffset
	}
	return &Monitor{o: o, log: o.Log, started: o.Now(), stop: make(chan struct{}), done: make(chan struct{})}
}

// Configure applies thresholds and the NTP server.
func (m *Monitor) Configure(c config.SystemConfig) {
	m.mu.Lock()
	changed := c.NTPServer != m.cfg.NTPServer
	m.cfg = c
	if changed {
		m.clock = Clock{Server: c.NTPServer}
	}
	m.mu.Unlock()
	if changed && c.NTPServer != "" {
		go m.checkClock()
	}
}

// Start launches the collection loop (it collects once right away).
func (m *Monitor) Start() {
	m.Collect()
	go m.loop()
}

// Close stops the loop.
func (m *Monitor) Close() {
	m.once.Do(func() { close(m.stop) })
	select {
	case <-m.done:
	case <-time.After(time.Second):
	}
}

func (m *Monitor) loop() {
	defer close(m.done)
	t := time.NewTicker(collectEvery)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.Collect()
		}
	}
}

// Snapshot returns the latest snapshot (collecting one if none exists yet).
func (m *Monitor) Snapshot() Snapshot {
	m.mu.Lock()
	s := m.snap
	m.mu.Unlock()
	if s == nil {
		return m.Collect()
	}
	return *s
}

// Health reports whether there is a problem and describes it (for the alert rule).
func (m *Monitor) Health() (bad bool, msg string) {
	s := m.Snapshot()
	if len(s.Issues) == 0 {
		return false, ""
	}
	parts := make([]string, 0, len(s.Issues))
	for _, i := range s.Issues {
		parts = append(parts, i.Message)
	}
	return true, strings.Join(parts, "; ")
}

func (m *Monitor) checkClock() {
	m.mu.Lock()
	server := m.cfg.NTPServer
	if server == "" || m.ntpBusy {
		m.mu.Unlock()
		return
	}
	m.ntpBusy = true
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), ntpTimeout)
	off, rtt, err := m.o.NTP(ctx, server)
	cancel()
	c := Clock{Server: server, Checked: m.o.Now()}
	if err != nil {
		c.Err = err.Error()
	} else {
		c.Offset, c.RTT, c.Measured = off, rtt, true
	}
	m.mu.Lock()
	m.ntpBusy = false
	if m.cfg.NTPServer == server {
		m.clock = c
	}
	m.mu.Unlock()
}

// Collect takes a snapshot now.
func (m *Monitor) Collect() Snapshot {
	now := m.o.Now()
	m.mu.Lock()
	cfg := m.cfg
	clock := m.clock
	m.mu.Unlock()
	if cfg.NTPServer != "" && (clock.Checked.IsZero() || now.Sub(clock.Checked) >= ntpEvery) {
		go m.checkClock()
	}

	s := Snapshot{At: now, Clock: clock, Uptime: now.Sub(m.started), Goroutines: runtime.NumGoroutine(), State: OK}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.HeapBytes = ms.HeapAlloc

	var cur sample
	cur.at = now
	if st := m.o.Store; st != nil {
		f := st.File()
		s.DataDir = filepath.Dir(f)
		if abs, err := filepath.Abs(s.DataDir); err == nil {
			s.DataDir = abs
		}
		if fi, err := os.Stat(f); err == nil {
			s.DBBytes = fi.Size()
		}
		if fi, err := os.Stat(f + "-wal"); err == nil {
			s.WALBytes = fi.Size()
			s.DBBytes += fi.Size()
		}
		s.WriterAlive = st.WriterAlive()
		s.DroppedWrites, s.WriteErrors, s.CommitTime = st.Dropped(), st.WriteErrors(), st.LastCommit()
		cur.dropped, cur.writeErrs = s.DroppedWrites, s.WriteErrors
		if free, total, ok := m.o.Disk(s.DataDir); ok && total > 0 {
			s.DiskKnown, s.DiskFreeBytes, s.DiskTotalBytes = true, free, total
			s.DiskFreePct = float64(free) / float64(total) * 100
		}
	}
	if sc := m.o.Sched; sc != nil {
		s.Rounds = sc.RoundStats()
		cur.rounds = s.Rounds
		s.SchedulerOK, s.SchedulerReason = sc.Healthy()
	} else {
		s.SchedulerOK = true
	}

	m.mu.Lock()
	m.hist = append(m.hist, cur)
	cut := 0
	for cut < len(m.hist)-1 && now.Sub(m.hist[cut].at) > window {
		cut++
	}
	m.hist = m.hist[cut:]
	base := m.hist[0]
	m.mu.Unlock()

	s.RoundsWindow = scheduler.RoundStats{
		Rounds: cur.rounds.Rounds - base.rounds.Rounds, Late: cur.rounds.Late - base.rounds.Late,
		Discarded: cur.rounds.Discarded - base.rounds.Discarded, SendErrors: cur.rounds.SendErrors - base.rounds.SendErrors,
	}
	s.Issues = issues(s, cfg, cur.dropped-base.dropped, cur.writeErrs-base.writeErrs)
	for _, i := range s.Issues {
		if i.Severity == Crit {
			s.State = Crit
		} else if s.State == OK {
			s.State = Warn
		}
	}
	m.mu.Lock()
	m.snap = &s
	m.mu.Unlock()
	return s
}

// issues judges a snapshot. dropped and writeErrs are the counts within the window.
func issues(s Snapshot, cfg config.SystemConfig, dropped, writeErrs int64) []Issue {
	var out []Issue
	add := func(code, sev, f string, a ...any) {
		out = append(out, Issue{Code: code, Severity: sev, Message: fmt.Sprintf(f, a...)})
	}
	if s.DiskKnown {
		low := s.DiskFreePct < cfg.DiskFreeMinPct || (cfg.DiskFreeMinBytes > 0 && s.DiskFreeBytes < cfg.DiskFreeMinBytes)
		if low {
			sev := Warn
			if s.DiskFreePct < 1 || s.DiskFreeBytes < 50<<20 {
				sev = Crit
			}
			add("disk_low", sev, "Low disk space for the database: %s free (%.1f%%) in %s", Bytes(s.DiskFreeBytes), s.DiskFreePct, s.DataDir)
		}
	}
	if !s.WriterAlive && s.DataDir != "" {
		add("writer_stalled", Crit, "The database writer has not committed for over 30 seconds")
	}
	if writeErrs > 0 {
		add("write_errors", Crit, "%d database %s failed in the last 10 minutes (see the log)", writeErrs, plural(writeErrs, "write", "writes"))
	}
	if dropped > 0 {
		add("writes_dropped", Warn, "%d measurements were dropped in the last 10 minutes because the database could not keep up", dropped)
	}
	if !s.SchedulerOK && s.SchedulerReason != "" {
		add("scheduler", Crit, "Probing has stalled: %s", s.SchedulerReason)
	}
	rw := s.RoundsWindow
	if bad := rw.Late + rw.Discarded; bad >= minLate && float64(bad) > lateShare*float64(rw.Rounds+rw.Discarded) {
		add("rounds_late", Warn, "%d of %d ICMP rounds in the last 10 minutes ran late or stalled: this machine may be overloaded or suspending", bad, rw.Rounds+rw.Discarded)
	}
	if rw.SendErrors >= minLate {
		add("send_errors", Warn, "%d ICMP rounds in the last 10 minutes could not send probes (check the network interface and NET_RAW)", rw.SendErrors)
	}
	if c := s.Clock; c.Measured && cfg.ClockMaxOffset > 0 && absDur(c.Offset) > cfg.ClockMaxOffset.D() {
		dir := "behind"
		if c.Offset < 0 {
			dir = "ahead of"
		}
		add("clock_offset", Warn, "This machine's clock is %s %s %s: timelines and alert times are skewed", fmtOffset(absDur(c.Offset)), dir, c.Server)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Severity == Crit && out[j].Severity != Crit })
	return out
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func fmtOffset(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Bytes formats a byte count ("1.2 GB").
func Bytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	exp := int(math.Floor(math.Log(float64(n)) / math.Log(unit)))
	if exp > 5 {
		exp = 5
	}
	v := float64(n) / math.Pow(unit, float64(exp))
	return fmt.Sprintf("%.1f %cB", v, "kMGTP"[exp-1])
}

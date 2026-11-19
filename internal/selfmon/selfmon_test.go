package selfmon

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
)

type fakeStore struct {
	file          string
	alive         bool
	dropped, errs int64
}

func (f *fakeStore) File() string              { return f.file }
func (f *fakeStore) WriterAlive() bool         { return f.alive }
func (f *fakeStore) Dropped() int64            { return f.dropped }
func (f *fakeStore) WriteErrors() int64        { return f.errs }
func (f *fakeStore) LastCommit() time.Duration { return time.Millisecond }

type fakeSched struct{ st scheduler.RoundStats }

func (f *fakeSched) RoundStats() scheduler.RoundStats { return f.st }
func (f *fakeSched) Healthy() (bool, string)          { return true, "" }

func cfg() config.SystemConfig {
	return config.SystemConfig{DiskFreeMinPct: 5, DiskFreeMinBytes: 500 << 20, ClockMaxOffset: config.Duration(2 * time.Second)}
}

func codes(s Snapshot) string {
	var c []string
	for _, i := range s.Issues {
		c = append(c, i.Code+":"+i.Severity)
	}
	return strings.Join(c, ",")
}

func TestHealthyAndProblems(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st := &fakeStore{file: filepath.Join(t.TempDir(), "pathwatch.db"), alive: true}
	sc := &fakeSched{}
	free := int64(50 << 30)
	m := New(Options{Store: st, Sched: sc, Now: func() time.Time { return now },
		Disk: func(string) (int64, int64, bool) { return free, 100 << 30, true }})
	m.Configure(cfg())
	if s := m.Collect(); s.State != OK || len(s.Issues) != 0 {
		t.Fatalf("healthy: %s %s", s.State, codes(s))
	}
	if bad, _ := m.Health(); bad {
		t.Fatal("Health must be fine")
	}

	// a minute later: low disk, a failed write, many late rounds
	now = now.Add(time.Minute)
	free = 3 << 30
	st.errs = 2
	sc.st = scheduler.RoundStats{Rounds: 30, Late: 10}
	s := m.Collect()
	if got := codes(s); got != "write_errors:crit,disk_low:warn,rounds_late:warn" {
		t.Fatalf("issues: %s", got)
	}
	if s.State != Crit {
		t.Fatalf("state %s", s.State)
	}
	bad, msg := m.Health()
	if !bad || !strings.Contains(msg, "Low disk space") {
		t.Fatalf("health message %q", msg)
	}

	// the window moves on: old write errors and late rounds no longer count
	now = now.Add(11 * time.Minute)
	m.Collect()
	now = now.Add(30 * time.Second)
	free = 50 << 30
	sc.st.Rounds += 300
	if s := m.Collect(); len(s.Issues) != 0 {
		t.Fatalf("recovered, got %s", codes(s))
	}
}

func TestClockOffset(t *testing.T) {
	m := New(Options{Disk: func(string) (int64, int64, bool) { return 0, 0, false },
		NTP: func(context.Context, string) (time.Duration, time.Duration, error) {
			return -5 * time.Second, 10 * time.Millisecond, nil
		}})
	m.Configure(config.SystemConfig{NTPServer: "ntp.example", ClockMaxOffset: config.Duration(2 * time.Second)})
	m.checkClock()
	s := m.Collect()
	if codes(s) != "clock_offset:warn" || !strings.Contains(s.Issues[0].Message, "5.0s ahead of ntp.example") {
		t.Fatalf("clock: %+v", s.Issues)
	}
	m2 := New(Options{NTP: func(context.Context, string) (time.Duration, time.Duration, error) {
		return 0, 0, errors.New("timeout")
	}})
	m2.Configure(config.SystemConfig{NTPServer: "ntp.example", ClockMaxOffset: config.Duration(2 * time.Second)})
	m2.checkClock()
	if s := m2.Collect(); s.Clock.Err != "timeout" || len(s.Issues) != 0 {
		t.Fatalf("an unreachable NTP server is shown, not an issue: %+v", s)
	}
}

func TestBytes(t *testing.T) {
	for in, want := range map[int64]string{999: "999 B", 1500: "1.5 kB", 3 << 30: "3.2 GB"} {
		if got := Bytes(in); got != want {
			t.Errorf("Bytes(%d) = %q, want %q", in, got, want)
		}
	}
}

package alert

import (
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func TestMaintenanceWindowActive(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tzdata")
	}
	w := MaintenanceWindows{{Name: "isp", Days: []string{"mon", "tue"}, Start: "03:00", End: "04:00", Timezone: "America/New_York"}}
	// Monday 2026-01-05 03:30 New York
	in := time.Date(2026, 1, 5, 3, 30, 0, 0, ny)
	act := w.Active(in)
	if len(act) != 1 || act[0].Name != "isp" || !act[0].Start.Equal(time.Date(2026, 1, 5, 3, 0, 0, 0, ny)) || !act[0].End.Equal(time.Date(2026, 1, 5, 4, 0, 0, 0, ny)) {
		t.Fatalf("active: %+v", act)
	}
	if _, ok := w.Silenced(in); !ok {
		t.Error("should be silenced")
	}
	for _, out := range []time.Time{
		time.Date(2026, 1, 5, 4, 0, 0, 0, ny),  // end is exclusive
		time.Date(2026, 1, 5, 2, 59, 0, 0, ny), // before
		time.Date(2026, 1, 7, 3, 30, 0, 0, ny), // Wednesday
	} {
		if len(w.Active(out)) != 0 {
			t.Errorf("unexpectedly active at %v", out)
		}
	}
	// the same instant expressed in UTC gives the same answer (time zone is the window's)
	if len(w.Active(in.UTC())) != 1 {
		t.Error("UTC instant")
	}
}

func TestMaintenanceWindowCrossesMidnight(t *testing.T) {
	w := MaintenanceWindows{{Name: "late", Days: []string{"fri"}, Start: "23:00", End: "01:00", Timezone: "UTC"}}
	fri := time.Date(2026, 1, 9, 23, 30, 0, 0, time.UTC) // Friday
	sat := time.Date(2026, 1, 10, 0, 30, 0, 0, time.UTC)
	if len(w.Active(fri)) != 1 || len(w.Active(sat)) != 1 {
		t.Fatalf("fri=%v sat=%v", w.Active(fri), w.Active(sat))
	}
	a := w.Active(sat)[0]
	if !a.Start.Equal(time.Date(2026, 1, 9, 23, 0, 0, 0, time.UTC)) || !a.End.Equal(time.Date(2026, 1, 10, 1, 0, 0, 0, time.UTC)) {
		t.Errorf("window: %+v", a)
	}
	if len(w.Active(time.Date(2026, 1, 10, 1, 0, 0, 0, time.UTC))) != 0 {
		t.Error("end exclusive")
	}
	if len(w.Active(time.Date(2026, 1, 10, 23, 30, 0, 0, time.UTC))) != 0 {
		t.Error("saturday night is not listed")
	}
	// start == end means all day
	all := MaintenanceWindows{{Name: "all", Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}, Start: "00:00", End: "00:00"}}
	if len(all.Active(time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC))) != 1 {
		t.Error("all day")
	}
}

func TestMaintenanceWindowsFromConfig(t *testing.T) {
	cfg, err := config.Parse([]byte("alerts:\n  maintenance_windows:\n    - name: n\n      days: [sun]\n      start: \"10:00\"\n      end: \"11:00\"\n"), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	w := MaintenanceWindows(cfg.Alerts.MaintenanceWindows)
	if len(w.Active(time.Date(2026, 1, 4, 10, 30, 0, 0, time.UTC))) != 1 { // a Sunday
		t.Error("config window inactive")
	}
}

func TestSilenceScope(t *testing.T) {
	now := time.Now()
	tid := int64(3)
	rule := "http-down"
	s := SilenceScope{TargetID: &tid, Rule: &rule, Start: now.Add(-time.Hour), End: now.Add(time.Hour)}
	if !s.Covers(now, 3, "http-down") || s.Covers(now, 4, "http-down") || s.Covers(now, 3, "other") {
		t.Error("scoped silence")
	}
	if s.Covers(now.Add(2*time.Hour), 3, "http-down") || s.Covers(now.Add(-2*time.Hour), 3, "http-down") {
		t.Error("time bounds")
	}
	all := SilenceScope{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
	if !all.Covers(now, 99, "anything") {
		t.Error("global silence")
	}
}

func TestNopEngine(t *testing.T) {
	var e Engine = Nop{}
	e.HandleMinute(Minute{})
	e.HandleProbe(ProbeSample{})
	e.Close()
}

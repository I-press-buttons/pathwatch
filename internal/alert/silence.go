package alert

import (
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

// Window is one occurrence of a maintenance window.
type Window struct {
	Name  string
	Start time.Time // UTC
	End   time.Time // UTC
}

// MaintenanceWindows evaluates the recurring windows from config.
type MaintenanceWindows []config.MaintenanceWindow

// Active returns the occurrences of the windows that are in effect at now. A window whose end
// is not after its start crosses midnight (it starts on a listed day and ends the next day).
func (m MaintenanceWindows) Active(now time.Time) []Window {
	var out []Window
	for _, w := range m {
		loc := time.UTC
		if w.Timezone != "" {
			if l, err := time.LoadLocation(w.Timezone); err == nil {
				loc = l
			}
		}
		startMin, ok1 := config.ParseClock(w.Start)
		endMin, ok2 := config.ParseClock(w.End)
		if !ok1 || !ok2 {
			continue
		}
		days := map[time.Weekday]bool{}
		for _, d := range w.Days {
			if wd, ok := config.ParseWeekday(d); ok {
				days[wd] = true
			}
		}
		local := now.In(loc)
		for off := 0; off >= -1; off-- {
			d := local.AddDate(0, 0, off)
			if !days[d.Weekday()] {
				continue
			}
			start := time.Date(d.Year(), d.Month(), d.Day(), startMin/60, startMin%60, 0, 0, loc)
			end := time.Date(d.Year(), d.Month(), d.Day(), endMin/60, endMin%60, 0, 0, loc)
			if endMin <= startMin {
				end = end.AddDate(0, 0, 1)
			}
			if !now.Before(start) && now.Before(end) {
				out = append(out, Window{Name: w.Name, Start: start.UTC(), End: end.UTC()})
				break
			}
		}
	}
	return out
}

// Silenced reports whether a maintenance window is active (windows apply to every target and rule).
func (m MaintenanceWindows) Silenced(now time.Time) (Window, bool) {
	if a := m.Active(now); len(a) > 0 {
		return a[0], true
	}
	return Window{}, false
}

// SilenceScope is the scope of a UI silence: nil target / rule mean "all".
type SilenceScope struct {
	TargetID *int64
	Rule     *string
	Start    time.Time
	End      time.Time
}

// Covers reports whether the silence applies to (targetID, rule) at now.
func (s SilenceScope) Covers(now time.Time, targetID int64, rule string) bool {
	if now.Before(s.Start) || !now.Before(s.End) {
		return false
	}
	if s.TargetID != nil && *s.TargetID != targetID {
		return false
	}
	if s.Rule != nil && *s.Rule != rule {
		return false
	}
	return true
}

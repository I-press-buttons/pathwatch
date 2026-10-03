package analyze

import "time"

// TargetHealth is one target's local-connectivity evidence for a window.
type TargetHealth struct {
	TargetID int64
	// Gateway1/Gateway2 report that hop 1 / hop 2 stopped responding entirely in the window
	// (100% loss although the hop has answered before).
	Gateway1Down bool
	Gateway2Down bool
	// E2EKnown is true when the target has an end-to-end signal this window; E2EFailing is
	// true when that signal is degraded (loss above threshold or probe failures).
	E2EKnown   bool
	E2EFailing bool
}

// LocalState is the outcome of local outage detection.
type LocalState struct {
	Down   bool
	Since  time.Time
	Reason string // "gateway" | "all_targets"
}

// LocalOutageDetector decides whether the local connection (not any single target) is down:
// either a target's hop 1 or hop 2 stopped responding while its end-to-end signal also fails, or
// every target with an end-to-end signal fails in the same window (needs at least MinTargets of
// them, so a single failing target is not blamed on the local link).
// A single local_connectivity alert replaces per-target alerts while it lasts.
type LocalOutageDetector struct {
	MinTargets int // default 2
	DownAfter  int // consecutive bad windows to declare an outage (default 1)
	UpAfter    int // consecutive good windows to end it (default 2)

	state LocalState
	bad   int
	good  int
	first time.Time
}

// NewLocalOutageDetector returns a detector with default parameters.
func NewLocalOutageDetector() *LocalOutageDetector {
	return &LocalOutageDetector{MinTargets: 2, DownAfter: 1, UpAfter: 2}
}

// State returns the current state.
func (d *LocalOutageDetector) State() LocalState { return d.state }

// Observe evaluates one window starting at `at` and returns the new state and whether it changed.
func (d *LocalOutageDetector) Observe(at time.Time, targets []TargetHealth) (LocalState, bool) {
	reason := ""
	known, failing := 0, 0
	for _, t := range targets {
		if t.E2EKnown {
			known++
			if t.E2EFailing {
				failing++
			}
		}
		if (t.Gateway1Down || t.Gateway2Down) && t.E2EKnown && t.E2EFailing {
			reason = "gateway"
		}
	}
	minT := d.MinTargets
	if minT < 1 {
		minT = 2
	}
	if reason == "" && known >= minT && failing == known {
		reason = "all_targets"
	}
	bad := reason != ""
	downAfter, upAfter := d.DownAfter, d.UpAfter
	if downAfter < 1 {
		downAfter = 1
	}
	if upAfter < 1 {
		upAfter = 1
	}
	changed := false
	if !d.state.Down {
		if !bad {
			d.bad = 0
			return d.state, false
		}
		if d.bad == 0 {
			d.first = at
		}
		d.bad++
		if d.bad >= downAfter {
			d.state = LocalState{Down: true, Since: d.first, Reason: reason}
			d.bad, d.good = 0, 0
			changed = true
		}
		return d.state, changed
	}
	if bad {
		d.good = 0
		return d.state, false
	}
	d.good++
	if d.good >= upAfter {
		d.state = LocalState{}
		d.bad, d.good = 0, 0
		changed = true
	}
	return d.state, changed
}

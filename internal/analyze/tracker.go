package analyze

import "time"

// Key identifies one classification stream: a hop of a target and a class.
type Key struct {
	Target int64
	TTL    int
	Class  string // ClassRateLimited or ClassDegraded
}

// Transition is a state change of a Tracker stream.
type Transition struct {
	Key
	Start bool      // true = began, false = ended
	At    time.Time // start of the first bad window (Start) or of the first clean window (end)
}

type trackState struct {
	active    bool
	bad       int       // consecutive windows with the class (while inactive)
	clean     int       // consecutive windows without it (while active)
	firstBad  time.Time // start of the first window of the current run
	firstGood time.Time
}

// Tracker turns per-window classifications into start/end state transitions with hysteresis:
// a class must persist StartAfter consecutive windows to begin and be absent EndAfter windows to
// end. A permanently lossy router therefore produces one long annotation instead of a flood.
type Tracker struct {
	StartAfter int // default 2
	EndAfter   int // default 3
	m          map[Key]*trackState
}

// NewTracker returns a tracker with default hysteresis.
func NewTracker() *Tracker { return &Tracker{StartAfter: 2, EndAfter: 3, m: map[Key]*trackState{}} }

// Observe records whether, in the window starting at `at`, the stream is in its class, and
// returns the transition this causes, if any.
func (t *Tracker) Observe(k Key, inClass bool, at time.Time) *Transition {
	startAfter, endAfter := t.StartAfter, t.EndAfter
	if startAfter < 1 {
		startAfter = 1
	}
	if endAfter < 1 {
		endAfter = 1
	}
	s := t.m[k]
	if s == nil {
		s = &trackState{}
		t.m[k] = s
	}
	if !s.active {
		if !inClass {
			s.bad = 0
			return nil
		}
		if s.bad == 0 {
			s.firstBad = at
		}
		s.bad++
		if s.bad >= startAfter {
			s.active, s.bad, s.clean = true, 0, 0
			return &Transition{Key: k, Start: true, At: s.firstBad}
		}
		return nil
	}
	if inClass {
		s.clean = 0
		return nil
	}
	if s.clean == 0 {
		s.firstGood = at
	}
	s.clean++
	if s.clean >= endAfter {
		s.active, s.bad, s.clean = false, 0, 0
		return &Transition{Key: k, Start: false, At: s.firstGood}
	}
	return nil
}

// Active reports whether the stream is currently in its class.
func (t *Tracker) Active(k Key) bool {
	s := t.m[k]
	return s != nil && s.active
}

// Restore marks a stream active (resuming open events after a restart).
func (t *Tracker) Restore(k Key) {
	t.m[k] = &trackState{active: true}
}

// Keys returns every key with state, optionally only the active ones.
func (t *Tracker) Keys(activeOnly bool) []Key {
	var out []Key
	for k, s := range t.m {
		if !activeOnly || s.active {
			out = append(out, k)
		}
	}
	return out
}

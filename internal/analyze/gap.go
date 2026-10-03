package analyze

import "time"

// Gap is a period during which pathwatch was not probing: "no data", never loss.
type Gap struct {
	From, To time.Time
	Reason   string // GapStalled or GapClockJump
}

// Gap reasons.
const (
	GapStalled   = "stalled"
	GapClockJump = "clock_jump"
)

// GapDetector watches the timestamps of consecutive rounds of one target. A gap is reported
// when the time between rounds exceeds Factor x Interval (process stopped, container or host
// suspended, scheduler stalled) or when the wall clock moved differently from the monotonic
// clock (clock jump, or a suspend that the monotonic clock did not count).
type GapDetector struct {
	Interval time.Duration
	Factor   float64       // default 3
	ClockTol time.Duration // allowed wall vs monotonic mismatch; default max(1s, Interval/2)

	have bool
	last time.Time // previous observation, including its monotonic reading when present
}

// NewGapDetector returns a detector for rounds expected every interval.
func NewGapDetector(interval time.Duration) *GapDetector {
	return &GapDetector{Interval: interval, Factor: 3}
}

func (g *GapDetector) tol() time.Duration {
	if g.ClockTol > 0 {
		return g.ClockTol
	}
	t := g.Interval / 2
	if t < time.Second {
		t = time.Second
	}
	return t
}

// Observe feeds the current time as returned by time.Now (it carries a monotonic reading) and
// returns the gap that ended at now, if any.
func (g *GapDetector) Observe(now time.Time) *Gap {
	if !g.have {
		g.have, g.last = true, now
		return nil
	}
	mono := now.Sub(g.last)                   // monotonic when both readings have one
	wall := now.Round(0).Sub(g.last.Round(0)) // wall clock only
	gap := g.evaluate(g.last.Round(0), now.Round(0), wall, mono)
	g.last = now
	return gap
}

// ObserveAt is the testable form: wall is the wall-clock time of the observation and mono the
// monotonic time elapsed since the previous call.
func (g *GapDetector) ObserveAt(wall time.Time, mono time.Duration) *Gap {
	if !g.have {
		g.have, g.last = true, wall
		return nil
	}
	gap := g.evaluate(g.last, wall, wall.Sub(g.last), mono)
	g.last = wall
	return gap
}

func (g *GapDetector) evaluate(prev, cur time.Time, wall, mono time.Duration) *Gap {
	factor := g.Factor
	if factor <= 0 {
		factor = 3
	}
	diff := wall - mono
	if diff < 0 {
		diff = -diff
	}
	if diff > g.tol() {
		from, to := prev, cur
		if to.Before(from) {
			from, to = to, from
		}
		return &Gap{From: from, To: to, Reason: GapClockJump}
	}
	if mono > time.Duration(factor*float64(g.Interval)) {
		return &Gap{From: prev, To: cur, Reason: GapStalled}
	}
	return nil
}

// Reset forgets the previous observation (the next Observe starts fresh).
func (g *GapDetector) Reset() { g.have = false }

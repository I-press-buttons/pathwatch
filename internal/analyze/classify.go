package analyze

// Hop classes. ClassOK is also used for the destination hop; the API layer renders it as
// "destination".
const (
	ClassOK          = "ok"
	ClassRateLimited = "rate_limited"
	ClassDegraded    = "degraded"
	ClassNoReply     = "no_reply"
)

// Params tune the classifier.
type Params struct {
	// LossThreshold is the loss percentage above which a signal counts as degraded (default 5).
	LossThreshold float64
	// MinSamples is the minimum number of probes in the window before a signal is judged (default 5).
	MinSamples int
}

// DefaultParams returns the default classifier parameters.
func DefaultParams() Params { return Params{LossThreshold: 5, MinSamples: 5} }

func (p Params) norm() Params {
	if p.LossThreshold <= 0 {
		p.LossThreshold = 5
	}
	if p.MinSamples <= 0 {
		p.MinSamples = 5
	}
	return p
}

// HopStat is one hop's statistics over an evaluation window (default one minute).
type HopStat struct {
	TTL           int
	Sent, Lost    int
	AvgMs         float64
	HaveAvg       bool
	Upper         float64 // upper edge of the latency baseline band; 0 = no band yet (loss only)
	EverResponded bool    // the hop has answered before; a hop that never does is "no_reply", not degraded
	IsDest        bool
}

// SignalStat is a downstream signal that is not an ICMP hop: the TCP or HTTP probe of the target.
type SignalStat struct {
	Name    string
	Sent    int
	Failed  int
	AvgMs   float64
	HaveAvg bool
	Upper   float64
}

// State of one signal in a window.
type State int

// Signal states.
const (
	StateNone     State = iota // no data, too few samples, or a hop that never answers
	StateClean                 // loss and latency within bounds
	StateDegraded              // loss above threshold or latency above its band
)

func judge(p Params, sent, bad int, avg float64, haveAvg bool, upper float64) State {
	if sent < p.MinSamples {
		return StateNone
	}
	if 100*float64(bad)/float64(sent) > p.LossThreshold {
		return StateDegraded
	}
	if haveAvg && upper > 0 && avg > upper {
		return StateDegraded
	}
	return StateClean
}

func hopState(p Params, h HopStat) State {
	if h.Sent > 0 && h.Lost == h.Sent && !h.EverResponded {
		return StateNone // permanently silent router: neither clean nor degraded
	}
	return judge(p, h.Sent, h.Lost, h.AvgMs, h.HaveAvg, h.Upper)
}

// HopClass is the classification of one hop.
type HopClass struct {
	TTL      int
	Class    string
	Degraded bool // the hop itself exceeded loss/latency bounds (before considering downstream)
}

// Result of classifying one window.
type Result struct {
	Hops []HopClass
	// Real is true when at least one hop is degraded together with every downstream signal.
	Real bool
	// StartTTL is the earliest degraded hop of a real degradation ("problem begins at hop k").
	StartTTL int
}

// ClassOf returns the class of a TTL (ClassNoReply when unknown).
func (r Result) ClassOf(ttl int) string {
	for _, h := range r.Hops {
		if h.TTL == ttl {
			return h.Class
		}
	}
	return ClassNoReply
}

// Classify implements the hop classification of the spec's "central insight".
//
// For each hop k with loss above the threshold or latency above its baseline band:
//   - if ANY downstream signal is clean over the same window (some hop j > k, the destination's
//     Echo Reply, or the target's TCP/HTTP probe), hop k is rate-limited: annotate, never alert;
//   - if hop k AND EVERY downstream signal are degraded, the degradation is real and begins at
//     the earliest such hop.
//
// hops must be in ascending TTL order. Signals without enough samples, and hops that never
// answer, are ignored (neither clean nor degraded).
func Classify(p Params, hops []HopStat, signals []SignalStat) Result {
	p = p.norm()
	states := make([]State, len(hops))
	for i, h := range hops {
		states[i] = hopState(p, h)
	}
	sigStates := make([]State, len(signals))
	for i, s := range signals {
		sigStates[i] = judge(p, s.Sent, s.Failed, s.AvgMs, s.HaveAvg, s.Upper)
	}
	sigClean := false
	for _, st := range sigStates {
		if st == StateClean {
			sigClean = true
		}
	}
	// cleanBelow[i] reports whether any hop with index > i is clean.
	cleanBelow := make([]bool, len(hops)+1)
	for i := len(hops) - 1; i >= 0; i-- {
		cleanBelow[i] = cleanBelow[i+1] || (i+1 < len(hops) && states[i+1] == StateClean)
	}
	res := Result{Hops: make([]HopClass, len(hops))}
	for i, h := range hops {
		hc := HopClass{TTL: h.TTL, Class: ClassOK, Degraded: states[i] == StateDegraded}
		switch {
		case hc.Degraded:
			if cleanBelow[i] || sigClean {
				hc.Class = ClassRateLimited
			} else {
				hc.Class = ClassDegraded
				if !res.Real {
					res.Real, res.StartTTL = true, h.TTL
				}
			}
		case h.Sent > 0 && h.Lost == h.Sent && !h.EverResponded:
			hc.Class = ClassNoReply
		}
		res.Hops[i] = hc
	}
	return res
}

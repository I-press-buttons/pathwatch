package scheduler

import (
	"net/netip"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/store"
)

// RespEntry is one responder seen at a TTL, with how many replies it sent.
type RespEntry struct {
	Addr  netip.Addr
	Count int
}

// Version is a path version: the resolved destination plus, per TTL, the set of responders
// (several responders at one TTL mean per-packet load balancing or multiple router interfaces,
// not a path change). Responder order is first-seen order and is stable: a responder's position
// is the index stored in the round blobs.
type Version struct {
	PathID  int64 // database id, assigned by the scheduler after Started
	IP      netip.Addr
	DestTTL int // 0 = the destination has not answered ICMP
	Resp    map[int][]*RespEntry
}

func newVersion(ip netip.Addr) *Version {
	return &Version{IP: ip, Resp: map[int][]*RespEntry{}}
}

// IndexOf returns the position of addr in the TTL's responder set, or -1.
func (v *Version) IndexOf(ttl int, a netip.Addr) int {
	for i, r := range v.Resp[ttl] {
		if r.Addr == a {
			return i
		}
	}
	return -1
}

// Shares returns each responder's fraction of the replies at its TTL.
func (v *Version) Shares() []store.ShareUpdate {
	var out []store.ShareUpdate
	for ttl, list := range v.Resp {
		total := 0
		for _, r := range list {
			total += r.Count
		}
		if total == 0 {
			continue
		}
		for i, r := range list {
			out = append(out, store.ShareUpdate{TTL: ttl, Idx: i, Share: float64(r.Count) / float64(total)})
		}
	}
	return out
}

// Obs is one observed round.
type Obs struct {
	TS      time.Time
	IP      netip.Addr
	DestTTL int
	Hops    []store.Hop // Addr is valid for responding hops; Resp is filled in by the tracker
}

// Added is a responder newly added to a version's set.
type Added struct {
	Version *Version
	TTL     int
	Idx     int
	Addr    netip.Addr
}

// Placed is a round assigned to a path version, ready to be stored.
type Placed struct {
	Obs     Obs
	Version *Version
}

// Decision is what the tracker decided after observing a round.
type Decision struct {
	// Started is non-nil when a new path version began; Previous is the version it replaced
	// (nil for the very first one). Handle it before Added and Placed.
	Started  *Version
	Previous *Version
	Added    []Added
	Placed   []Placed
	// DestTTLSet lists versions whose destination TTL became known in this decision.
	DestTTLSet []*Version
}

// PathTracker versions the path of one target with debouncing: a round only counts as different
// when it shows a responder that is not in the current version's set for that TTL (or a different
// destination TTL, or a new resolved IP). A new version starts only after Debounce consecutive
// different rounds; a single odd reply is merged into the responder sets instead. Rounds that
// might belong to a new version are held back (at most Debounce-1 of them) until the decision.
type PathTracker struct {
	Debounce int // default 3
	cur      *Version
	pending  []Obs
}

// NewPathTracker returns a tracker with the default debounce of 3 rounds.
func NewPathTracker() *PathTracker { return &PathTracker{Debounce: 3} }

// Current returns the current version (nil before the first round).
func (t *PathTracker) Current() *Version { return t.cur }

// Resume continues an existing version after a restart.
func (t *PathTracker) Resume(v *Version) { t.cur, t.pending = v, nil }

// Pending is the number of rounds held back awaiting the debounce decision.
func (t *PathTracker) Pending() int { return len(t.pending) }

func (v *Version) differs(o Obs) bool {
	if v.DestTTL > 0 && o.DestTTL > 0 && v.DestTTL != o.DestTTL {
		return true
	}
	for _, h := range o.Hops {
		if !h.Responded() || !h.Addr.IsValid() {
			continue
		}
		set := v.Resp[h.TTL]
		if len(set) == 0 {
			continue // a hop that never answered before is not a path change
		}
		if v.IndexOf(h.TTL, h.Addr) < 0 {
			return true
		}
	}
	return false
}

// place assigns the round to v: it fills in responder indices, grows the responder sets and
// records the destination TTL.
func (t *PathTracker) place(d *Decision, v *Version, o Obs) {
	hops := make([]store.Hop, len(o.Hops))
	copy(hops, o.Hops)
	for i := range hops {
		h := &hops[i]
		if !h.Responded() || !h.Addr.IsValid() {
			h.Resp = 0
			continue
		}
		idx := v.IndexOf(h.TTL, h.Addr)
		if idx < 0 {
			v.Resp[h.TTL] = append(v.Resp[h.TTL], &RespEntry{Addr: h.Addr})
			idx = len(v.Resp[h.TTL]) - 1
			d.Added = append(d.Added, Added{Version: v, TTL: h.TTL, Idx: idx, Addr: h.Addr})
		}
		v.Resp[h.TTL][idx].Count++
		h.Resp = idx + 1
	}
	if v.DestTTL == 0 && o.DestTTL > 0 {
		v.DestTTL = o.DestTTL
		d.DestTTLSet = append(d.DestTTLSet, v)
	}
	o.Hops = hops
	d.Placed = append(d.Placed, Placed{Obs: o, Version: v})
}

func (t *PathTracker) start(d *Decision, o Obs, rounds []Obs) {
	v := newVersion(o.IP)
	d.Previous = t.cur
	d.Started = v
	t.cur = v
	for _, r := range rounds {
		t.place(d, v, r)
	}
}

// Observe feeds one round and returns the resulting decision (possibly empty while rounds are held).
func (t *PathTracker) Observe(o Obs) Decision {
	var d Decision
	deb := t.Debounce
	if deb < 1 {
		deb = 1
	}
	if t.cur == nil {
		t.start(&d, o, []Obs{o})
		return d
	}
	if o.IP.IsValid() && t.cur.IP.IsValid() && o.IP != t.cur.IP {
		// The pinned destination changed: held rounds belong to the old version, the new one
		// starts immediately.
		for _, p := range t.pending {
			t.place(&d, t.cur, p)
		}
		t.pending = nil
		t.start(&d, o, []Obs{o})
		return d
	}
	if !t.cur.differs(o) {
		// A matching round: held rounds were odd replies (load balancing), merge them.
		for _, p := range t.pending {
			t.place(&d, t.cur, p)
		}
		t.pending = nil
		t.place(&d, t.cur, o)
		return d
	}
	t.pending = append(t.pending, o)
	if len(t.pending) >= deb {
		rounds := t.pending
		t.pending = nil
		t.start(&d, o, rounds)
	}
	return d
}

// Flush places any held rounds on the current version (used at shutdown).
func (t *PathTracker) Flush() Decision {
	var d Decision
	if t.cur != nil {
		for _, p := range t.pending {
			t.place(&d, t.cur, p)
		}
	}
	t.pending = nil
	return d
}

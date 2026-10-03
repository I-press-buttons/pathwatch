package web

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/scheduler"
)

// Hub fans live events out to SSE subscribers. It implements scheduler.Observer and
// alert.AlertSink. Slow subscribers lose events instead of blocking probing.
type Hub struct {
	mu     sync.RWMutex
	subs   map[chan []byte]struct{}
	closed bool

	// alertJSON renders an alert row for the "alert" event (set by the Server).
	alertJSON func(id int64) (any, bool)

	changedMu    sync.Mutex
	changedTimer *time.Timer
}

// NewHub returns an empty hub.
func NewHub() *Hub { return &Hub{subs: map[chan []byte]struct{}{}} }

// Subscribe registers a subscriber. Call the returned func to unsubscribe.
func (h *Hub) Subscribe() (<-chan []byte, func()) {
	ch := make(chan []byte, 256)
	h.mu.Lock()
	if h.closed {
		close(ch)
		h.mu.Unlock()
		return ch, func() {}
	}
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
}

// Close disconnects every subscriber.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for ch := range h.subs {
		delete(h.subs, ch)
		close(ch)
	}
}

// Subscribers returns the number of connected streams.
func (h *Hub) Subscribers() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.subs)
}

// Publish sends an SSE event to all subscribers.
func (h *Hub) Publish(event string, data any) {
	h.mu.RLock()
	n := len(h.subs)
	h.mu.RUnlock()
	if n == 0 {
		return
	}
	b, err := json.Marshal(data)
	if err != nil {
		return
	}
	msg := make([]byte, 0, len(b)+len(event)+16)
	msg = append(msg, "event: "...)
	msg = append(msg, event...)
	msg = append(msg, "\ndata: "...)
	msg = append(msg, b...)
	msg = append(msg, '\n', '\n')
	h.mu.RLock()
	for ch := range h.subs {
		select {
		case ch <- msg:
		default: // subscriber too slow: drop
		}
	}
	h.mu.RUnlock()
}

type sseHop struct {
	TTL     int      `json:"ttl"`
	Address *string  `json:"address"`
	RTTMS   *float64 `json:"rtt_ms"`
}

// Round implements scheduler.Observer.
func (h *Hub) Round(e scheduler.RoundEvent) {
	h.mu.RLock()
	n := len(h.subs)
	h.mu.RUnlock()
	if n == 0 {
		return
	}
	hops := make([]sseHop, len(e.Hops))
	for i, hp := range e.Hops {
		hops[i].TTL = hp.TTL
		if hp.Responded() {
			if hp.Addr.IsValid() {
				a := hp.Addr.String()
				hops[i].Address = &a
			}
			v := round3(hp.RTTms())
			hops[i].RTTMS = &v
		}
	}
	h.Publish("round", map[string]any{"target_id": e.TargetID, "ts": e.TS.UnixMilli(), "hops": hops})
}

// Probe implements scheduler.Observer.
func (h *Hub) Probe(e scheduler.ProbeEvent) {
	var tid any
	if e.TargetID != 0 {
		tid = e.TargetID
	}
	m := map[string]any{"target_id": tid, "probe_id": e.ProbeID, "type": e.Type, "ts": e.TS.UnixMilli(), "ok": e.OK}
	if e.OK {
		m["total_ms"] = round3(e.TotalMS)
	} else {
		m["total_ms"] = nil
	}
	h.Publish("probe", m)
}

// TargetsChanged implements scheduler.Observer. Bursts are coalesced.
func (h *Hub) TargetsChanged() {
	h.changedMu.Lock()
	defer h.changedMu.Unlock()
	if h.changedTimer != nil {
		return
	}
	h.changedTimer = time.AfterFunc(100*time.Millisecond, func() {
		h.changedMu.Lock()
		h.changedTimer = nil
		h.changedMu.Unlock()
		h.Publish("targets", struct{}{})
	})
}

// AlertChanged implements alert.AlertSink: it pushes the alert row as an "alert" event.
func (h *Hub) AlertChanged(id int64) {
	if h.alertJSON == nil {
		return
	}
	if v, ok := h.alertJSON(id); ok {
		h.Publish("alert", v)
	}
}

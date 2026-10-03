package store

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Hop is the result of one TTL probe within a round.
type Hop struct {
	TTL    int
	Status uint8         // probe.Status: 0 timeout, 1 reply (destination), 2 ttl exceeded, 3 unreachable
	RTT    time.Duration // zero unless Status != 0
	Resp   int           // 1-based responder index within the path's responder list for this TTL; 0 = none
	Addr   netip.Addr    // responder address (not persisted; used for live streaming)
}

// Responded reports whether any reply was received.
func (h Hop) Responded() bool { return h.Status != 0 }

// Round is one mtr-style round: one probe per TTL from 1 up to the probed path length.
type Round struct {
	TargetID int64
	TS       time.Time
	PathID   int64
	Hops     []Hop // TTL 1..N, in order, including non-responding TTLs
}

// RTTms returns the hop's RTT in milliseconds.
func (h Hop) RTTms() float64 { return float64(h.RTT) / float64(time.Millisecond) }

// EncodeHops packs hops into the icmp_rounds.results blob:
// for each hop in TTL order: status (1 byte) | rtt_us (uvarint) | responder index (uvarint).
func EncodeHops(hops []Hop) []byte {
	b := make([]byte, 0, len(hops)*4)
	for _, h := range hops {
		b = append(b, h.Status)
		us := uint64(0)
		if h.RTT > 0 {
			us = uint64(h.RTT / time.Microsecond)
			if us == 0 {
				us = 1
			}
		}
		b = binary.AppendUvarint(b, us)
		b = binary.AppendUvarint(b, uint64(h.Resp))
	}
	return b
}

// DecodeHops unpacks n hops (TTL 1..n) from a results blob.
func DecodeHops(b []byte, n int) ([]Hop, error) {
	hops := make([]Hop, 0, n)
	for ttl := 1; ttl <= n; ttl++ {
		if len(b) < 1 {
			return nil, errors.New("round blob truncated")
		}
		h := Hop{TTL: ttl, Status: b[0]}
		b = b[1:]
		us, k := binary.Uvarint(b)
		if k <= 0 {
			return nil, errors.New("round blob: bad rtt")
		}
		b = b[k:]
		resp, k := binary.Uvarint(b)
		if k <= 0 {
			return nil, errors.New("round blob: bad responder")
		}
		b = b[k:]
		h.RTT = time.Duration(us) * time.Microsecond
		h.Resp = int(resp)
		hops = append(hops, h)
	}
	return hops, nil
}

// HTTPSample is one raw HTTP probe sample.
type HTTPSample struct {
	ProbeID      int64
	TS           time.Time
	ResolvedIP   string
	Status       int
	DNS          time.Duration
	Connect      time.Duration
	TLS          time.Duration
	TTFB         time.Duration
	Transfer     time.Duration
	Total        time.Duration
	Redirects    int
	CertNotAfter time.Time
	Error        string // empty on success
}

// TCPSample is one raw TCP connect sample.
type TCPSample struct {
	ProbeID    int64
	TS         time.Time
	ResolvedIP string
	Connect    time.Duration
	Error      string
}

// DNSSample is one raw DNS probe sample.
type DNSSample struct {
	ProbeID int64
	TS      time.Time
	RCode   int
	RTT     time.Duration
	Error   string
}

func us(t time.Time) int64 { return t.UnixMicro() }

func fromUs(v int64) time.Time { return time.UnixMicro(v).UTC() }

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

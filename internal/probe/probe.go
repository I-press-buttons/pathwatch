// Package probe contains the network probers: ICMP (platform specific), HTTP, TCP and DNS.
package probe

import (
	"context"
	"net/netip"
	"time"
)

// Status is the outcome of a single TTL-limited ICMP probe.
type Status uint8

// Probe outcomes. The numeric values are persisted in the packed round blob.
const (
	StatusTimeout     Status = 0 // no reply before the timeout (late replies count as lost)
	StatusReply       Status = 1 // Echo Reply from the destination
	StatusTTLExceeded Status = 2 // Time Exceeded from an intermediate router
	StatusUnreachable Status = 3 // Destination Unreachable from some router
)

func (s Status) String() string {
	switch s {
	case StatusReply:
		return "reply"
	case StatusTTLExceeded:
		return "ttl_exceeded"
	case StatusUnreachable:
		return "unreachable"
	}
	return "timeout"
}

// Responded reports whether any reply (of any kind) was received.
func (s Status) Responded() bool { return s != StatusTimeout }

// Request is one TTL-limited ICMP Echo probe.
type Request struct {
	Dst     netip.Addr    // pinned destination address
	TTL     int           // IP TTL (1..255)
	Flow    uint16        // constant per target: Paris-style flow identity (the ICMP identifier in raw mode)
	Seq     uint16        // varied per probe, used for matching
	Timeout time.Duration // never longer than the round interval
}

// Result is the outcome of a Request.
type Result struct {
	Status Status
	Addr   netip.Addr    // responder (zero when Status is StatusTimeout)
	RTT    time.Duration // zero when Status is StatusTimeout
	Err    error         // set for local failures (send errors); Status is StatusTimeout
}

// Prober sends TTL-limited ICMP Echo probes. Implementations are safe for concurrent use.
// Probe blocks until a reply arrives, the timeout elapses or ctx is cancelled.
type Prober interface {
	Probe(ctx context.Context, req Request) Result
	// Mode reports the active mode: "raw" or "dgram".
	Mode() string
	Close() error
}

// FlowReleaser is optionally implemented by probers that hold per-flow resources
// (the datagram prober keeps one socket per flow).
type FlowReleaser interface {
	ReleaseFlow(flow uint16)
}

// Mode names.
const (
	ModeRaw         = "raw"
	ModeDgram       = "dgram"
	ModeUnavailable = "unavailable"
)

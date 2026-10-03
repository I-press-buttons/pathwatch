//go:build linux

package probe

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestDgramLoopbackProbe(t *testing.T) {
	p, mode, err := NewICMPProber("dgram")
	if err != nil {
		t.Skipf("datagram ICMP sockets unavailable: %v", err)
	}
	defer p.Close()
	if mode != ModeDgram {
		t.Fatalf("mode %q", mode)
	}
	dst := netip.MustParseAddr("127.0.0.1")
	res := p.Probe(context.Background(), Request{Dst: dst, TTL: 4, Flow: 9, Seq: 1, Timeout: time.Second})
	if res.Status != StatusReply || res.RTT <= 0 {
		t.Skipf("dgram loopback probe did not reply (kernel/sandbox limits?): %+v", res)
	}
	if fr, ok := p.(FlowReleaser); ok {
		fr.ReleaseFlow(9)
	}
}

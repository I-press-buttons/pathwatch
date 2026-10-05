package probe

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func newTestWaiter(p *pendingTable, key uint32, dst netip.Addr) *waiter {
	w := &waiter{ch: make(chan Result, 1), dst: dst}
	w.sent.Store(monoNow())
	p.add(key, w)
	return w
}

func TestDeliverRejectsEchoReplyFromOtherSource(t *testing.T) {
	p := newPendingTable()
	dst := netip.MustParseAddr("192.0.2.1")
	key := pendKey(4242, 17)
	w := newTestWaiter(p, key, dst)

	// Wrong source: ignored, waiter stays pending.
	p.deliver(key, time.Now(), StatusReply, netip.MustParseAddr("198.51.100.7"), netip.Addr{})
	if len(w.ch) != 0 {
		t.Fatal("reply from another source completed the probe")
	}
	p.mu.Lock()
	_, pending := p.m[key]
	p.mu.Unlock()
	if !pending {
		t.Fatal("waiter was removed by a mismatched reply")
	}

	// The genuine reply (here 4in6-mapped) still completes it.
	p.deliver(key, time.Now(), StatusReply, netip.MustParseAddr("::ffff:192.0.2.1"), netip.Addr{})
	r := p.wait(context.Background(), key, w, 100*time.Millisecond)
	if r.Status != StatusReply {
		t.Fatalf("got %v, want reply", r.Status)
	}
}

func TestDeliverErrorSourceAndOrigDst(t *testing.T) {
	dst := netip.MustParseAddr("192.0.2.1")
	router := netip.MustParseAddr("203.0.113.9")
	other := netip.MustParseAddr("198.51.100.7")
	cases := []struct {
		name    string
		origDst netip.Addr
		accept  bool
	}{
		{"router error quoting our destination", dst, true},
		{"router error, destination unknown", netip.Addr{}, true},
		{"router error quoting another destination", other, false},
	}
	for _, c := range cases {
		p := newPendingTable()
		key := pendKey(1, 2)
		w := newTestWaiter(p, key, dst)
		p.deliver(key, time.Now(), StatusTTLExceeded, router, c.origDst)
		got := len(w.ch) == 1
		if got != c.accept {
			t.Errorf("%s: accepted=%v, want %v", c.name, got, c.accept)
		}
		if got {
			if r := <-w.ch; r.Status != StatusTTLExceeded || r.Addr != router {
				t.Errorf("%s: got %v from %v", c.name, r.Status, r.Addr)
			}
		}
	}
}

func TestDeliverWithoutDestinationAcceptsAnything(t *testing.T) {
	p := newPendingTable()
	key := pendKey(9, 9)
	w := newTestWaiter(p, key, netip.Addr{})
	p.deliver(key, time.Now(), StatusReply, netip.MustParseAddr("198.51.100.7"), netip.Addr{})
	if len(w.ch) != 1 {
		t.Fatal("waiter without a destination should accept any reply")
	}
}

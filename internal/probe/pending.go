package probe

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// waiter is a probe awaiting its reply.
type waiter struct {
	ch   chan Result
	sent atomic.Int64 // monotonic nanoseconds since epoch, set just before the packet is sent
	dst  netip.Addr
}

var epoch = time.Now()

func monoNow() int64 { return int64(time.Since(epoch)) }

// pendingTable matches replies to in-flight probes by (id, seq).
type pendingTable struct {
	mu sync.Mutex
	m  map[uint32]*waiter
}

func newPendingTable() *pendingTable { return &pendingTable{m: make(map[uint32]*waiter)} }

func pendKey(id, seq uint16) uint32 { return uint32(id)<<16 | uint32(seq) }

func (p *pendingTable) add(key uint32, w *waiter) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, dup := p.m[key]; dup {
		return false
	}
	p.m[key] = w
	return true
}

// take removes and returns the waiter for key, if any.
func (p *pendingTable) take(key uint32) *waiter {
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.m[key]
	delete(p.m, key)
	return w
}

// deliver completes the waiter for key (if still pending) with a reply received at recvAt.
// origDst, when valid, must match the waiter's destination (error messages only).
func (p *pendingTable) deliver(key uint32, recvAt time.Time, status Status, addr netip.Addr, origDst netip.Addr) {
	p.mu.Lock()
	w := p.m[key]
	if w == nil || (origDst.IsValid() && w.dst.IsValid() && origDst != w.dst) {
		p.mu.Unlock()
		return
	}
	delete(p.m, key)
	p.mu.Unlock()
	rtt := recvAt.Sub(epoch) - time.Duration(w.sent.Load())
	if rtt < 0 {
		rtt = 0
	}
	w.ch <- Result{Status: status, Addr: addr, RTT: rtt}
}

// wait blocks for the waiter's result, the timeout or ctx. On timeout the entry is
// removed so a late reply is discarded (late replies count as lost).
func (p *pendingTable) wait(ctx context.Context, key uint32, w *waiter, timeout time.Duration) Result {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-w.ch:
		return r
	case <-t.C:
	case <-ctx.Done():
	}
	if p.take(key) == nil {
		// A reply raced with the timeout and was already delivered.
		select {
		case r := <-w.ch:
			return r
		default:
		}
	}
	return Result{Status: StatusTimeout}
}

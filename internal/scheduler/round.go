package scheduler

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// RoundResult is the outcome of one mtr-style round.
type RoundResult struct {
	// Hops holds TTL 1..N in order, including non-responding TTLs. N is the destination's TTL when
	// it answered, otherwise the number of TTLs probed.
	Hops    []store.Hop
	DestTTL int   // TTL of the destination's Echo Reply, 0 if it did not answer
	MaxResp int   // highest TTL that got any reply
	SendErr error // first local send error, if any
}

// ProbeRound sends one ICMP Echo per TTL from 1 to limit toward dst, with a small stagger
// between consecutive TTLs, all with the same flow identity and consecutive sequence numbers
// starting after seqBase. As soon as the destination answers at some TTL, probes for higher TTLs
// that have not been sent yet are skipped and the result is cut at the lowest answering TTL.
func ProbeRound(ctx context.Context, p probe.Prober, dst netip.Addr, flow uint16, seqBase uint16, limit int, timeout, stagger time.Duration) RoundResult {
	results := make([]probe.Result, limit+1)
	var destTTL atomic.Int32
	var wg sync.WaitGroup
	for ttl := 1; ttl <= limit; ttl++ {
		wg.Add(1)
		go func(ttl int) {
			defer wg.Done()
			if d := time.Duration(ttl-1) * stagger; d > 0 {
				if !sleepCtx(ctx, d) {
					return
				}
			}
			if dt := destTTL.Load(); dt != 0 && int32(ttl) > dt {
				return // the destination already answered at a lower TTL
			}
			res := p.Probe(ctx, probe.Request{Dst: dst, TTL: ttl, Flow: flow, Seq: seqBase + uint16(ttl), Timeout: timeout})
			results[ttl] = res
			if res.Status == probe.StatusReply {
				for {
					cur := destTTL.Load()
					if cur != 0 && cur <= int32(ttl) {
						break
					}
					if destTTL.CompareAndSwap(cur, int32(ttl)) {
						break
					}
				}
			}
		}(ttl)
	}
	wg.Wait()

	var rr RoundResult
	for ttl := 1; ttl <= limit; ttl++ {
		if err := results[ttl].Err; err != nil {
			rr.SendErr = err
			break
		}
	}
	rr.DestTTL = int(destTTL.Load())
	cut := limit
	if rr.DestTTL > 0 {
		cut = rr.DestTTL
	}
	rr.Hops = make([]store.Hop, 0, cut)
	for ttl := 1; ttl <= cut; ttl++ {
		res := results[ttl]
		h := store.Hop{TTL: ttl, Status: uint8(res.Status)}
		if res.Status.Responded() {
			h.RTT, h.Addr = res.RTT, res.Addr
			rr.MaxResp = ttl
		}
		rr.Hops = append(rr.Hops, h)
	}
	return rr
}

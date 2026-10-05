package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
)

type hopAgg struct {
	sent, lost int
	last       float64
	n          int
	mean, m2   float64
	best, wrst float64
	addrs      map[netip.Addr]int
}

func (h *hopAgg) add(ms float64) {
	h.last = ms
	h.n++
	d := ms - h.mean
	h.mean += d / float64(h.n)
	h.m2 += d * (ms - h.mean)
	if h.n == 1 || ms < h.best {
		h.best = ms
	}
	if ms > h.wrst {
		h.wrst = ms
	}
}

func (h *hopAgg) stdev() float64 {
	if h.n < 2 {
		return 0
	}
	return math.Sqrt(h.m2 / float64(h.n-1))
}

func traceCmd(args []string) int {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	count := fs.Int("c", 10, "number of rounds")
	interval := fs.Duration("i", time.Second, "interval between rounds")
	maxHops := fs.Int("m", 30, "maximum number of hops")
	timeout := fs.Duration("w", 2*time.Second, "per-probe timeout")
	mode := fs.String("mode", "auto", "ICMP mode: auto, raw or dgram")
	noDNS := fs.Bool("n", false, "do not resolve hop addresses to host names")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pathwatch trace [-c rounds] [-i interval] [-m max-hops] [-w timeout] [-mode auto|raw|dgram] [-n] <host>")
		return 2
	}
	host := fs.Arg(0)
	if *count < 1 || *maxHops < 1 || *maxHops > 64 || *interval < 100*time.Millisecond {
		fmt.Fprintln(os.Stderr, "pathwatch trace: invalid -c, -m or -i")
		return 2
	}
	if *timeout > *interval {
		*timeout = *interval
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dst, err := resolveForTrace(ctx, host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pathwatch trace: cannot resolve %s: %v\n", host, err)
		return 1
	}
	p, m, err := probe.NewICMPProber(*mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pathwatch trace: ICMP is unavailable: %v\n", err)
		return 1
	}
	defer p.Close()

	flow := uint16(os.Getpid()&0x7fff) + 1
	lim := scheduler.NewLimiter(*maxHops)
	aggs := map[int]*hopAgg{}
	destTTL := 0
	var seq uint16
	for i := 0; i < *count && ctx.Err() == nil; i++ {
		start := time.Now()
		limit := lim.Next()
		rr := scheduler.ProbeRound(ctx, p, dst, flow, seq, limit, *timeout, 3*time.Millisecond)
		seq += uint16(limit)
		lim.Record(rr.DestTTL, rr.MaxResp)
		if ctx.Err() != nil {
			break
		}
		if rr.DestTTL > 0 {
			destTTL = rr.DestTTL
		}
		for _, h := range rr.Hops {
			a := aggs[h.TTL]
			if a == nil {
				a = &hopAgg{addrs: map[netip.Addr]int{}}
				aggs[h.TTL] = a
			}
			a.sent++
			if h.Responded() {
				a.add(h.RTTms())
				if h.Addr.IsValid() {
					a.addrs[h.Addr]++
				}
			} else {
				a.lost++
			}
		}
		if i+1 < *count {
			if wait := *interval - time.Since(start); wait > 0 {
				select {
				case <-ctx.Done():
				case <-time.After(wait):
				}
			}
		}
	}

	// rows end at the destination, or at the last hop that ever answered
	last := destTTL
	if last == 0 {
		for ttl, a := range aggs {
			if a.n > 0 && ttl > last {
				last = ttl
			}
		}
	}
	names := map[netip.Addr]string{}
	if !*noDNS {
		names = reverseLookup(ctx, aggs)
	}
	fmt.Printf("pathwatch trace to %s (%s), %d rounds, ICMP mode %s\n", host, dst, *count, m)
	if last == 0 {
		fmt.Println("no replies received")
		return 1
	}
	fmt.Printf("%4s  %-44s %7s %4s %8s %8s %8s %8s %8s\n", "Hop", "Host", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev")
	for ttl := 1; ttl <= last; ttl++ {
		a := aggs[ttl]
		if a == nil {
			continue
		}
		addrs := sortedAddrs(a)
		label := "???"
		if len(addrs) > 0 {
			label = describe(addrs[0], names)
		}
		loss := 100 * float64(a.lost) / float64(a.sent)
		if a.n > 0 {
			fmt.Printf("%4d  %-44s %6.1f%% %4d %8.1f %8.1f %8.1f %8.1f %8.1f\n", ttl, trunc(label, 44), loss, a.sent, a.last, a.mean, a.best, a.wrst, a.stdev())
		} else {
			fmt.Printf("%4d  %-44s %6.1f%% %4d %8s %8s %8s %8s %8s\n", ttl, label, loss, a.sent, "-", "-", "-", "-", "-")
		}
		for _, extra := range addrs[min(1, len(addrs)):] {
			fmt.Printf("      %s\n", describe(extra, names))
		}
	}
	if destTTL == 0 {
		fmt.Println("(the destination did not answer ICMP echo; a TCP probe can monitor such targets)")
	}
	return 0
}

// reorderFlags moves flags before the positional host so `pathwatch trace example.com -c 5` works.
func reorderFlags(args []string) []string {
	var flags, pos []string
	valued := map[string]bool{"-c": true, "-i": true, "-m": true, "-w": true, "-mode": true, "--mode": true}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			if valued[a] && i+1 < len(args) && !strings.Contains(a, "=") {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func sortedAddrs(a *hopAgg) []netip.Addr {
	out := make([]netip.Addr, 0, len(a.addrs))
	for ad := range a.addrs {
		out = append(out, ad)
	}
	sort.Slice(out, func(i, j int) bool {
		if a.addrs[out[i]] != a.addrs[out[j]] {
			return a.addrs[out[i]] > a.addrs[out[j]]
		}
		return out[i].Less(out[j])
	})
	return out
}

func describe(a netip.Addr, names map[netip.Addr]string) string {
	if n := names[a]; n != "" {
		return n + " (" + a.String() + ")"
	}
	return a.String()
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

func resolveForTrace(ctx context.Context, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(rctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			return a, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return netip.Addr{}, fmt.Errorf("no addresses")
}

func reverseLookup(ctx context.Context, aggs map[int]*hopAgg) map[netip.Addr]string {
	var mu sync.Mutex
	var wg sync.WaitGroup
	names := map[netip.Addr]string{}
	seen := map[netip.Addr]bool{}
	for _, a := range aggs {
		for ad := range a.addrs {
			if seen[ad] {
				continue
			}
			seen[ad] = true
			wg.Add(1)
			go func(ad netip.Addr) {
				defer wg.Done()
				c, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				if n, err := net.DefaultResolver.LookupAddr(c, ad.String()); err == nil && len(n) > 0 {
					mu.Lock()
					names[ad] = strings.TrimSuffix(n[0], ".")
					mu.Unlock()
				}
			}(ad)
		}
	}
	wg.Wait()
	return names
}

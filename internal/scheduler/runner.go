package scheduler

import (
	"context"
	"encoding/json"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

type pin struct {
	Addr netip.Addr
	DNS  time.Duration // how long the per-cycle resolution took
	At   time.Time
}

// runner executes all probes of one target.
type runner struct {
	s      *Scheduler
	row    store.TargetRow
	spec   config.Target
	probes []ProbeRef
	flow   uint16

	cancel context.CancelFunc
	wg     sync.WaitGroup

	pin        atomic.Pointer[pin]
	pinReady   chan struct{}
	pinOnce    sync.Once
	rediscover atomic.Bool

	mu         sync.Mutex
	unresp     bool
	lastRound  time.Time
	resolveErr string
}

func newRunner(s *Scheduler, row store.TargetRow, spec config.Target, probes []ProbeRef) *runner {
	return &runner{s: s, row: row, spec: spec, probes: probes, flow: s.flowFor(row.ID), pinReady: make(chan struct{})}
}

func (r *runner) snapshot() (ip string, unresp bool, last time.Time) {
	if p := r.pin.Load(); p != nil {
		ip = p.Addr.String()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return ip, r.unresp, r.lastRound
}

func (r *runner) log(args ...any) []any {
	return append([]any{"target", r.row.Name}, args...)
}

// run starts the target's goroutines and blocks until they have all finished (ctx cancelled or stop).
func (r *runner) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	defer cancel()
	r.start(ctx)
	r.wg.Wait()
}

func (r *runner) start(ctx context.Context) {
	r.s.log.Info("target started", r.log("host", r.row.Host, "source", r.row.Source)...)
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.discoverLoop(ctx) }()
	if r.spec.ICMP != nil && r.s.opts.Prober != nil {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.icmpLoop(ctx) }()
	} else if r.spec.ICMP != nil {
		r.s.log.Warn("ICMP trace skipped: no ICMP prober available", r.log()...)
	}
	for _, p := range r.spec.Probes {
		ref, ok := r.refFor(p)
		if !ok {
			continue
		}
		p := p
		r.wg.Add(1)
		switch p.Type {
		case config.ProbeHTTP:
			go func() { defer r.wg.Done(); r.httpLoop(ctx, p, ref) }()
		case config.ProbeTCP:
			go func() { defer r.wg.Done(); r.tcpLoop(ctx, p, ref) }()
		default:
			r.wg.Done()
		}
	}
}

func (r *runner) refFor(p config.Probe) (ProbeRef, bool) {
	for _, ref := range r.probes {
		if ref.Key == p.Key() {
			return ref, true
		}
	}
	return ProbeRef{}, false
}

// stop cancels the runner and waits for its goroutines.
func (r *runner) stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	if fr, ok := r.s.opts.Prober.(probe.FlowReleaser); ok {
		fr.ReleaseFlow(r.flow)
	}
	r.s.log.Info("target stopped", r.log()...)
}

// ---------------------------------------------------------------------------
// discovery: resolve once per cycle and pin the address for every probe

func (r *runner) rediscoveryInterval() time.Duration {
	if r.spec.ICMP != nil && r.spec.ICMP.Rediscovery > 0 {
		return r.spec.ICMP.Rediscovery
	}
	if r.s.opts.Defaults.PathRediscovery > 0 {
		return r.s.opts.Defaults.PathRediscovery.D()
	}
	return 5 * time.Minute
}

func (r *runner) resolveOnce(ctx context.Context) bool {
	var cur netip.Addr
	if p := r.pin.Load(); p != nil {
		cur = p.Addr
	}
	addr, dur, err := resolveHost(ctx, r.s.opts.Resolver, r.row.Host, cur)
	if err != nil {
		if ctx.Err() != nil {
			return false
		}
		r.mu.Lock()
		first := r.resolveErr == ""
		r.resolveErr = err.Error()
		r.mu.Unlock()
		if first || cur.IsValid() {
			r.s.log.Warn("cannot resolve target host", r.log("host", r.row.Host, "err", err)...)
		}
		return false
	}
	r.mu.Lock()
	r.resolveErr = ""
	r.mu.Unlock()
	if cur.IsValid() && cur != addr {
		r.s.log.Info("target address changed", r.log("from", cur, "to", addr)...)
	}
	r.pin.Store(&pin{Addr: addr, DNS: dur, At: time.Now()})
	r.pinOnce.Do(func() { close(r.pinReady) })
	return true
}

func (r *runner) discoverLoop(ctx context.Context) {
	for !r.resolveOnce(ctx) {
		if !sleepCtx(ctx, 10*time.Second) {
			return
		}
	}
	iv := r.rediscoveryInterval()
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r.rediscover.Store(true)
		for !r.resolveOnce(ctx) {
			// keep the previous pin; retry sooner than the next cycle
			if !sleepCtx(ctx, 15*time.Second) {
				return
			}
			if r.pin.Load() != nil {
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP and TCP probes

func (r *runner) waitPin(ctx context.Context, d time.Duration) *pin {
	if p := r.pin.Load(); p != nil {
		return p
	}
	select {
	case <-r.pinReady:
	case <-time.After(d):
	case <-ctx.Done():
	}
	return r.pin.Load()
}

func (r *runner) httpLoop(ctx context.Context, p config.Probe, ref ProbeRef) {
	if !sleepCtx(ctx, jitter(minDur(p.Interval, 5*time.Second))) {
		return
	}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		pn := r.waitPin(ctx, 2*time.Second)
		if ctx.Err() != nil {
			return
		}
		ts := time.Now().UTC()
		opts := probe.HTTPOptions{Version: r.s.opts.Version}
		var ip string
		if pn != nil {
			opts.Pin, opts.PinDNS = pn.Addr, pn.DNS
			ip = pn.Addr.String()
		}
		res := probe.HTTPProbe(ctx, p, opts)
		if ctx.Err() != nil {
			return
		}
		smp := store.HTTPSample{ProbeID: ref.ID, TS: ts, ResolvedIP: ip, Status: res.Status,
			DNS: res.DNS, Connect: res.Connect, TLS: res.TLS, TTFB: res.TTFB, Transfer: res.Transfer, Total: res.Total,
			Redirects: res.Redirects, CertNotAfter: res.CertNotAfter}
		if res.Err != nil {
			smp.Error = res.Err.Error()
		}
		r.s.opts.Store.RecordHTTP(smp)
		pe := ProbeEvent{TargetID: r.row.ID, ProbeID: ref.ID, Type: config.ProbeHTTP, TS: ts, OK: res.OK, TotalMS: ms(res.Total)}
		pe.Sample = alert.ProbeSample{TargetID: r.row.ID, ProbeID: ref.ID, Type: config.ProbeHTTP, TS: ts, OK: res.OK, Error: smp.Error,
			Status: res.Status, TotalMS: ms(res.Total), TTFBMS: ms(res.TTFB), CertNotAfter: res.CertNotAfter}
		r.s.obs.Probe(pe)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *runner) tcpLoop(ctx context.Context, p config.Probe, ref ProbeRef) {
	if !sleepCtx(ctx, jitter(minDur(p.Interval, 5*time.Second))) {
		return
	}
	t := time.NewTicker(p.Interval)
	defer t.Stop()
	for {
		pn := r.waitPin(ctx, 2*time.Second)
		if ctx.Err() != nil {
			return
		}
		ts := time.Now().UTC()
		smp := store.TCPSample{ProbeID: ref.ID, TS: ts}
		var res probe.TCPResult
		if pn == nil {
			r.mu.Lock()
			msg := r.resolveErr
			r.mu.Unlock()
			if msg == "" {
				msg = "host not resolved yet"
			}
			res.Err = errString("resolve: " + msg)
		} else {
			smp.ResolvedIP = pn.Addr.String()
			res = probe.TCPConnect(ctx, pn.Addr, p.Port, p.Timeout)
		}
		if ctx.Err() != nil {
			return
		}
		smp.Connect = res.Connect
		if res.Err != nil {
			smp.Error = res.Err.Error()
		}
		r.s.opts.Store.RecordTCP(smp)
		pe := ProbeEvent{TargetID: r.row.ID, ProbeID: ref.ID, Type: config.ProbeTCP, TS: ts, OK: res.OK, TotalMS: ms(res.Connect)}
		pe.Sample = alert.ProbeSample{TargetID: r.row.ID, ProbeID: ref.ID, Type: config.ProbeTCP, TS: ts, OK: res.OK, Error: smp.Error, TotalMS: ms(res.Connect)}
		r.s.obs.Probe(pe)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// ICMP rounds

// icmpState is the per-target ICMP bookkeeping that lives for the runner's lifetime.
type icmpState struct {
	tracker  *PathTracker
	limiter  *Limiter
	gaps     *analyze.GapDetector
	seq      uint16
	rounds   int // rounds since start
	unrespEv int64
	lastWarn time.Time
}

func (r *runner) icmpLoop(ctx context.Context) {
	ic := r.spec.ICMP
	st := &icmpState{
		tracker: &PathTracker{Debounce: r.s.opts.Debounce},
		limiter: NewLimiter(ic.MaxHops),
		gaps:    analyze.NewGapDetector(ic.Interval),
	}
	select {
	case <-r.pinReady:
	case <-ctx.Done():
		return
	}
	r.resumePath(st)
	if !sleepCtx(ctx, jitter(ic.Interval)) {
		return
	}
	// Time not probed while the process was down is a gap, not loss.
	if last, ok := r.s.opts.Store.LastRoundTime(r.row.ID); ok {
		if now := time.Now(); now.Sub(last) > 3*ic.Interval && last.Before(now) {
			r.s.opts.Store.RecordGap(r.row.ID, last, now.UTC(), "stopped")
			r.s.log.Info("monitor gap recorded (process was not running)", r.log("from", last, "to", now.UTC())...)
		}
	}
	t := time.NewTicker(ic.Interval)
	defer t.Stop()
	for {
		r.round(ctx, st)
		select {
		case <-ctx.Done():
			r.flushPending(st)
			return
		case <-t.C:
		}
	}
}

// resumePath continues the latest stored path version after a restart, so a restart does not
// create a new version.
func (r *runner) resumePath(st *icmpState) {
	pn := r.pin.Load()
	if pn == nil {
		return
	}
	p, err := r.s.opts.Store.LatestPath(r.row.ID)
	if err != nil {
		return
	}
	ip, err := netip.ParseAddr(p.ResolvedIP)
	if err != nil || ip != pn.Addr {
		return
	}
	v := newVersion(ip)
	v.PathID, v.DestTTL = p.ID, p.DestTTL
	if hops, err := r.s.opts.Store.PathHops([]int64{p.ID}); err == nil {
		for _, h := range hops[p.ID] {
			a, err := netip.ParseAddr(h.Address)
			if err != nil {
				continue
			}
			list := v.Resp[h.TTL]
			for len(list) <= h.Idx {
				list = append(list, &RespEntry{})
			}
			list[h.Idx] = &RespEntry{Addr: a, Count: int(h.Share * 100)}
			v.Resp[h.TTL] = list
		}
	}
	st.tracker.Resume(v)
	if p.DestTTL > 0 {
		st.limiter.Record(p.DestTTL, p.DestTTL) // start probing exactly to the known destination
		st.limiter.Rediscover()                 // but do one full-depth round first
	}
}

func (r *runner) round(ctx context.Context, st *icmpState) {
	ic := r.spec.ICMP
	pn := r.pin.Load()
	if pn == nil {
		return
	}
	dst := pn.Addr
	if !dst.Is4() {
		if time.Since(st.lastWarn) > time.Hour {
			st.lastWarn = time.Now()
			r.s.log.Warn("ICMP trace supports IPv4 only; skipping rounds for this target", r.log("addr", dst)...)
		}
		return
	}
	if r.rediscover.Swap(false) {
		st.limiter.Rediscover()
	}
	limit := st.limiter.Next()
	start := time.Now()
	if g := st.gaps.Observe(start); g != nil {
		r.s.opts.Store.RecordGap(r.row.ID, g.From.UTC(), g.To.UTC(), g.Reason)
		r.s.log.Warn("monitor gap detected", r.log("reason", g.Reason, "from", g.From.UTC(), "to", g.To.UTC())...)
	}

	rr := ProbeRound(ctx, r.s.opts.Prober, dst, r.flow, st.seq, limit, ic.Timeout, r.s.opts.Stagger)
	st.seq += uint16(limit)
	if ctx.Err() != nil {
		return
	}
	// A round that took much longer than its timeouts allow straddled a suspend or a stall: its
	// results are artefacts, so it is dropped (the surrounding time becomes a gap).
	if el := time.Since(start); el > ic.Timeout+time.Duration(limit)*r.s.opts.Stagger+time.Second {
		r.s.log.Warn("discarding ICMP round that took too long (system suspended or stalled?)", r.log("took", el)...)
		return
	}
	if rr.SendErr != nil && time.Since(st.lastWarn) > time.Minute {
		st.lastWarn = time.Now()
		r.s.log.Warn("ICMP probe could not be sent", r.log("err", rr.SendErr)...)
	}
	hops, dt, maxResp := rr.Hops, rr.DestTTL, rr.MaxResp
	st.limiter.Record(dt, maxResp)
	st.rounds++

	dec := st.tracker.Observe(Obs{TS: start.UTC(), IP: dst, DestTTL: dt, Hops: hops})
	r.apply(dec)

	r.mu.Lock()
	r.lastRound = start
	r.mu.Unlock()

	// icmp_unresponsive: the destination never answered during this process' life or the path version
	if cur := st.tracker.Current(); cur != nil {
		r.updateUnresponsive(st, cur.DestTTL == 0 && st.rounds >= 10)
	}
}

func (r *runner) updateUnresponsive(st *icmpState, unresp bool) {
	r.mu.Lock()
	changed := r.unresp != unresp
	r.unresp = unresp
	r.mu.Unlock()
	if !changed {
		return
	}
	tid := r.row.ID
	if unresp {
		det, _ := json.Marshal(map[string]string{"note": "destination does not answer ICMP echo; TCP probe (if any) is the end-to-end signal"})
		id, err := r.s.opts.Store.InsertEvent(store.Event{TargetID: &tid, Kind: store.EventICMPUnresponsive, From: time.Now().UTC(), Details: det})
		if err == nil {
			st.unrespEv = id
		}
		r.s.log.Info("destination does not answer ICMP echo (icmp_unresponsive)", r.log()...)
		return
	}
	if st.unrespEv != 0 {
		r.s.opts.Store.CloseEvent(st.unrespEv, time.Now().UTC())
		st.unrespEv = 0
	}
	r.s.log.Info("destination answers ICMP echo again", r.log()...)
}

func (r *runner) flushPending(st *icmpState) {
	r.apply(st.tracker.Flush())
}

// apply persists a tracker decision: new path versions, new responders, and the rounds.
func (r *runner) apply(d Decision) {
	st := r.s.opts.Store
	if d.Started != nil {
		v := d.Started
		id, err := st.NewPath(r.row.ID, v.IP.String(), 0, time.Now().UTC())
		if err != nil {
			r.s.log.Error("cannot create path version", r.log("err", err)...)
			return
		}
		v.PathID = id
		if d.Previous != nil {
			det, _ := json.Marshal(map[string]any{"from_path": d.Previous.PathID, "to_path": id, "resolved_ip": v.IP.String()})
			tid := r.row.ID
			if _, err := st.InsertEvent(store.Event{TargetID: &tid, Kind: store.EventRouteChange, From: time.Now().UTC(), Details: det}); err != nil {
				r.s.log.Warn("cannot record route change", r.log("err", err)...)
			}
			r.s.log.Info("path changed (new path version)", r.log("path", id, "ip", v.IP)...)
		}
	}
	for _, a := range d.Added {
		if a.Version.PathID != 0 {
			st.AddPathHop(a.Version.PathID, a.TTL, a.Idx, a.Addr.String())
		}
	}
	for _, v := range d.DestTTLSet {
		if v.PathID != 0 {
			st.SetPathDestTTL(v.PathID, v.DestTTL)
		}
	}
	for _, p := range d.Placed {
		if p.Version.PathID == 0 {
			continue
		}
		st.RecordRound(store.Round{TargetID: r.row.ID, TS: p.Obs.TS, PathID: p.Version.PathID, Hops: p.Obs.Hops})
		r.s.obs.Round(RoundEvent{TargetID: r.row.ID, TS: p.Obs.TS, Hops: p.Obs.Hops})
	}
	if len(d.Placed) > 0 {
		// refresh the stored responder shares now and then (cheap: a handful of rows)
		v := d.Placed[len(d.Placed)-1].Version
		if v.PathID != 0 && d.Placed[len(d.Placed)-1].Obs.TS.Second()%30 < 2 {
			st.UpdatePathShares(v.PathID, v.Shares())
		}
	}
}

package store

import (
	"sort"
	"sync"
	"time"
)

// MinuteStep is the width of the continuous aggregation buckets.
const MinuteStep = time.Minute

type icmpKey struct {
	target int64
	ttl    int
	path   int64
	bucket int64 // µs, start of the minute
}

type probeKey struct {
	probe  int64
	bucket int64
}

type ttlKey struct {
	target int64
	ttl    int
}

// ICMPRow is one completed 1-minute ICMP cell.
type ICMPRow struct {
	TargetID int64
	TTL      int
	PathID   int64
	Bucket   int64 // µs
	Roll     *Roll
}

// ProbeRollRow is one completed 1-minute probe cell.
type ProbeRollRow struct {
	ProbeID int64
	Bucket  int64 // µs
	Roll    *ProbeRoll
}

// MinuteBatch is everything that completed for one 1-minute bucket. It is persisted as
// 1m rollups and handed to subscribers (the analyzer / alert engine).
type MinuteBatch struct {
	Bucket time.Time // start of the minute (UTC)
	ICMP   []ICMPRow
	Probes []ProbeRollRow
}

// Aggregator maintains in-memory 1-minute buckets per (target, TTL, path) and per probe.
// It needs no database; Store wires it to the writer.
type Aggregator struct {
	mu      sync.Mutex
	icmp    map[icmpKey]*Roll
	probes  map[probeKey]*ProbeRoll
	lastRTT map[ttlKey]float64 // previous reply latency per (target, ttl) for jitter
}

// NewAggregator creates an empty aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{
		icmp:    make(map[icmpKey]*Roll),
		probes:  make(map[probeKey]*ProbeRoll),
		lastRTT: make(map[ttlKey]float64),
	}
}

func bucketOf(t time.Time) int64 {
	return t.Truncate(MinuteStep).UnixMicro()
}

// AddRound folds one round into the current buckets.
func (a *Aggregator) AddRound(r Round) {
	b := bucketOf(r.TS)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, h := range r.Hops {
		k := icmpKey{r.TargetID, h.TTL, r.PathID, b}
		roll := a.icmp[k]
		if roll == nil {
			roll = &Roll{}
			a.icmp[k] = roll
		}
		tk := ttlKey{r.TargetID, h.TTL}
		if h.Responded() {
			v := h.RTTms()
			prev, have := a.lastRTT[tk]
			roll.AddReply(v, prev, have)
			a.lastRTT[tk] = v
		} else {
			roll.AddLoss()
		}
	}
}

// ResetJitter forgets the previous RTTs of a target (after a monitor gap).
func (a *Aggregator) ResetJitter(target int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k := range a.lastRTT {
		if k.target == target {
			delete(a.lastRTT, k)
		}
	}
}

func (a *Aggregator) probeRoll(id int64, t time.Time) *ProbeRoll {
	k := probeKey{id, bucketOf(t)}
	p := a.probes[k]
	if p == nil {
		p = &ProbeRoll{}
		a.probes[k] = p
	}
	return p
}

// AddHTTP folds one HTTP sample into the current bucket.
func (a *Aggregator) AddHTTP(s HTTPSample) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.probeRoll(s.ProbeID, s.TS)
	if !s.CertNotAfter.IsZero() {
		p.CertNotAfter = us(s.CertNotAfter)
	}
	if s.Error != "" {
		p.AddError()
		return
	}
	p.AddOK(ms(s.DNS), ms(s.Connect), ms(s.TLS), ms(s.TTFB), ms(s.Transfer), ms(s.Total))
}

// AddTCP folds one TCP connect sample into the current bucket.
func (a *Aggregator) AddTCP(s TCPSample) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.probeRoll(s.ProbeID, s.TS)
	if s.Error != "" {
		p.AddError()
		return
	}
	c := ms(s.Connect)
	p.AddOK(0, c, 0, 0, 0, c)
}

// AddDNS folds one DNS probe sample into the current bucket.
func (a *Aggregator) AddDNS(s DNSSample) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.probeRoll(s.ProbeID, s.TS)
	if s.Error != "" {
		p.AddError()
		return
	}
	v := ms(s.RTT)
	p.AddOK(0, 0, 0, 0, 0, v)
}

// Flush removes and returns every bucket whose minute ended at or before cutoff, one
// MinuteBatch per minute in chronological order.
func (a *Aggregator) Flush(cutoff time.Time) []MinuteBatch {
	return a.flush(func(bucket int64) bool {
		return time.UnixMicro(bucket).Add(MinuteStep).Compare(cutoff) <= 0
	})
}

// FlushAll removes and returns every bucket, complete or not (shutdown).
func (a *Aggregator) FlushAll() []MinuteBatch {
	return a.flush(func(int64) bool { return true })
}

func (a *Aggregator) flush(due func(bucket int64) bool) []MinuteBatch {
	a.mu.Lock()
	defer a.mu.Unlock()
	byBucket := map[int64]*MinuteBatch{}
	get := func(b int64) *MinuteBatch {
		mb := byBucket[b]
		if mb == nil {
			mb = &MinuteBatch{Bucket: fromUs(b)}
			byBucket[b] = mb
		}
		return mb
	}
	for k, r := range a.icmp {
		if due(k.bucket) {
			mb := get(k.bucket)
			mb.ICMP = append(mb.ICMP, ICMPRow{TargetID: k.target, TTL: k.ttl, PathID: k.path, Bucket: k.bucket, Roll: r})
			delete(a.icmp, k)
		}
	}
	for k, p := range a.probes {
		if due(k.bucket) {
			mb := get(k.bucket)
			mb.Probes = append(mb.Probes, ProbeRollRow{ProbeID: k.probe, Bucket: k.bucket, Roll: p})
			delete(a.probes, k)
		}
	}
	out := make([]MinuteBatch, 0, len(byBucket))
	for _, mb := range byBucket {
		sort.Slice(mb.ICMP, func(i, j int) bool {
			x, y := mb.ICMP[i], mb.ICMP[j]
			if x.TargetID != y.TargetID {
				return x.TargetID < y.TargetID
			}
			if x.TTL != y.TTL {
				return x.TTL < y.TTL
			}
			return x.PathID < y.PathID
		})
		sort.Slice(mb.Probes, func(i, j int) bool { return mb.Probes[i].ProbeID < mb.Probes[j].ProbeID })
		out = append(out, *mb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bucket.Before(out[j].Bucket) })
	return out
}

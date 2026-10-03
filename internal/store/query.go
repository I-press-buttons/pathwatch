package store

import (
	"database/sql"
	"sort"
	"time"
)

// Tier is a storage resolution.
type Tier int

// Resolution tiers: raw rounds for ranges <= 6h, 1-minute rollups <= 7d, 1-hour rollups beyond.
const (
	TierRaw Tier = iota
	Tier1m
	Tier1h
)

// Tier thresholds.
const (
	RawMaxRange = 6 * time.Hour
	M1MaxRange  = 7 * 24 * time.Hour
)

func (t Tier) String() string {
	switch t {
	case Tier1m:
		return "1m"
	case Tier1h:
		return "1h"
	}
	return "raw"
}

// Native is the finest bucket width of the tier.
func (t Tier) Native() time.Duration {
	switch t {
	case Tier1m:
		return time.Minute
	case Tier1h:
		return time.Hour
	}
	return time.Second
}

// TierFor picks the tier for a range.
func TierFor(from, to time.Time) Tier {
	d := to.Sub(from)
	switch {
	case d <= RawMaxRange:
		return TierRaw
	case d <= M1MaxRange:
		return Tier1m
	}
	return Tier1h
}

// Plan describes the bucket grid of a query.
type Plan struct {
	Tier Tier
	From time.Time // aligned bucket origin (<= requested from)
	To   time.Time // requested end
	Step time.Duration
	N    int
}

// MakePlan lays out about `buckets` buckets over [from, to] with the tier chosen by range.
func MakePlan(from, to time.Time, buckets int) Plan {
	if buckets <= 0 {
		buckets = 300
	}
	if buckets > 2000 {
		buckets = 2000
	}
	if !to.After(from) {
		from = to.Add(-time.Hour)
	}
	tier := TierFor(from, to)
	native := tier.Native()
	step := to.Sub(from) / time.Duration(buckets)
	if step < native {
		step = native
	}
	if rem := step % native; rem != 0 {
		step += native - rem
	}
	origin := time.UnixMilli(from.UnixMilli() / step.Milliseconds() * step.Milliseconds()).UTC()
	n := int((to.Sub(origin) + step - 1) / step)
	if n < 1 {
		n = 1
	}
	return Plan{Tier: tier, From: origin, To: to, Step: step, N: n}
}

// SinglePlan aggregates the whole range into one bucket using the given tier.
func SinglePlan(from, to time.Time, tier Tier) Plan {
	return Plan{Tier: tier, From: from, To: to, Step: to.Sub(from), N: 1}
}

// Index returns the bucket index of t, or -1 when outside the plan.
func (p Plan) Index(t time.Time) int {
	if t.Before(p.From) || p.Step <= 0 {
		return -1
	}
	i := int(t.Sub(p.From) / p.Step)
	if i >= p.N {
		if t.After(p.To) {
			return -1
		}
		i = p.N - 1
	}
	return i
}

// BucketStart is the start time of bucket i.
func (p Plan) BucketStart(i int) time.Time { return p.From.Add(time.Duration(i) * p.Step) }

type cellKey struct {
	path int64
	ttl  int
	b    int
}

// ICMPCells holds per-(path, ttl, bucket) statistics for one target and plan.
type ICMPCells struct {
	Plan     Plan
	cells    map[cellKey]*Roll
	paths    map[int64]PathRow
	lastResp map[int64]int // per path: highest TTL with a reply
	maxTTL   int
}

// ICMPCells loads the target's ICMP statistics on the plan's grid.
func (s *Store) ICMPCells(targetID int64, p Plan) (*ICMPCells, error) {
	c := &ICMPCells{Plan: p, cells: map[cellKey]*Roll{}, lastResp: map[int64]int{}}
	from, to := us(p.From), us(p.To)
	if p.Tier == TierRaw {
		rows, err := s.rdb.Query(`SELECT ts, path_id, hop_count, results FROM icmp_rounds WHERE target_id=? AND ts>=? AND ts<=? ORDER BY ts`, targetID, from, to)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		prev := map[int]float64{}
		for rows.Next() {
			var ts, path int64
			var hc int
			var blob []byte
			if err := rows.Scan(&ts, &path, &hc, &blob); err != nil {
				return nil, err
			}
			hops, err := DecodeHops(blob, hc)
			if err != nil {
				continue
			}
			b := p.Index(fromUs(ts))
			if b < 0 {
				continue
			}
			for _, h := range hops {
				r := c.cell(path, h.TTL, b)
				if h.Responded() {
					v := h.RTTms()
					pv, ok := prev[h.TTL]
					r.AddReply(v, pv, ok)
					prev[h.TTL] = v
					if h.TTL > c.lastResp[path] {
						c.lastResp[path] = h.TTL
					}
				} else {
					r.AddLoss()
				}
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	} else {
		table := "icmp_rollup_1m"
		if p.Tier == Tier1h {
			table = "icmp_rollup_1h"
		}
		// hour rollups are keyed by their start; include the hour containing From
		lo := from
		if p.Tier == Tier1h {
			lo = p.From.Truncate(time.Hour).UnixMicro()
		}
		rows, err := s.rdb.Query(`SELECT bucket, ttl, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter, hist FROM `+table+` WHERE target_id=? AND bucket>=? AND bucket<=?`, targetID, lo, to)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var bucket, path, n, lost int64
			var ttl int
			var mn, av, mx, jt sql.NullFloat64
			var hist []byte
			if err := rows.Scan(&bucket, &ttl, &path, &n, &lost, &mn, &av, &mx, &jt, &hist); err != nil {
				return nil, err
			}
			t := fromUs(bucket)
			if t.Before(p.From) {
				t = p.From // the hour that contains From
			}
			b := p.Index(t)
			if b < 0 {
				continue
			}
			roll := rollFromRow(n, lost, mn.Float64, av.Float64, mx.Float64, jt.Float64, hist)
			c.cell(path, ttl, b).Merge(roll)
			if roll.Replies() > 0 && ttl > c.lastResp[path] {
				c.lastResp[path] = ttl
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	ids := make([]int64, 0, len(c.lastResp))
	seen := map[int64]bool{}
	for k := range c.cells {
		if !seen[k.path] {
			seen[k.path] = true
			ids = append(ids, k.path)
		}
	}
	paths, err := s.PathsOf(ids)
	if err != nil {
		return nil, err
	}
	c.paths = paths
	return c, nil
}

func (c *ICMPCells) cell(path int64, ttl, b int) *Roll {
	k := cellKey{path, ttl, b}
	r := c.cells[k]
	if r == nil {
		r = &Roll{}
		c.cells[k] = r
		if ttl > c.maxTTL {
			c.maxTTL = ttl
		}
	}
	return r
}

// LastRespTTL is the highest TTL that got a reply in any path version.
func (c *ICMPCells) LastRespTTL() int {
	m := 0
	for _, v := range c.lastResp {
		if v > m {
			m = v
		}
	}
	return m
}

// MaxTTL is the highest TTL with any data.
func (c *ICMPCells) MaxTTL() int { return c.maxTTL }

// PathIDs returns the path versions seen, oldest id first.
func (c *ICMPCells) PathIDs() []int64 {
	var out []int64
	seen := map[int64]bool{}
	for k := range c.cells {
		if !seen[k.path] {
			seen[k.path] = true
			out = append(out, k.path)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Series returns the merged (across path versions) per-bucket stats of a TTL. Empty buckets are nil.
func (c *ICMPCells) Series(ttl int) []*Roll {
	out := make([]*Roll, c.Plan.N)
	for k, r := range c.cells {
		if k.ttl != ttl {
			continue
		}
		if out[k.b] == nil {
			out[k.b] = &Roll{}
		}
		out[k.b].Merge(r)
	}
	return out
}

// Total merges every bucket of a TTL.
func (c *ICMPCells) Total(ttl int) *Roll {
	t := &Roll{}
	for k, r := range c.cells {
		if k.ttl == ttl {
			t.Merge(r)
		}
	}
	return t
}

// e2eTTL is the TTL regarded as "the destination" for a path: the destination TTL when the
// destination answered ICMP, else (fallbackLast) the last responding hop.
func (c *ICMPCells) e2eTTL(path int64, fallbackLast bool) int {
	if p, ok := c.paths[path]; ok && p.DestTTL > 0 {
		return p.DestTTL
	}
	if fallbackLast {
		return c.lastResp[path]
	}
	return 0
}

// E2ESeries returns the destination's per-bucket stats, resolving the destination TTL per path
// version. ok is false when no cell belongs to a destination.
func (c *ICMPCells) E2ESeries(fallbackLast bool) ([]*Roll, bool) {
	out := make([]*Roll, c.Plan.N)
	found := false
	for k, r := range c.cells {
		if t := c.e2eTTL(k.path, fallbackLast); t == 0 || k.ttl != t {
			continue
		}
		if out[k.b] == nil {
			out[k.b] = &Roll{}
		}
		out[k.b].Merge(r)
		found = true
	}
	return out, found
}

// E2ETotal merges the destination over all buckets.
func (c *ICMPCells) E2ETotal(fallbackLast bool) (*Roll, bool) {
	s, ok := c.E2ESeries(fallbackLast)
	t := &Roll{}
	for _, r := range s {
		t.Merge(r)
	}
	return t, ok
}

// ProbeCells holds per-bucket statistics of one probe.
type ProbeCells struct {
	Plan  Plan
	Rolls []*ProbeRoll // nil = no samples in the bucket
}

// ProbeCells loads one probe's statistics on the plan's grid. typ is http, tcp or dns.
func (s *Store) ProbeCells(probeID int64, typ string, p Plan) (*ProbeCells, error) {
	pc := &ProbeCells{Plan: p, Rolls: make([]*ProbeRoll, p.N)}
	get := func(b int) *ProbeRoll {
		if pc.Rolls[b] == nil {
			pc.Rolls[b] = &ProbeRoll{}
		}
		return pc.Rolls[b]
	}
	from, to := us(p.From), us(p.To)
	if p.Tier == TierRaw {
		var rows *sql.Rows
		var err error
		switch typ {
		case "http":
			rows, err = s.rdb.Query(`SELECT ts, COALESCE(dns_us,0), COALESCE(connect_us,0), COALESCE(tls_us,0), COALESCE(ttfb_us,0), COALESCE(transfer_us,0), COALESCE(total_us,0), cert_not_after, error FROM http_samples WHERE probe_id=? AND ts>=? AND ts<=? ORDER BY ts`, probeID, from, to)
		case "tcp":
			rows, err = s.rdb.Query(`SELECT ts, COALESCE(connect_us,0), error FROM tcp_samples WHERE probe_id=? AND ts>=? AND ts<=? ORDER BY ts`, probeID, from, to)
		default:
			rows, err = s.rdb.Query(`SELECT ts, COALESCE(rtt_us,0), error FROM dns_samples WHERE probe_id=? AND ts>=? AND ts<=? ORDER BY ts`, probeID, from, to)
		}
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var ts int64
			var e sql.NullString
			var b int
			f := func(us int64) float64 { return float64(us) / 1000 }
			switch typ {
			case "http":
				var dns, conn, tls, ttfb, tr, tot int64
				var cert sql.NullInt64
				if err := rows.Scan(&ts, &dns, &conn, &tls, &ttfb, &tr, &tot, &cert, &e); err != nil {
					return nil, err
				}
				if b = p.Index(fromUs(ts)); b < 0 {
					continue
				}
				r := get(b)
				if cert.Valid {
					r.CertNotAfter = cert.Int64
				}
				if e.Valid && e.String != "" {
					r.AddError()
				} else {
					r.AddOK(f(dns), f(conn), f(tls), f(ttfb), f(tr), f(tot))
				}
			default:
				var v int64
				if err := rows.Scan(&ts, &v, &e); err != nil {
					return nil, err
				}
				if b = p.Index(fromUs(ts)); b < 0 {
					continue
				}
				r := get(b)
				if e.Valid && e.String != "" {
					r.AddError()
				} else if typ == "tcp" {
					r.AddOK(0, f(v), 0, 0, 0, f(v))
				} else {
					r.AddOK(0, 0, 0, 0, 0, f(v))
				}
			}
		}
		return pc, rows.Err()
	}
	table := "probe_rollup_1m"
	lo := from
	if p.Tier == Tier1h {
		table = "probe_rollup_1h"
		lo = p.From.Truncate(time.Hour).UnixMicro()
	}
	rows, err := s.rdb.Query(`SELECT bucket, n, errors, dns_avg, connect_avg, tls_avg, ttfb_avg, transfer_avg, total_min, total_avg, total_max, hist, cert_not_after FROM `+table+` WHERE probe_id=? AND bucket>=? AND bucket<=? ORDER BY bucket`, probeID, lo, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var bucket, n, e int64
		var dns, conn, tls, ttfb, tr, tmin, tavg, tmax sql.NullFloat64
		var hist []byte
		var cert sql.NullInt64
		if err := rows.Scan(&bucket, &n, &e, &dns, &conn, &tls, &ttfb, &tr, &tmin, &tavg, &tmax, &hist, &cert); err != nil {
			return nil, err
		}
		t := fromUs(bucket)
		if t.Before(p.From) {
			t = p.From
		}
		b := p.Index(t)
		if b < 0 {
			continue
		}
		get(b).Merge(probeRollFromRow(n, e, dns.Float64, conn.Float64, tls.Float64, ttfb.Float64, tr.Float64, tmin.Float64, tavg.Float64, tmax.Float64, hist, cert.Int64))
	}
	return pc, rows.Err()
}

// Total merges all buckets.
func (pc *ProbeCells) Total() *ProbeRoll {
	t := &ProbeRoll{}
	for _, r := range pc.Rolls {
		t.Merge(r)
	}
	return t
}

// LatestCert returns the newest certificate expiry recorded for an HTTP probe.
func (s *Store) LatestCert(probeID int64) (time.Time, bool) {
	var v sql.NullInt64
	_ = s.rdb.QueryRow(`SELECT cert_not_after FROM http_samples WHERE probe_id=? AND cert_not_after IS NOT NULL ORDER BY ts DESC LIMIT 1`, probeID).Scan(&v)
	if !v.Valid {
		_ = s.rdb.QueryRow(`SELECT cert_not_after FROM probe_rollup_1m WHERE probe_id=? AND cert_not_after IS NOT NULL ORDER BY bucket DESC LIMIT 1`, probeID).Scan(&v)
	}
	if !v.Valid {
		return time.Time{}, false
	}
	return fromUs(v.Int64), true
}

// LastRounds returns up to n of the newest rounds of a target (newest last).
func (s *Store) LastRounds(targetID int64, n int) ([]Round, error) {
	rows, err := s.rdb.Query(`SELECT ts, path_id, hop_count, results FROM icmp_rounds WHERE target_id=? ORDER BY ts DESC LIMIT ?`, targetID, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Round
	for rows.Next() {
		var ts, path int64
		var hc int
		var blob []byte
		if err := rows.Scan(&ts, &path, &hc, &blob); err != nil {
			return nil, err
		}
		hops, err := DecodeHops(blob, hc)
		if err != nil {
			continue
		}
		out = append(out, Round{TargetID: targetID, TS: fromUs(ts), PathID: path, Hops: hops})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// LastProbeSample returns the timestamp of the newest sample of a probe.
func (s *Store) LastProbeSample(probeID int64, typ string) (time.Time, bool) {
	table := map[string]string{"http": "http_samples", "tcp": "tcp_samples", "dns": "dns_samples"}[typ]
	if table == "" {
		return time.Time{}, false
	}
	var v sql.NullInt64
	if err := s.rdb.QueryRow(`SELECT MAX(ts) FROM `+table+` WHERE probe_id=?`, probeID).Scan(&v); err != nil || !v.Valid {
		return time.Time{}, false
	}
	return fromUs(v.Int64), true
}

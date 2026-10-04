package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
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

// E2EMode limits ICMPCells to what E2ESeries and E2ETotal read.
type E2EMode int

// E2E modes. The destination of a path version is the TTL in paths.dest_ttl; it is 0 when the
// destination never answered ICMP.
const (
	E2EOff        E2EMode = iota // load every TTL
	E2EDest                      // the destination TTL of each path version (E2ESeries(false))
	E2EDestOrLast                // ... and the last responding hop of the others (E2ESeries(true))
)

// CellOpts narrows what ICMPCells and ProbeCells load. The zero value loads everything. The
// accessors of ICMPCells only see what was loaded.
type CellOpts struct {
	// NoHist leaves out the latency histograms: Quantile reports ok=false. Rollup rows are
	// read without their hist column.
	NoHist bool
	// TTL, when set, loads only that TTL (ICMPCells).
	TTL int
	// E2E loads only the TTLs E2ESeries and E2ETotal use (ICMPCells). It takes precedence
	// over TTL; E2ESeries(true) needs E2EDestOrLast.
	E2E E2EMode
	// LastResp makes LastRespTTL cover every TTL instead of the loaded ones. It costs an
	// aggregate query on the rollup tiers; the raw tier decodes every hop anyway. E2EDestOrLast
	// needs the last responding hops of the path versions without a destination, and then
	// reports every TTL whether LastResp is set or not.
	LastResp bool
}

// hopFilter says which (path, ttl) results of a load are folded into cells.
type hopFilter struct {
	all  bool          // every TTL
	ttl  int           // without all and want: this TTL only
	want map[int64]int // E2E, per path version: the TTL to keep; 0 = its last responding hop
	open int           // path versions of want that are still 0
}

func newHopFilter(o CellOpts, paths map[int64]PathRow) hopFilter {
	switch {
	case o.E2E != E2EOff:
		f := hopFilter{want: map[int64]int{}}
		for id, p := range paths {
			switch {
			case p.DestTTL > 0:
				f.want[id] = p.DestTTL
			case o.E2E == E2EDestOrLast:
				f.want[id] = 0
				f.open++
			}
		}
		return f
	case o.TTL > 0:
		return hopFilter{ttl: o.TTL}
	}
	return hopFilter{all: true}
}

func (f *hopFilter) keep(path int64, ttl int) bool {
	switch {
	case f.all:
		return true
	case f.want == nil:
		return ttl == f.ttl
	}
	t, ok := f.want[path]
	return ok && (t == 0 || ttl == t)
}

// ttls lists the distinct TTLs a partial filter keeps, for the SQL side of a rollup read.
func (f *hopFilter) ttls() []int64 {
	if f.want == nil {
		return []int64{int64(f.ttl)}
	}
	seen := map[int]bool{}
	var out []int64
	for _, t := range f.want {
		if !seen[t] {
			seen[t] = true
			out = append(out, int64(t))
		}
	}
	return out
}

// numRow scans the numeric columns of a rollup row into interface values, which database/sql
// copies as they are. Typed destinations go through reflection instead, and that together
// with the driver is most of the cost of a row. NULL reads as 0, as with sql.NullFloat64.
type numRow struct {
	v    []any
	dest []any // the Scan destinations: v, then the extra ones given to newNumRow
}

func newNumRow(n int, extra ...any) *numRow {
	r := &numRow{v: make([]any, n), dest: make([]any, n, n+len(extra))}
	for i := range r.v {
		r.dest[i] = &r.v[i]
	}
	r.dest = append(r.dest, extra...)
	return r
}

func (r *numRow) i64(i int) int64 {
	x, _ := r.v[i].(int64)
	return x
}

func (r *numRow) f64(i int) float64 {
	switch x := r.v[i].(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	}
	return 0
}

// ICMPCells holds per-(path, ttl, bucket) statistics for one target and plan.
type ICMPCells struct {
	Plan     Plan
	cells    map[cellKey]*Roll
	paths    map[int64]PathRow
	lastResp map[int64]int // per path: highest TTL with a reply
	maxTTL   int
}

// ICMPCells loads the target's ICMP statistics on the plan's grid. o limits what is loaded;
// ctx cancels the queries.
func (s *Store) ICMPCells(ctx context.Context, targetID int64, p Plan, o CellOpts) (*ICMPCells, error) {
	c := &ICMPCells{Plan: p, cells: map[cellKey]*Roll{}, lastResp: map[int64]int{}}
	// The path versions come first: their destination TTLs decide what an E2E load keeps.
	paths, err := s.pathsOfTarget(ctx, targetID)
	if err != nil {
		return nil, err
	}
	c.paths = paths
	f := newHopFilter(o, paths)
	if p.Tier == TierRaw {
		err = s.loadRawCells(ctx, c, targetID, f, o)
	} else {
		err = s.loadRollupCells(ctx, c, targetID, f, o)
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// pathsOfTarget returns every path version of a target by id.
func (s *Store) pathsOfTarget(ctx context.Context, targetID int64) (map[int64]PathRow, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT `+pathCols+` FROM paths WHERE target_id=?`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]PathRow{}
	for rows.Next() {
		p, err := scanPath(rows)
		if err != nil {
			return nil, err
		}
		out[p.ID] = p
	}
	return out, rows.Err()
}

var errRoundBlob = errors.New("round blob: truncated or malformed")

// appendHops is DecodeHops into a reused buffer: a round of hops costs no allocation.
func appendHops(buf []Hop, b []byte, n int) ([]Hop, error) {
	buf = buf[:0]
	for ttl := 1; ttl <= n; ttl++ {
		if len(b) < 1 {
			return nil, errRoundBlob
		}
		h := Hop{TTL: ttl, Status: b[0]}
		b = b[1:]
		rtt, k := binary.Uvarint(b)
		if k <= 0 {
			return nil, errRoundBlob
		}
		b = b[k:]
		resp, k := binary.Uvarint(b)
		if k <= 0 {
			return nil, errRoundBlob
		}
		b = b[k:]
		h.RTT = time.Duration(rtt) * time.Microsecond
		h.Resp = int(resp)
		buf = append(buf, h)
	}
	return buf, nil
}

func (s *Store) loadRawCells(ctx context.Context, c *ICMPCells, targetID int64, f hopFilter, o CellOpts) error {
	p := c.Plan
	rows, err := s.rdb.QueryContext(ctx, `SELECT ts, path_id, hop_count, results FROM icmp_rounds WHERE target_id=? AND ts>=? AND ts<=? ORDER BY ts`, targetID, us(p.From), us(p.To))
	if err != nil {
		return err
	}
	defer rows.Close()
	// The jitter chain of a TTL runs through every round, so it is followed for the TTLs that
	// are not kept as well: the kept cells then match a full load.
	type lastRTT struct {
		ms float64
		ok bool
	}
	var prev []lastRTT
	every := o.LastResp || f.open > 0 // the last responding hop over every TTL, not just the kept ones
	var hops []Hop
	var ts, path int64
	var hc int
	var blob sql.RawBytes // read before the next row
	for rows.Next() {
		if err := rows.Scan(&ts, &path, &hc, &blob); err != nil {
			return err
		}
		b := p.Index(fromUs(ts))
		if b < 0 {
			continue
		}
		var err error
		if hops, err = appendHops(hops, blob, hc); err != nil {
			continue
		}
		if len(prev) <= hc {
			prev = append(prev, make([]lastRTT, hc+1-len(prev))...)
		}
		top := 0
		for _, h := range hops {
			keep := f.keep(path, h.TTL)
			if !h.Responded() {
				if keep {
					c.cell(path, h.TTL, b).AddLoss()
				}
				continue
			}
			v := h.RTTms()
			if keep {
				r, pv := c.cell(path, h.TTL, b), prev[h.TTL]
				if o.NoHist {
					r.addStats(v, pv.ms, pv.ok)
				} else {
					r.AddReply(v, pv.ms, pv.ok)
				}
			}
			prev[h.TTL] = lastRTT{v, true}
			if (keep || every) && h.TTL > top {
				top = h.TTL
			}
		}
		if top > c.lastResp[path] {
			c.lastResp[path] = top
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if f.open > 0 {
		// Path versions without a destination kept every TTL: their last responding hop is
		// only known now.
		c.maxTTL = 0
		for k := range c.cells {
			if f.want[k.path] == 0 && k.ttl != c.lastResp[k.path] {
				delete(c.cells, k)
			} else if k.ttl > c.maxTTL {
				c.maxTTL = k.ttl
			}
		}
	}
	return nil
}

func (s *Store) loadRollupCells(ctx context.Context, c *ICMPCells, targetID int64, f hopFilter, o CellOpts) error {
	p := c.Plan
	table := "icmp_rollup_1m"
	lo, to := us(p.From), us(p.To)
	if p.Tier == Tier1h {
		table = "icmp_rollup_1h"
		// hour rollups are keyed by their start; include the hour containing From
		lo = p.From.Truncate(time.Hour).UnixMicro()
	}
	cond, args := "", []any{targetID, lo, to}
	if !f.all {
		if o.LastResp || f.open > 0 {
			// The last responding hop of a path version is the highest TTL with a reply over
			// the whole range, which a partial load cannot tell.
			last, err := s.lastRespByPath(ctx, table, targetID, lo, to)
			if err != nil {
				return err
			}
			c.lastResp = last
			for id, t := range f.want {
				if t != 0 {
					continue
				}
				if t = last[id]; t > 0 {
					f.want[id] = t
				} else {
					delete(f.want, id) // no reply, nothing to keep
				}
			}
		}
		ttls := f.ttls()
		if len(ttls) == 0 {
			return nil
		}
		in, a := inClause(ttls)
		cond = " AND ttl IN " + in
		args = append(args, a...)
	}
	cols := `bucket, ttl, path_id, n, lost, rtt_min, rtt_avg, rtt_max, jitter`
	var hist sql.RawBytes // read before the next row; stays nil without the column
	var extra []any
	if !o.NoHist {
		cols += `, hist`
		extra = append(extra, &hist)
	}
	row := newNumRow(9, extra...)
	rows, err := s.rdb.QueryContext(ctx, `SELECT `+cols+` FROM `+table+` WHERE target_id=? AND bucket>=? AND bucket<=?`+cond, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(row.dest...); err != nil {
			return err
		}
		bucket, ttl, path, n, lost := row.i64(0), int(row.i64(1)), row.i64(2), row.i64(3), row.i64(4)
		if !f.keep(path, ttl) {
			continue
		}
		t := fromUs(bucket)
		if t.Before(p.From) {
			t = p.From // the hour that contains From
		}
		b := p.Index(t)
		if b < 0 {
			continue
		}
		c.cell(path, ttl, b).mergeRow(n, lost, row.f64(5), row.f64(6), row.f64(7), row.f64(8), hist)
		if n > lost && ttl > c.lastResp[path] {
			c.lastResp[path] = ttl
		}
	}
	return rows.Err()
}

// lastRespByPath returns the highest TTL with a reply per path version in a rollup table.
func (s *Store) lastRespByPath(ctx context.Context, table string, targetID, lo, hi int64) (map[int64]int, error) {
	rows, err := s.rdb.QueryContext(ctx, `SELECT path_id, MAX(ttl) FROM `+table+` WHERE target_id=? AND bucket>=? AND bucket<=? AND n>lost GROUP BY path_id`, targetID, lo, hi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var path int64
		var ttl int
		if err := rows.Scan(&path, &ttl); err != nil {
			return nil, err
		}
		out[path] = ttl
	}
	return out, rows.Err()
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

// ProbeCells loads one probe's statistics on the plan's grid. typ is http, tcp or dns. Of o only
// NoHist applies; ctx cancels the queries.
func (s *Store) ProbeCells(ctx context.Context, probeID int64, typ string, p Plan, o CellOpts) (*ProbeCells, error) {
	pc := &ProbeCells{Plan: p, Rolls: make([]*ProbeRoll, p.N)}
	get := func(b int) *ProbeRoll {
		if pc.Rolls[b] == nil {
			pc.Rolls[b] = &ProbeRoll{}
		}
		return pc.Rolls[b]
	}
	addOK := func(r *ProbeRoll, dns, connect, tls, ttfb, transfer, total float64) {
		if o.NoHist {
			r.addOKStats(dns, connect, tls, ttfb, transfer, total)
		} else {
			r.AddOK(dns, connect, tls, ttfb, transfer, total)
		}
	}
	from, to := us(p.From), us(p.To)
	if p.Tier == TierRaw {
		var rows *sql.Rows
		var err error
		switch typ {
		case "http":
			rows, err = s.rdb.QueryContext(ctx, `SELECT ts, COALESCE(dns_us,0), COALESCE(connect_us,0), COALESCE(tls_us,0), COALESCE(ttfb_us,0), COALESCE(transfer_us,0), COALESCE(total_us,0), cert_not_after, error FROM http_samples WHERE probe_id=? AND ts>=? AND ts<=? ORDER BY ts`, probeID, from, to)
		case "tcp":
			rows, err = s.rdb.QueryContext(ctx, `SELECT ts, COALESCE(connect_us,0), error FROM tcp_samples WHERE probe_id=? AND ts>=? AND ts<=? ORDER BY ts`, probeID, from, to)
		default:
			rows, err = s.rdb.QueryContext(ctx, `SELECT ts, COALESCE(rtt_us,0), error FROM dns_samples WHERE probe_id=? AND ts>=? AND ts<=? ORDER BY ts`, probeID, from, to)
		}
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ts, v, dns, conn, tls, ttfb, tr, tot int64
		var e sql.NullString
		var cert sql.NullInt64
		f := func(us int64) float64 { return float64(us) / 1000 }
		for rows.Next() {
			var b int
			switch typ {
			case "http":
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
					addOK(r, f(dns), f(conn), f(tls), f(ttfb), f(tr), f(tot))
				}
			default:
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
					addOK(r, 0, f(v), 0, 0, 0, f(v))
				} else {
					addOK(r, 0, 0, 0, 0, 0, f(v))
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
	cols := `bucket, n, errors, dns_avg, connect_avg, tls_avg, ttfb_avg, transfer_avg, total_min, total_avg, total_max, cert_not_after`
	var hist sql.RawBytes // read before the next row; stays nil without the column
	var extra []any
	if !o.NoHist {
		cols += `, hist`
		extra = append(extra, &hist)
	}
	row := newNumRow(12, extra...)
	rows, err := s.rdb.QueryContext(ctx, `SELECT `+cols+` FROM `+table+` WHERE probe_id=? AND bucket>=? AND bucket<=? ORDER BY bucket`, probeID, lo, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(row.dest...); err != nil {
			return nil, err
		}
		t := fromUs(row.i64(0))
		if t.Before(p.From) {
			t = p.From
		}
		b := p.Index(t)
		if b < 0 {
			continue
		}
		get(b).mergeRow(row.i64(1), row.i64(2), row.f64(3), row.f64(4), row.f64(5), row.f64(6), row.f64(7), row.f64(8), row.f64(9), row.f64(10), hist, row.i64(11))
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

// LatestCert returns the newest certificate expiry recorded for an HTTP probe. It is answered
// from an in-memory cache that RecordHTTP keeps current; the database is read once per probe.
func (s *Store) LatestCert(probeID int64) (time.Time, bool) {
	return s.latestCert(probeID)
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

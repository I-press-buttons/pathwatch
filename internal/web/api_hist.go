package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"strconv"

	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// e2ePoint is one end-to-end bucket.
type e2ePoint struct {
	n                          int64
	avg, min, max, p95         float64
	jitter, loss               float64
	haveAvg, haveJit, haveLoss bool
}

type e2eResult struct {
	points   []e2ePoint
	source   string // icmp | tcp | last_hop | http | ""
	ttl      int    // destination or last-hop TTL (icmp / last_hop)
	lastResp int    // highest responding TTL in the range; exact with detail, and for a last_hop series
}

func pointFromRoll(r *store.Roll) e2ePoint {
	var p e2ePoint
	if r == nil || r.N == 0 {
		return p
	}
	p.n = r.N
	p.avg, p.haveAvg = r.Avg()
	if p.haveAvg {
		p.min, p.max = r.Min, r.Max
		p.p95, _ = r.Quantile(0.95)
	}
	p.jitter, p.haveJit = r.Jitter()
	p.loss, p.haveLoss = r.LossPct()
	return p
}

func pointFromProbe(r *store.ProbeRoll) e2ePoint {
	var p e2ePoint
	if r == nil || r.N == 0 {
		return p
	}
	p.n = r.N
	p.avg, p.haveAvg = r.AvgTotal()
	if p.haveAvg {
		p.min, p.max = r.TotalMin, r.TotalMax
		p.p95, _ = r.Quantile(0.95)
	}
	p.loss, p.haveLoss = r.FailPct()
	return p
}

// e2e returns the end-to-end series of a target: destination ICMP, else the TCP probe (the
// signal for destinations that drop ICMP), else the last responding hop, else HTTP. Only the
// hops that series can come from are loaded, without histograms. detail keeps the histograms
// (the points' p95) and makes lastResp exact, which the 5-minute summary needs.
func (s *Server) e2e(ctx context.Context, v targetView, plan store.Plan, detail bool) (e2eResult, error) {
	var res e2eResult
	unresp := v.hasSt && v.state.ICMPUnresponsive
	tcp := v.probesOfType(config.ProbeTCP)
	// lastResp is also the TTL of a last_hop series, which the unresponsive state leads to
	opts := store.CellOpts{NoHist: !detail, LastResp: detail || unresp, E2E: store.E2EDestOrLast}
	if len(tcp) > 0 {
		opts.E2E = store.E2EDest // the TCP probe comes before the last hop
	}
	cells, err := s.d.Store.ICMPCells(ctx, v.row.ID, plan, opts)
	if err != nil {
		return res, err
	}
	res.lastResp = cells.LastRespTTL()
	probeOpts := store.CellOpts{NoHist: !detail}
	latestDest := func() int {
		if p, err := s.d.Store.LatestPath(v.row.ID); err == nil {
			return p.DestTTL
		}
		return 0
	}
	if !unresp {
		if rolls, ok := cells.E2ESeries(false); ok {
			res.source, res.ttl = "icmp", latestDest()
			for _, r := range rolls {
				res.points = append(res.points, pointFromRoll(r))
			}
			return res, nil
		}
	}
	if len(tcp) > 0 {
		pc, err := s.d.Store.ProbeCells(ctx, tcp[0].ID, config.ProbeTCP, plan, probeOpts)
		if err != nil {
			return res, err
		}
		res.source = config.ProbeTCP
		for _, r := range pc.Rolls {
			res.points = append(res.points, pointFromProbe(r))
		}
		return res, nil
	}
	if rolls, ok := cells.E2ESeries(true); ok {
		res.source, res.ttl = "last_hop", res.lastResp
		for _, r := range rolls {
			res.points = append(res.points, pointFromRoll(r))
		}
		return res, nil
	}
	if ps := v.probesOfType(config.ProbeHTTP); len(ps) > 0 {
		pc, err := s.d.Store.ProbeCells(ctx, ps[0].ID, config.ProbeHTTP, plan, probeOpts)
		if err != nil {
			return res, err
		}
		res.source = config.ProbeHTTP
		for _, r := range pc.Rolls {
			res.points = append(res.points, pointFromProbe(r))
		}
	}
	return res, nil
}

// queryFailed answers a failed query. A client that went away mid-query (its request context
// is done) is not a server error: there is nobody to answer and nothing to log.
func (s *Server) queryFailed(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		return
	}
	s.internal(w, r, err)
}

// rangeAndPlan parses range/buckets for history endpoints.
func (s *Server) rangeAndPlan(w http.ResponseWriter, r *http.Request, defBuckets int) (store.Plan, bool) {
	from, to, err := s.parseRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return store.Plan{}, false
	}
	b, err := intParam(r, "buckets", defBuckets, 1, 2000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return store.Plan{}, false
	}
	return store.MakePlan(from, to, b), true
}

// ---------------------------------------------------------------------------
// overview

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	plan, ok := s.rangeAndPlan(w, r, 60)
	if !ok {
		return
	}
	rows, err := s.d.Store.Targets(false)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		e, err := s.e2e(r.Context(), s.viewOf(row), plan, false)
		if err != nil {
			s.queryFailed(w, r, err)
			return
		}
		pts := make([][]any, plan.N)
		for i := 0; i < plan.N; i++ {
			ts := plan.BucketStart(i).UnixMilli()
			if i < len(e.points) && e.points[i].n > 0 {
				p := e.points[i]
				pts[i] = []any{ts, fp(p.avg, p.haveAvg), fp(p.loss, p.haveLoss)}
			} else {
				pts[i] = []any{ts, nil, nil}
			}
		}
		out = append(out, map[string]any{"target_id": row.ID, "step_ms": plan.Step.Milliseconds(), "points": pts})
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// shared hop identity

type hopIdentity struct {
	addr     string // primary responder ("" = none)
	alts     []string
	count    int
	hostname string
	asn      *int
	asName   *string
}

type pathCtx struct {
	path    store.PathRow
	hasPath bool
	hops    map[int][]store.PathHopRow
	classes map[int]string // ttl -> rate_limited | degraded (from events)
}

func (s *Server) loadPathCtx(row store.TargetRow, plan store.Plan) (pathCtx, error) {
	var pc pathCtx
	pc.hops = map[int][]store.PathHopRow{}
	pc.classes = map[int]string{}
	p, err := s.d.Store.PathAt(row.ID, plan.To)
	if err == nil {
		pc.path, pc.hasPath = p, true
		hs, err := s.d.Store.PathHops([]int64{p.ID})
		if err != nil {
			return pc, err
		}
		for _, h := range hs[p.ID] {
			pc.hops[h.TTL] = append(pc.hops[h.TTL], h)
		}
		for t := range pc.hops {
			l := pc.hops[t]
			sort.SliceStable(l, func(i, j int) bool { return l[i].Share > l[j].Share })
		}
	} else if err != store.ErrNotFound {
		return pc, err
	}
	tid := row.ID
	evs, err := s.d.Store.Events(store.EventQuery{TargetID: &tid, From: plan.From, To: plan.To, Kinds: []string{store.EventRateLimited, store.EventDegraded}})
	if err != nil {
		return pc, err
	}
	for _, e := range evs {
		if e.TTL == nil {
			continue
		}
		if e.Kind == store.EventDegraded || pc.classes[*e.TTL] == "" {
			pc.classes[*e.TTL] = e.Kind
		}
	}
	return pc, nil
}

func (s *Server) identity(pc pathCtx, ttl int) hopIdentity {
	var id hopIdentity
	list := pc.hops[ttl]
	id.count = len(list)
	for i, h := range list {
		if i == 0 {
			id.addr = h.Address
		} else {
			id.alts = append(id.alts, h.Address)
		}
	}
	if id.addr != "" && s.d.Enrich != nil {
		if a, err := netip.ParseAddr(id.addr); err == nil {
			info := s.d.Enrich.Lookup(a)
			id.hostname = info.Hostname
			if info.ASN != 0 {
				asn := info.ASN
				id.asn = &asn
				if info.ASName != "" {
					n := info.ASName
					id.asName = &n
				}
			}
		}
	}
	return id
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// lastTTL is the last row shown for a target: the highest TTL that answered in the range, or the
// destination TTL, whichever is larger. Trailing silent TTLs are trimmed.
func lastTTL(cells *store.ICMPCells, pc pathCtx) int {
	end := cells.LastRespTTL()
	if pc.hasPath && pc.path.DestTTL > end {
		end = pc.path.DestTTL
	}
	return end
}

// ---------------------------------------------------------------------------
// hops grid

func (s *Server) handleHops(w http.ResponseWriter, r *http.Request) {
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	from, to, err := s.parseRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	plan := store.SinglePlan(from, to, store.TierFor(from, to))
	cells, err := s.d.Store.ICMPCells(r.Context(), row.ID, plan, store.CellOpts{})
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	pc, err := s.loadPathCtx(row, plan)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	resp := map[string]any{"target_id": row.ID, "path_id": nil, "resolved_ip": nil, "from": from.UnixMilli(), "to": to.UnixMilli()}
	if pc.hasPath {
		resp["path_id"] = pc.path.ID
		resp["resolved_ip"] = pc.path.ResolvedIP
	}
	// current RTT per TTL from the newest round
	cur := map[int]*float64{}
	if lr, err := s.d.Store.LastRounds(row.ID, 1); err == nil && len(lr) == 1 {
		for _, h := range lr[0].Hops {
			if h.Responded() {
				cur[h.TTL] = fp(h.RTTms(), true)
			}
		}
	}
	end := lastTTL(cells, pc)
	hops := make([]map[string]any, 0, end)
	for ttl := 1; ttl <= end; ttl++ {
		tot := cells.Total(ttl)
		id := s.identity(pc, ttl)
		isDest := pc.hasPath && pc.path.DestTTL > 0 && ttl == pc.path.DestTTL
		class := pc.classes[ttl]
		switch {
		case class != "":
		case tot.Replies() == 0 && tot.N > 0, tot.N == 0 && id.addr == "":
			class = analyze.ClassNoReply
		case isDest:
			class = "destination"
		default:
			class = analyze.ClassOK
		}
		avg, haveAvg := tot.Avg()
		jit, haveJit := tot.Jitter()
		p95, _ := tot.Quantile(0.95)
		loss, haveLoss := tot.LossPct()
		alts := id.alts
		if alts == nil {
			alts = []string{}
		}
		h := map[string]any{
			"ttl": ttl, "address": strPtr(id.addr), "hostname": strPtr(id.hostname), "asn": id.asn, "as_name": id.asName,
			"responders": id.count, "alt_addresses": alts,
			"sent": tot.N, "lost": tot.Lost, "loss_pct": fp(loss, haveLoss),
			"min_ms": fp(tot.Min, tot.Replies() > 0), "avg_ms": fp(avg, haveAvg), "max_ms": fp(tot.Max, tot.Replies() > 0),
			"cur_ms": cur[ttl], "p95_ms": fp(p95, haveAvg), "jitter_ms": fp(jit, haveJit),
			"classification": class, "is_destination": isDest,
		}
		hops = append(hops, h)
	}
	resp["hops"] = hops
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------------
// timeline

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	plan, ok := s.rangeAndPlan(w, r, 300)
	if !ok {
		return
	}
	cells, err := s.d.Store.ICMPCells(r.Context(), row.ID, plan, store.CellOpts{NoHist: true})
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	pc, err := s.loadPathCtx(row, plan)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	end := lastTTL(cells, pc)
	ttls := make([]int, 0, end)
	labels := make([]map[string]any, 0, end)
	rtt := make([][]*float64, 0, end)
	loss := make([][]*float64, 0, end)
	for ttl := 1; ttl <= end; ttl++ {
		ttls = append(ttls, ttl)
		id := s.identity(pc, ttl)
		class := pc.classes[ttl]
		if class == "" {
			class = analyze.ClassOK
			if id.addr == "" {
				class = analyze.ClassNoReply
			}
		}
		labels = append(labels, map[string]any{"ttl": ttl, "address": strPtr(id.addr), "hostname": strPtr(id.hostname), "classification": class})
		series := cells.Series(ttl)
		rr := make([]*float64, plan.N)
		ll := make([]*float64, plan.N)
		for i, c := range series {
			if c == nil || c.N == 0 {
				continue
			}
			avg, ok := c.Avg()
			rr[i] = fp(avg, ok)
			lp, ok2 := c.LossPct()
			ll[i] = fp(lp, ok2)
		}
		rtt = append(rtt, rr)
		loss = append(loss, ll)
	}
	gaps, err := s.d.Store.Gaps(row.ID, plan.From, plan.To)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	gj := make([][2]int64, 0, len(gaps))
	for _, g := range gaps {
		gj = append(gj, [2]int64{g.From.UnixMilli(), g.To.UnixMilli()})
	}
	tid := row.ID
	evs, err := s.d.Store.Events(store.EventQuery{TargetID: &tid, From: plan.From, To: plan.To,
		Kinds: []string{store.EventRouteChange, store.EventRateLimited, store.EventICMPUnresponsive, store.EventLocalOutage}})
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	events := make([]map[string]any, 0, len(evs))
	for _, e := range evs {
		events = append(events, eventJSON(e))
	}
	// timeline markers use from/to rather than the list shape
	for i, e := range events {
		events[i] = map[string]any{"kind": e["kind"], "ttl": e["ttl"], "from": e["from"], "to": e["to"], "details": e["details"]}
	}
	als, err := s.d.Store.AlertsOverlapping(row.ID, plan.From, plan.To)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	for _, a := range als {
		var to any
		if a.EndedAt != nil {
			to = a.EndedAt.UnixMilli()
		}
		events = append(events, map[string]any{"kind": "alert", "ttl": nil, "from": a.StartedAt.UnixMilli(), "to": to,
			"details": map[string]any{"rule": a.Rule, "alert_id": a.ID}})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i]["from"].(int64) < events[j]["from"].(int64) })
	writeJSON(w, http.StatusOK, map[string]any{
		"from": plan.From.UnixMilli(), "to": plan.To.UnixMilli(), "step_ms": plan.Step.Milliseconds(), "resolution": plan.Tier.String(),
		"ttls": ttls, "labels": labels, "rtt": rtt, "loss": loss, "gaps": gj, "events": events,
	})
}

// ---------------------------------------------------------------------------
// hop series

func (s *Server) handleSeries(w http.ResponseWriter, r *http.Request) {
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	plan, ok := s.rangeAndPlan(w, r, 300)
	if !ok {
		return
	}
	pts := make([][]any, 0, plan.N)
	var ttl any
	if v := r.URL.Query().Get("ttl"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 255 {
			writeError(w, http.StatusBadRequest, "invalid ttl")
			return
		}
		cells, err := s.d.Store.ICMPCells(r.Context(), row.ID, plan, store.CellOpts{NoHist: true, TTL: n})
		if err != nil {
			s.queryFailed(w, r, err)
			return
		}
		ttl = n
		for i, c := range cells.Series(n) {
			ts := plan.BucketStart(i).UnixMilli()
			p := pointFromRoll(c)
			pts = append(pts, seriesPoint(ts, p))
		}
	} else {
		e, err := s.e2e(r.Context(), s.viewOf(row), plan, false)
		if err != nil {
			s.queryFailed(w, r, err)
			return
		}
		if e.ttl > 0 {
			ttl = e.ttl
		}
		for i := 0; i < plan.N; i++ {
			var p e2ePoint
			if i < len(e.points) {
				p = e.points[i]
			}
			pts = append(pts, seriesPoint(plan.BucketStart(i).UnixMilli(), p))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ttl": ttl, "step_ms": plan.Step.Milliseconds(), "points": pts})
}

func seriesPoint(ts int64, p e2ePoint) []any {
	if p.n == 0 {
		return []any{ts, nil, nil, nil, nil}
	}
	return []any{ts, fp(p.avg, p.haveAvg), fp(p.min, p.haveAvg), fp(p.max, p.haveAvg), fp(p.loss, p.haveLoss)}
}

// ---------------------------------------------------------------------------
// probe series

func (s *Server) handleProbes(w http.ResponseWriter, r *http.Request) {
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	plan, ok := s.rangeAndPlan(w, r, 300)
	if !ok {
		return
	}
	v := s.viewOf(row)
	httpOut := []map[string]any{}
	tcpOut := []map[string]any{}
	for _, p := range v.probes {
		switch p.Type {
		case config.ProbeHTTP:
			pc, err := s.d.Store.ProbeCells(r.Context(), p.ID, p.Type, plan, store.CellOpts{NoHist: true})
			if err != nil {
				s.queryFailed(w, r, err)
				return
			}
			pts := make([][]any, 0, plan.N)
			for i, c := range pc.Rolls {
				ts := plan.BucketStart(i).UnixMilli()
				if c == nil || c.N == 0 {
					pts = append(pts, []any{ts, nil, nil, nil, nil, nil, nil, nil})
					continue
				}
				dns, a := c.AvgDNS()
				conn, b := c.AvgConnect()
				tls, c2 := c.AvgTLS()
				ttfb, d := c.AvgTTFB()
				tr, e := c.AvgTransfer()
				tot, f := c.AvgTotal()
				succ, g := c.SuccessPct()
				pts = append(pts, []any{ts, fp(dns, a), fp(conn, b), fp(tls, c2), fp(ttfb, d), fp(tr, e), fp(tot, f), fp(succ, g)})
			}
			var cert *int64
			if t, ok := s.d.Store.LatestCert(p.ID); ok {
				cert = msPtr(t)
			}
			httpOut = append(httpOut, map[string]any{"probe_id": p.ID, "label": p.Label, "cert_not_after": cert, "points": pts})
		case config.ProbeTCP:
			pc, err := s.d.Store.ProbeCells(r.Context(), p.ID, p.Type, plan, store.CellOpts{NoHist: true})
			if err != nil {
				s.queryFailed(w, r, err)
				return
			}
			pts := make([][]any, 0, plan.N)
			for i, c := range pc.Rolls {
				ts := plan.BucketStart(i).UnixMilli()
				if c == nil || c.N == 0 {
					pts = append(pts, []any{ts, nil, nil})
					continue
				}
				avg, a := c.AvgTotal()
				fl, b := c.FailPct()
				pts = append(pts, []any{ts, fp(avg, a), fp(fl, b)})
			}
			tcpOut = append(tcpOut, map[string]any{"probe_id": p.ID, "label": p.Label, "points": pts})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"http": httpOut, "tcp": tcpOut})
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	plan, ok := s.rangeAndPlan(w, r, 300)
	if !ok {
		return
	}
	out := []map[string]any{}
	if s.d.Sched != nil {
		for _, d := range s.d.Sched.DNSStates() {
			pc, err := s.d.Store.ProbeCells(r.Context(), d.ProbeID, config.ProbeDNS, plan, store.CellOpts{NoHist: true})
			if err != nil {
				s.queryFailed(w, r, err)
				return
			}
			pts := make([][]any, 0, plan.N)
			for i, c := range pc.Rolls {
				ts := plan.BucketStart(i).UnixMilli()
				if c == nil || c.N == 0 {
					pts = append(pts, []any{ts, nil, nil})
					continue
				}
				avg, a := c.AvgTotal()
				fl, b := c.FailPct()
				pts = append(pts, []any{ts, fp(avg, a), fp(fl, b)})
			}
			out = append(out, map[string]any{"probe_id": d.ProbeID, "name": d.Spec.Name, "server": d.Spec.Server, "query": d.Spec.Query, "points": pts})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func eventJSON(e store.Event) map[string]any {
	var tid, ttl, to any
	if e.TargetID != nil {
		tid = *e.TargetID
	}
	if e.TTL != nil {
		ttl = *e.TTL
	}
	if e.To != nil {
		to = e.To.UnixMilli()
	}
	var details any = map[string]any{}
	if len(e.Details) > 0 {
		var d any
		if json.Unmarshal(e.Details, &d) == nil && d != nil {
			details = d
		}
	}
	return map[string]any{"id": e.ID, "target_id": tid, "kind": e.Kind, "ttl": ttl, "from": e.From.UnixMilli(), "to": to, "details": details}
}

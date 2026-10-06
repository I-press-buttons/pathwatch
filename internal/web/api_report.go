package web

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// maxReportIncidents bounds the incidents analysed for one report (each one reads the range it
// covers); more are reported as truncated.
const maxReportIncidents = 200

// Incident severities.
const (
	sevCritical = "critical"
	sevWarning  = "warning"
	sevInfo     = "info"
)

type reportProbe struct {
	ProbeID    int64    `json:"probe_id"`
	Label      string   `json:"label"`
	Type       string   `json:"type"`
	Samples    int64    `json:"samples"`
	Errors     int64    `json:"errors"`
	SuccessPct *float64 `json:"success_pct"`
	AvgMS      *float64 `json:"avg_ms"`
}

type reportSummary struct {
	Source          string        `json:"source"` // icmp | tcp | last_hop | http | none
	Samples         int64         `json:"samples"`
	AvailabilityPct *float64      `json:"availability_pct"`
	LossPct         *float64      `json:"loss_pct"`
	AvgMS           *float64      `json:"avg_ms"`
	P95MS           *float64      `json:"p95_ms"`
	JitterMS        *float64      `json:"jitter_ms"`
	MOS             *float64      `json:"mos"`
	HTTP            []reportProbe `json:"http"`
	TCP             []reportProbe `json:"tcp"`
}

type reportOrigin struct {
	TTL            int      `json:"ttl"`
	Address        *string  `json:"address"`
	Hostname       *string  `json:"hostname"`
	ASN            *int     `json:"asn"`
	ASName         *string  `json:"as_name"`
	Reason         string   `json:"reason"` // loss | latency
	LossPct        *float64 `json:"loss_pct"`
	AvgMS          *float64 `json:"avg_ms"`
	BaselineMaxMS  *float64 `json:"baseline_max_ms"`
	Classification string   `json:"classification"`
}

type reportIncident struct {
	Source     string         `json:"source"` // alert | event
	ID         int64          `json:"id"`
	Kind       string         `json:"kind"` // the rule type of an alert, the kind of an event
	Rule       string         `json:"rule,omitempty"`
	Severity   string         `json:"severity"`
	State      string         `json:"state,omitempty"`
	Message    string         `json:"message,omitempty"`
	StartedAt  int64          `json:"started_at"`
	EndedAt    *int64         `json:"ended_at"`
	Ongoing    bool           `json:"ongoing"`
	DurationMS int64          `json:"duration_ms"` // an ongoing incident lasts until the end of the range
	Origin     *reportOrigin  `json:"origin"`
	Probes     []reportProbe  `json:"probes"`
	TTL        *int           `json:"ttl"`
	Details    map[string]any `json:"details,omitempty"`
}

type reportGap struct {
	From       int64 `json:"from"`
	To         int64 `json:"to"`
	DurationMS int64 `json:"duration_ms"`
}

type reportPathChange struct {
	At         int64   `json:"at"`
	FromIP     *string `json:"from_ip"`
	ToIP       *string `json:"to_ip"`
	ResolvedIP *string `json:"resolved_ip"`
}

func severityOfAlert(ruleType string) string {
	switch ruleType {
	case "http_failure", "tcp_failure", "dns_failure", "final_hop_loss":
		return sevCritical
	case "path_degradation", "http_latency", "dns_latency":
		return sevWarning
	}
	return sevInfo
}

func severityOfEvent(kind string) string {
	switch kind {
	case store.EventLocalOutage:
		return sevCritical
	case store.EventDegraded:
		return sevWarning
	}
	return sevInfo
}

// wantsOrigin says whether the first degraded hop is worth looking for: not for certificate or
// route notices, nor for events that describe the monitor's own side.
func wantsOrigin(kind string) bool {
	switch kind {
	case "cert_expiry", "route_change", store.EventICMPUnresponsive, store.EventLocalOutage:
		return false
	}
	return true
}

// windowPlan is a one-bucket plan over the half-open window [from, to). Windows within 6h come from the raw rounds;
// raw data is pruned sooner than the rollups, so an empty raw read falls back to minute rollups
// (the window is then widened to whole minutes).
func windowPlan(from, to time.Time, tier store.Tier) store.Plan {
	if tier == store.Tier1m {
		from = from.Truncate(time.Minute)
	}
	if tier == store.Tier1h {
		from = from.Truncate(time.Hour)
	}
	return store.SinglePlan(from, to.Add(-time.Microsecond), tier)
}

func (s *Server) windowCells(ctx context.Context, id int64, from, to time.Time, o store.CellOpts) (*store.ICMPCells, store.Plan, error) {
	tier := store.TierFor(from, to)
	plan := windowPlan(from, to, tier)
	cells, err := s.d.Store.ICMPCells(ctx, id, plan, o)
	if err != nil {
		return nil, plan, err
	}
	if tier == store.TierRaw && cells.MaxTTL() == 0 {
		plan = windowPlan(from, to, store.Tier1m)
		cells, err = s.d.Store.ICMPCells(ctx, id, plan, o)
	}
	return cells, plan, err
}

func (s *Server) probeStats(ctx context.Context, v targetView, from, to time.Time) ([]reportProbe, error) {
	var out []reportProbe
	tier := store.TierFor(from, to)
	for _, p := range v.probes {
		if p.Type != config.ProbeHTTP && p.Type != config.ProbeTCP {
			continue
		}
		plan := windowPlan(from, to, tier)
		pc, err := s.d.Store.ProbeCells(ctx, p.ID, p.Type, plan, store.CellOpts{NoHist: true})
		if err != nil {
			return nil, err
		}
		tot := pc.Total()
		if tot.N == 0 && tier == store.TierRaw {
			pc, err = s.d.Store.ProbeCells(ctx, p.ID, p.Type, windowPlan(from, to, store.Tier1m), store.CellOpts{NoHist: true})
			if err != nil {
				return nil, err
			}
			tot = pc.Total()
		}
		rp := reportProbe{ProbeID: p.ID, Label: p.Label, Type: p.Type, Samples: tot.N, Errors: tot.Errors}
		succ, ok := tot.SuccessPct()
		rp.SuccessPct = fp(succ, ok)
		avg, ok := tot.AvgTotal()
		rp.AvgMS = fp(avg, ok)
		out = append(out, rp)
	}
	return out, nil
}

// originOf finds where a degradation that began in [from, to] starts: the hops of the window are
// judged with the analyzer's own classifier (analyze.Classify), against a latency band built from
// the six hours before it. nil when no hop is degraded together with everything downstream.
func (s *Server) originOf(ctx context.Context, row store.TargetRow, probes []reportProbe, from, to time.Time) (*reportOrigin, error) {
	cells, plan, err := s.windowCells(ctx, row.ID, from, to, store.CellOpts{NoHist: true})
	if err != nil {
		return nil, err
	}
	// baseline: per-minute averages of the 6 hours before the window
	bands := analyze.NewBandTracker()
	bands.MinSamples = 20
	pre := store.Plan{Tier: store.Tier1m, Step: time.Minute, N: 360}
	pre.To = from.Truncate(time.Minute)
	pre.From = pre.To.Add(-6 * time.Hour)
	before, err := s.d.Store.ICMPCells(ctx, row.ID, pre, store.CellOpts{NoHist: true})
	if err != nil {
		return nil, err
	}
	pc, err := s.loadPathCtx(row, plan)
	if err != nil {
		return nil, err
	}
	params := analyze.DefaultParams()
	var hops []analyze.HopStat
	stats := map[int]analyze.HopStat{}
	for ttl := 1; ttl <= cells.MaxTTL(); ttl++ {
		tot := cells.Total(ttl)
		if tot.N == 0 {
			continue
		}
		hs := analyze.HopStat{TTL: ttl, Sent: int(tot.N), Lost: int(tot.Lost), IsDest: pc.hasPath && pc.path.DestTTL == ttl}
		hs.AvgMs, hs.HaveAvg = tot.Avg()
		ever := before.Total(ttl).Replies() > 0 || tot.Replies() > 0
		hs.EverResponded = ever
		key := string(rune(ttl))
		for _, c := range before.Series(ttl) {
			if c != nil && c.Replies() > 0 {
				avg, _ := c.Avg()
				bands.Observe(key, avg)
			}
		}
		if _, up, ok := bands.Band(key); ok {
			hs.Upper = up
		}
		hops = append(hops, hs)
		stats[ttl] = hs
	}
	if len(hops) == 0 {
		return nil, nil
	}
	var signals []analyze.SignalStat
	for _, x := range probes {
		sig := analyze.SignalStat{Name: x.Label, Sent: int(x.Samples), Failed: int(x.Errors)}
		if x.AvgMS != nil {
			sig.AvgMs, sig.HaveAvg = *x.AvgMS, true
		}
		signals = append(signals, sig)
	}
	res := analyze.Classify(params, hops, signals)
	if !res.Real {
		return nil, nil
	}
	hs := stats[res.StartTTL]
	id := s.identity(pc, res.StartTTL)
	o := &reportOrigin{TTL: res.StartTTL, Address: strPtr(id.addr), Hostname: strPtr(id.hostname), ASN: id.asn, ASName: id.asName,
		Classification: res.ClassOf(res.StartTTL), Reason: "latency"}
	if 100*float64(hs.Lost)/float64(hs.Sent) > params.LossThreshold {
		o.Reason = "loss"
	}
	o.LossPct = fp(100*float64(hs.Lost)/float64(hs.Sent), true)
	o.AvgMS = fp(hs.AvgMs, hs.HaveAvg)
	o.BaselineMaxMS = fp(hs.Upper, hs.Upper > 0)
	return o, nil
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	from, to, err := s.parseRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx := r.Context()
	v := s.viewOf(row)

	// summary
	sum := reportSummary{Source: "none", HTTP: []reportProbe{}, TCP: []reportProbe{}}
	plan := windowPlan(from, to, store.TierFor(from, to))
	e, err := s.e2e(ctx, v, plan, true)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	if e.source != "" {
		sum.Source = e.source
	}
	if len(e.points) > 0 && e.points[0].n > 0 {
		p := e.points[0]
		sum.Samples = p.n
		sum.LossPct = fp(p.loss, p.haveLoss)
		if p.haveLoss {
			sum.AvailabilityPct = fp(100-p.loss, true)
		}
		sum.AvgMS = fp(p.avg, p.haveAvg)
		sum.P95MS = fp(p.p95, p.haveAvg && p.p95 > 0)
		sum.JitterMS = fp(p.jitter, p.haveJit)
		if p.haveAvg && p.haveLoss {
			jit := 0.0
			if p.haveJit {
				jit = p.jitter
			}
			sum.MOS = fp(analyze.MOS(p.avg, jit, p.loss), true)
		}
	}
	probes, err := s.probeStats(ctx, v, from, to)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	for _, p := range probes {
		if p.Type == config.ProbeHTTP {
			sum.HTTP = append(sum.HTTP, p)
		} else {
			sum.TCP = append(sum.TCP, p)
		}
	}

	// incidents: alerts (not the suppressed ones) and the events that mean trouble
	tid := row.ID
	alerts, err := s.d.Store.AlertsOverlapping(tid, from, to)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	evs, err := s.d.Store.Events(store.EventQuery{TargetID: &tid, From: from, To: to,
		Kinds: []string{store.EventDegraded, store.EventICMPUnresponsive, store.EventLocalOutage}})
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	incidents := make([]reportIncident, 0, len(alerts)+len(evs))
	span := func(start time.Time, end *time.Time) (reportIncident, time.Time) {
		in := reportIncident{StartedAt: start.UnixMilli(), Ongoing: end == nil, Probes: []reportProbe{}}
		stop := to
		if end != nil {
			stop = *end
			in.EndedAt = msPtr(*end)
		}
		if d := stop.Sub(start); d > 0 {
			in.DurationMS = d.Milliseconds()
		}
		return in, stop
	}
	type window struct{ from, to time.Time }
	wins := make([]window, 0, cap(incidents))
	for _, a := range alerts {
		in, stop := span(a.StartedAt, a.EndedAt)
		in.Source, in.ID, in.Kind, in.Rule, in.State, in.Message = "alert", a.ID, a.RuleType, a.Rule, a.State, a.Message
		in.Severity = severityOfAlert(a.RuleType)
		incidents = append(incidents, in)
		wins = append(wins, window{a.StartedAt, stop})
	}
	for _, ev := range evs {
		in, stop := span(ev.From, ev.To)
		in.Source, in.ID, in.Kind, in.TTL = "event", ev.ID, ev.Kind, ev.TTL
		in.Severity = severityOfEvent(ev.Kind)
		if len(ev.Details) > 0 {
			var d map[string]any
			if json.Unmarshal(ev.Details, &d) == nil {
				in.Details = d
			}
		}
		incidents = append(incidents, in)
		wins = append(wins, window{ev.From, stop})
	}
	idx := make([]int, len(incidents))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return incidents[idx[a]].StartedAt < incidents[idx[b]].StartedAt })
	sorted := make([]reportIncident, 0, len(incidents))
	sortedWins := make([]window, 0, len(incidents))
	for _, i := range idx {
		sorted = append(sorted, incidents[i])
		sortedWins = append(sortedWins, wins[i])
	}
	truncated := false
	if len(sorted) > maxReportIncidents {
		sorted, sortedWins, truncated = sorted[:maxReportIncidents], sortedWins[:maxReportIncidents], true
	}
	for i := range sorted {
		in, win := &sorted[i], sortedWins[i]
		// the part of the incident inside the range; at least a minute so a short one has data
		wf, wt := win.from, win.to
		if wf.Before(from) {
			wf = from
		}
		if wt.Before(wf.Add(time.Minute)) {
			wt = wf.Add(time.Minute)
			if wt.After(to) {
				wt = to
				if wf = wt.Add(-time.Minute); wf.Before(from) {
					wf = from
				}
			}
		}
		if in.Source == "event" && in.Kind == store.EventICMPUnresponsive || in.Source == "alert" && in.Kind == "cert_expiry" {
			// not a delivery problem: nothing to attribute or measure
		} else {
			ps, err := s.probeStats(ctx, v, wf, wt)
			if err != nil {
				s.queryFailed(w, r, err)
				return
			}
			if ps != nil {
				in.Probes = ps
			}
		}
		if wantsOrigin(in.Kind) {
			o, err := s.originOf(ctx, row, in.Probes, wf, wt)
			if err != nil {
				s.queryFailed(w, r, err)
				return
			}
			in.Origin = o
		}
	}

	// gaps (no data, never loss) and path changes
	gaps, err := s.d.Store.Gaps(tid, from, to)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	gj := make([]reportGap, 0, len(gaps))
	for _, g := range gaps {
		gj = append(gj, reportGap{From: g.From.UnixMilli(), To: g.To.UnixMilli(), DurationMS: g.To.Sub(g.From).Milliseconds()})
	}
	rc, err := s.d.Store.Events(store.EventQuery{TargetID: &tid, From: from, To: to, Kinds: []string{store.EventRouteChange}})
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	changes := make([]reportPathChange, 0, len(rc))
	for _, ev := range rc {
		pcj := reportPathChange{At: ev.From.UnixMilli()}
		var d struct {
			From int64  `json:"from_path"`
			To   int64  `json:"to_path"`
			IP   string `json:"resolved_ip"`
		}
		if len(ev.Details) > 0 && json.Unmarshal(ev.Details, &d) == nil {
			pcj.ResolvedIP = strPtr(d.IP)
			if paths, err := s.d.Store.PathsOf([]int64{d.From, d.To}); err == nil {
				if p, ok := paths[d.From]; ok {
					pcj.FromIP = strPtr(p.ResolvedIP)
				}
				if p, ok := paths[d.To]; ok {
					pcj.ToIP = strPtr(p.ResolvedIP)
				}
			}
		}
		changes = append(changes, pcj)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"target":       map[string]any{"id": row.ID, "name": row.Name, "host": row.Host},
		"from":         from.UnixMilli(),
		"to":           to.UnixMilli(),
		"generated_at": s.now().UnixMilli(),
		"resolution":   plan.Tier.String(),
		"summary":      sum,
		"incidents":    sorted,
		"truncated":    truncated,
		"gaps":         gj,
		"path_changes": changes,
	})
}

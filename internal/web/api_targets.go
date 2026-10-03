package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
	"github.com/i-press-buttons/pathwatch/internal/settings"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	ok := s.d.Store.WriterAlive()
	reason := ""
	if !ok {
		reason = "writer"
	}
	if ok && s.d.Sched != nil {
		if hok, _ := s.d.Sched.Healthy(); !hok {
			ok, reason = false, "scheduler"
		}
	}
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": reason + " unhealthy"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	local := "unknown"
	if s.d.Analyzer != nil && s.d.Analyzer.HasData() {
		local = "ok"
		if s.d.Analyzer.Local().Down {
			local = "down"
		}
	}
	_, total, err := s.d.Store.ActiveAlertCounts()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	mode := "unavailable"
	if s.d.Sched != nil {
		mode = s.d.Sched.ICMPMode()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":           s.d.Version,
		"now":               now.UnixMilli(),
		"uptime_s":          int64(now.Sub(s.started).Seconds()),
		"icmp_mode":         mode,
		"local_status":      local,
		"active_alerts":     total,
		"auth_enabled":      s.d.Auth.Enabled,
		"read_only_config":  s.d.Settings == nil,
		"status_thresholds": s.cfg().Status,
	})
}

// ---------------------------------------------------------------------------
// targets

type probeJSON struct {
	ID    int64  `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

type summaryJSON struct {
	E2ERTT       *float64 `json:"e2e_rtt_ms"`
	E2EP95       *float64 `json:"e2e_p95_ms"`
	E2ELoss      *float64 `json:"e2e_loss_pct"`
	Jitter       *float64 `json:"jitter_ms"`
	MOS          *float64 `json:"mos"`
	HopCount     *int     `json:"hop_count"`
	HTTPTotal    *float64 `json:"http_total_ms"`
	HTTPSuccess  *float64 `json:"http_success_pct"`
	CertNotAfter *int64   `json:"cert_not_after"`
	ActiveAlerts int      `json:"active_alerts"`
}

type targetJSON struct {
	ID               int64       `json:"id"`
	Name             string      `json:"name"`
	Host             string      `json:"host"`
	HostKind         string      `json:"host_kind"` // ipv4 | ipv6 | hostname
	Source           string      `json:"source"`
	Overridden       bool        `json:"overridden"` // a config-file target edited in the UI
	Active           bool        `json:"active"`
	Paused           bool        `json:"paused"`
	Removed          bool        `json:"removed"`
	Status           string      `json:"status"`
	ResolvedIP       *string     `json:"resolved_ip"`
	ICMPUnresponsive bool        `json:"icmp_unresponsive"`
	ICMPIntervalMS   *int        `json:"icmp_interval_ms"`
	LastRound        *int64      `json:"last_round"`
	Summary          summaryJSON `json:"summary"`
	Probes           []probeJSON `json:"probes"`
}

// targetView resolves everything the API knows about a stored target.
type targetView struct {
	row    store.TargetRow
	state  scheduler.State
	hasSt  bool
	probes []scheduler.ProbeRef
}

func (s *Server) viewOf(row store.TargetRow) targetView {
	v := targetView{row: row}
	if s.d.Sched != nil {
		if st, ok := s.d.Sched.State(row.ID); ok {
			v.state, v.hasSt = st, true
			v.probes = st.Probes
			v.row = st.Row
		}
	}
	if !v.hasSt {
		if ps, err := s.d.Store.Probes(row.ID); err == nil {
			for _, p := range ps {
				v.probes = append(v.probes, scheduler.ProbeRef{ID: p.ID, Type: p.Type, Key: p.Key, Label: p.Label})
			}
		}
	}
	return v
}

func (v targetView) running() bool {
	return v.hasSt && v.state.Running && !v.row.Paused && v.row.Active
}

func (v targetView) probesOfType(t string) []scheduler.ProbeRef {
	var out []scheduler.ProbeRef
	for _, p := range v.probes {
		if p.Type == t {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	incl := r.URL.Query().Get("include_inactive")
	rows, err := s.d.Store.Targets(incl == "1" || incl == "true")
	if err != nil {
		s.internal(w, r, err)
		return
	}
	counts, _, err := s.d.Store.ActiveAlertCounts()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	out := make([]targetJSON, 0, len(rows))
	for _, row := range rows {
		tj, err := s.buildTarget(s.viewOf(row), counts)
		if err != nil {
			s.internal(w, r, err)
			return
		}
		out = append(out, tj)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) buildTarget(v targetView, counts map[int64]int) (targetJSON, error) {
	now := s.now()
	tj := targetJSON{
		ID: v.row.ID, Name: v.row.Name, Host: v.row.Host, HostKind: config.HostKind(v.row.Host), Source: v.row.Source,
		Overridden: v.row.Source == config.SourceConfig && v.row.Spec != "",
		Active:     v.running(), Paused: v.row.Paused, Removed: !v.row.Active,
		ICMPUnresponsive: v.hasSt && v.state.ICMPUnresponsive,
		Probes:           make([]probeJSON, 0, len(v.probes)),
	}
	for _, p := range v.probes {
		tj.Probes = append(tj.Probes, probeJSON{ID: p.ID, Type: p.Type, Label: p.Label})
	}
	if v.hasSt && v.state.Spec.ICMP != nil {
		iv := v.state.ICMPIntervalMS
		tj.ICMPIntervalMS = &iv
	}
	if v.hasSt && v.state.ResolvedIP != "" {
		ip := v.state.ResolvedIP
		tj.ResolvedIP = &ip
	} else if p, err := s.d.Store.LatestPath(v.row.ID); err == nil {
		ip := p.ResolvedIP
		tj.ResolvedIP = &ip
	}
	last := time.Time{}
	if v.hasSt {
		last = v.state.LastRound
	}
	if last.IsZero() {
		if t, ok := s.d.Store.LastRoundTime(v.row.ID); ok {
			last = t
		}
	}
	tj.LastRound = msPtr(last)

	sum, e2eLoss, httpOK, err := s.summarize(v, now)
	if err != nil {
		return tj, err
	}
	sum.ActiveAlerts = counts[v.row.ID]
	tj.Summary = sum
	tj.Status = s.statusOf(v, now, last, sum, e2eLoss, httpOK)
	return tj, nil
}

// summarize computes the 5-minute summary of a target.
func (s *Server) summarize(v targetView, now time.Time) (summaryJSON, *float64, bool, error) {
	var sum summaryJSON
	plan := store.SinglePlan(now.Add(-5*time.Minute), now, store.TierRaw)
	e2e, err := s.e2e(v, plan)
	if err != nil {
		return sum, nil, false, err
	}
	var loss *float64 // loss usable for the degraded verdict
	if len(e2e.points) > 0 {
		p := e2e.points[0]
		sum.E2ERTT = fp(p.avg, p.haveAvg)
		sum.E2EP95 = fp(p.p95, p.haveAvg)
		sum.Jitter = fp(p.jitter, p.haveJit)
		sum.E2ELoss = fp(p.loss, p.haveLoss)
		// The last responding hop of an ICMP-unresponsive destination is often a rate-limited
		// router, so its loss is shown but never turns the target "degraded" on its own.
		if e2e.source != "last_hop" {
			loss = sum.E2ELoss
		}
		if p.haveLoss {
			switch {
			case p.haveAvg:
				sum.MOS = fp(analyze.MOS(p.avg, p.jitter, p.loss), true)
			case p.loss >= 100:
				sum.MOS = fp(1, true)
			}
		}
	}
	if st := s.hopCount(v, e2e); st > 0 {
		sum.HopCount = &st
	}
	httpOK := false
	var merged store.ProbeRoll
	var certMin time.Time
	for _, p := range v.probesOfType(config.ProbeHTTP) {
		pc, err := s.d.Store.ProbeCells(p.ID, p.Type, plan)
		if err != nil {
			return sum, nil, false, err
		}
		merged.Merge(pc.Total())
		if c, ok := s.d.Store.LatestCert(p.ID); ok && (certMin.IsZero() || c.Before(certMin)) {
			certMin = c
		}
	}
	if merged.N > 0 {
		httpOK = true
		if avg, ok := merged.AvgTotal(); ok {
			sum.HTTPTotal = fp(avg, true)
		}
		if sp, ok := merged.SuccessPct(); ok {
			sum.HTTPSuccess = fp(sp, true)
		}
	}
	sum.CertNotAfter = msPtr(certMin)
	return sum, loss, httpOK, nil
}

func (s *Server) hopCount(v targetView, e2e e2eResult) int {
	if v.hasSt && v.state.Spec.ICMP == nil {
		return 0
	}
	if p, err := s.d.Store.LatestPath(v.row.ID); err == nil && p.DestTTL > 0 {
		return p.DestTTL
	}
	return e2e.lastResp
}

func (s *Server) statusOf(v targetView, now, lastRound time.Time, sum summaryJSON, e2eLoss *float64, httpOK bool) string {
	if !v.running() {
		return "nodata"
	}
	// fresh data?
	fresh := false
	if v.state.Spec.ICMP != nil && s.d.Sched != nil && s.d.Sched.ICMPMode() != "unavailable" {
		iv := v.state.Spec.ICMP.Interval
		limit := 5 * iv
		if limit < 20*time.Second {
			limit = 20 * time.Second
		}
		if !lastRound.IsZero() && now.Sub(lastRound) < limit {
			fresh = true
		}
	}
	if !fresh {
		for _, p := range v.state.Spec.Probes {
			ref := p
			var pid int64
			for _, pr := range v.probes {
				if pr.Key == ref.Key() {
					pid = pr.ID
				}
			}
			if pid == 0 {
				continue
			}
			if t, ok := s.d.Store.LastProbeSample(pid, p.Type); ok {
				limit := 3*p.Interval + p.Timeout
				if limit < 30*time.Second {
					limit = 30 * time.Second
				}
				if now.Sub(t) < limit {
					fresh = true
					break
				}
			}
		}
	}
	if !fresh {
		return "nodata"
	}
	if sum.ActiveAlerts > 0 {
		return "alerting"
	}
	degraded := false
	if s.d.Analyzer != nil {
		if a, ok := s.d.Analyzer.Latest(v.row.ID); ok && a.Real && now.Sub(a.At) < 5*time.Minute {
			degraded = true
		}
	}
	th := s.cfg().Status
	if e2eLoss != nil && *e2eLoss > th.DegradedLossPct {
		degraded = true
	}
	if httpOK && sum.HTTPSuccess != nil && *sum.HTTPSuccess < th.DegradedHTTPSuccessPct {
		degraded = true
	}
	if degraded {
		if s.silenced(now, v.row.ID) {
			return "silenced"
		}
		return "degraded"
	}
	if first, ok := s.d.Store.FirstDataTime(v.row.ID); ok && now.Sub(first) < 2*time.Hour {
		return "learning"
	}
	return "ok"
}

// silenced reports whether an all-rules silence or maintenance window covers the target now.
func (s *Server) silenced(now time.Time, targetID int64) bool {
	if _, ok := s.maint.Silenced(now); ok {
		return true
	}
	sils, err := s.d.Store.Silences(now)
	if err != nil {
		return false
	}
	for _, x := range sils {
		sc := alert.SilenceScope{TargetID: x.TargetID, Rule: x.Rule, Start: x.StartsAt, End: x.EndsAt}
		if x.Rule == nil && sc.Covers(now, targetID, "") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// create / delete / pause

// createTargetReq is a full target definition, or (without "probes") the simple form of
// earlier versions: name, host, icmp_interval_ms, http_url and tcp_port.
type createTargetReq struct {
	config.TargetConfig
	HTTPURL string `json:"http_url"`
	TCPPort int    `json:"tcp_port"`
}

func (s *Server) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	if s.d.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	var req createTargetReq
	if !decodeStrict(w, r, &req) {
		return
	}
	tc := req.TargetConfig
	if tc.Probes == nil {
		simple, err := config.UITargetRequest{Name: tc.Name, Host: tc.Host, HTTPURL: req.HTTPURL, TCPPort: req.TCPPort}.Config()
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		tc.Probes = simple.Probes
	} else if req.HTTPURL != "" || req.TCPPort != 0 {
		writeError(w, http.StatusBadRequest, "use either probes or http_url/tcp_port, not both")
		return
	}
	row, err := s.d.Settings.CreateTarget(tc)
	if err != nil {
		s.settingsError(w, r, err, tc.Name)
		return
	}
	s.writeTarget(w, r, row, http.StatusCreated)
}

func (s *Server) writeTarget(w http.ResponseWriter, r *http.Request, row store.TargetRow, code int) {
	counts, _, _ := s.d.Store.ActiveAlertCounts()
	tj, err := s.buildTarget(s.viewOf(row), counts)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, code, tj)
}

// settingsError maps settings manager errors to responses.
func (s *Server) settingsError(w http.ResponseWriter, r *http.Request, err error, name string) {
	var inv settings.InvalidError
	switch {
	case errors.As(err, &inv):
		writeError(w, http.StatusBadRequest, inv.Error())
	case errors.Is(err, store.ErrDuplicate):
		writeError(w, http.StatusConflict, "a target named "+strconv.Quote(strings.TrimSpace(name))+" already exists")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "target not found")
	case errors.Is(err, settings.ErrRemoved):
		writeError(w, http.StatusConflict, "target was removed from the config file")
	case errors.Is(err, settings.ErrRenameCf):
		writeError(w, http.StatusBadRequest, "this target is defined in the config file; rename it there")
	case errors.Is(err, settings.ErrNotInUI):
		writeError(w, http.StatusConflict, "this target has no settings edited in the UI")
	case errors.Is(err, scheduler.ErrConfigTarget):
		writeError(w, http.StatusForbidden, "this target is defined in the config file; remove it there")
	default:
		s.internal(w, r, err)
	}
}

func (s *Server) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	if s.d.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	var tc config.TargetConfig
	if !decodeStrict(w, r, &tc) {
		return
	}
	nrow, err := s.d.Settings.UpdateTarget(row.ID, tc)
	if err != nil {
		s.settingsError(w, r, err, tc.Name)
		return
	}
	s.writeTarget(w, r, nrow, http.StatusOK)
}

// targetConfigJSON is a target's editable definition.
type targetConfigJSON struct {
	ID         int64               `json:"id"`
	Source     string              `json:"source"`
	Overridden bool                `json:"overridden"`
	Target     config.TargetConfig `json:"target"`
}

func (s *Server) handleTargetConfig(w http.ResponseWriter, r *http.Request) {
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	if s.d.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	def, err := s.d.Settings.Target(row)
	if err != nil {
		s.settingsError(w, r, err, row.Name)
		return
	}
	if def.Target.Probes == nil {
		def.Target.Probes = []config.ProbeConfig{}
	}
	writeJSON(w, http.StatusOK, targetConfigJSON{ID: row.ID, Source: row.Source, Overridden: def.Overridden, Target: def.Target})
}

func (s *Server) handleRevertTarget(w http.ResponseWriter, r *http.Request) {
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	if s.d.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	if err := s.d.Settings.RevertTarget(row.ID); err != nil {
		s.settingsError(w, r, err, row.Name)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	if row.Source != config.SourceUI {
		writeError(w, http.StatusForbidden, "this target is defined in the config file; remove it there")
		return
	}
	if s.d.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	if err := s.d.Settings.DeleteTarget(row.ID); err != nil {
		s.settingsError(w, r, err, row.Name)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePause(pause bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		row, ok := s.targetFromPath(w, r)
		if !ok {
			return
		}
		if !row.Active {
			writeError(w, http.StatusConflict, "target was removed from the config file")
			return
		}
		if s.d.Sched == nil {
			writeError(w, http.StatusServiceUnavailable, "scheduler not running")
			return
		}
		if err := s.d.Sched.SetPaused(row.ID, pause); err != nil {
			s.internal(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

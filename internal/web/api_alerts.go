package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/store"
)

func (s *Server) targetNames() map[int64]string {
	out := map[int64]string{}
	if rows, err := s.d.Store.Targets(true); err == nil {
		for _, r := range rows {
			out[r.ID] = r.Name
		}
	}
	return out
}

func (s *Server) alertObject(a store.Alert, names map[int64]string, dels []store.Delivery) map[string]any {
	var tid, tname, reason, end, val, peak, base any
	if a.TargetID != nil {
		tid = *a.TargetID
		if n, ok := names[*a.TargetID]; ok {
			tname = n
		}
	}
	if a.SuppressedReason != "" {
		reason = a.SuppressedReason
	}
	if a.EndedAt != nil {
		end = a.EndedAt.UnixMilli()
	}
	if a.Value != nil {
		val = fp(*a.Value, true)
	}
	if a.PeakValue != nil {
		peak = fp(*a.PeakValue, true)
	}
	if a.Baseline != nil {
		base = fp(*a.Baseline, true)
	}
	ds := make([]map[string]any, 0, len(dels))
	for _, d := range dels {
		var le any
		if d.LastError != nil {
			le = *d.LastError
		}
		ds = append(ds, map[string]any{"channel": d.Channel, "status": d.Status, "attempts": d.Attempts, "last_error": le})
	}
	return map[string]any{
		"id": a.ID, "target_id": tid, "target_name": tname, "rule": a.Rule, "rule_type": a.RuleType,
		"state": a.State, "suppressed_reason": reason, "started_at": a.StartedAt.UnixMilli(), "ended_at": end,
		"value": val, "peak_value": peak, "baseline": base, "message": a.Message, "deliveries": ds,
	}
}

// alertByID renders one alert for the SSE "alert" event.
func (s *Server) alertByID(id int64) (any, bool) {
	a, err := s.d.Store.GetAlert(id)
	if err != nil {
		return nil, false
	}
	dels, _ := s.d.Store.Deliveries([]int64{id})
	return s.alertObject(a, s.targetNames(), dels[id]), true
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit, err := intParam(r, "limit", 100, 1, 1000)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var tid *int64
	if v := r.URL.Query().Get("target_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid target_id")
			return
		}
		tid = &n
	}
	list, err := s.d.Store.ListAlerts(limit, tid)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	ids := make([]int64, len(list))
	for i, a := range list {
		ids[i] = a.ID
	}
	dels, err := s.d.Store.Deliveries(ids)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	names := s.targetNames()
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		out = append(out, s.alertObject(a, names, dels[a.ID]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	from, to, err := s.parseRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	q := store.EventQuery{From: from, To: to, ExcludeKinds: []string{store.EventDegraded}}
	if v := r.URL.Query().Get("target_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid target_id")
			return
		}
		q.TargetID = &n
	}
	if v := r.URL.Query().Get("kind"); v != "" {
		q.Kinds = strings.Split(v, ",")
	}
	evs, err := s.d.Store.Events(q)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(evs))
	for _, e := range evs {
		out = append(out, eventJSON(e))
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// silences

func silenceObject(x store.Silence) map[string]any {
	var tid, rule any
	if x.TargetID != nil {
		tid = *x.TargetID
	}
	if x.Rule != nil {
		rule = *x.Rule
	}
	return map[string]any{"id": x.ID, "target_id": tid, "rule": rule, "starts_at": x.StartsAt.UnixMilli(), "ends_at": x.EndsAt.UnixMilli(), "reason": x.Reason, "source": "ui"}
}

func (s *Server) handleSilences(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	sils, err := s.d.Store.Silences(now)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(sils))
	for _, x := range sils {
		out = append(out, silenceObject(x))
	}
	// Active maintenance windows from the config, with negative ids (they cannot be deleted).
	for i, w := range s.maint {
		for _, act := range s.maint[i : i+1].Active(now) {
			out = append(out, map[string]any{"id": -int64(i + 1), "target_id": nil, "rule": nil,
				"starts_at": act.Start.UnixMilli(), "ends_at": act.End.UnixMilli(), "reason": w.Name, "source": "maintenance"})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

type createSilenceReq struct {
	TargetID   *int64  `json:"target_id"`
	Rule       *string `json:"rule"`
	DurationMS *int64  `json:"duration_ms"`
	StartsAt   *int64  `json:"starts_at"`
	EndsAt     *int64  `json:"ends_at"`
	Reason     string  `json:"reason"`
}

func (s *Server) handleCreateSilence(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	var req createSilenceReq
	if !decodeBody(w, r, &req) {
		return
	}
	now := s.now()
	start := now
	var end time.Time
	switch {
	case req.DurationMS != nil:
		if *req.DurationMS <= 0 || *req.DurationMS > int64(366*24*time.Hour/time.Millisecond) {
			writeError(w, http.StatusBadRequest, "duration_ms must be between 1 and 366 days")
			return
		}
		if req.StartsAt != nil {
			start = time.UnixMilli(*req.StartsAt).UTC()
		}
		end = start.Add(time.Duration(*req.DurationMS) * time.Millisecond)
	case req.EndsAt != nil:
		if req.StartsAt != nil {
			start = time.UnixMilli(*req.StartsAt).UTC()
		}
		end = time.UnixMilli(*req.EndsAt).UTC()
	default:
		writeError(w, http.StatusBadRequest, "provide duration_ms, or starts_at and ends_at")
		return
	}
	if !end.After(start) {
		writeError(w, http.StatusBadRequest, "ends_at must be after starts_at")
		return
	}
	if end.Sub(start) > 366*24*time.Hour {
		writeError(w, http.StatusBadRequest, "a silence may last at most 366 days")
		return
	}
	if !end.After(now) {
		writeError(w, http.StatusBadRequest, "the silence would already be over")
		return
	}
	if req.TargetID != nil {
		if _, err := s.d.Store.Target(*req.TargetID); err != nil {
			if err == store.ErrNotFound {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown target_id %d", *req.TargetID))
				return
			}
			s.internal(w, r, err)
			return
		}
	}
	x := store.Silence{TargetID: req.TargetID, StartsAt: start, EndsAt: end, Reason: strings.TrimSpace(req.Reason), CreatedBy: "ui"}
	if len(x.Reason) > 500 {
		writeError(w, http.StatusBadRequest, "reason is too long")
		return
	}
	if req.Rule != nil {
		rule := strings.TrimSpace(*req.Rule)
		if len(rule) > 100 {
			writeError(w, http.StatusBadRequest, "rule is too long")
			return
		}
		if rule != "" {
			x.Rule = &rule
		}
	}
	if u, _, ok := r.BasicAuth(); ok && u != "" {
		x.CreatedBy = u
	}
	x, err := s.d.Store.CreateSilence(x)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, silenceObject(x))
}

func (s *Server) handleDeleteSilence(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid silence id")
		return
	}
	if id < 0 {
		writeError(w, http.StatusBadRequest, "maintenance windows are defined in the config file")
		return
	}
	if err := s.d.Store.DeleteSilence(id); err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, "silence not found")
			return
		}
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// SSE

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // long-lived response
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(": connected\n\n"))
	fl.Flush()

	ch, unsub := s.hub.Subscribe()
	defer unsub()
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if _, err := w.Write(msg); err != nil {
				return
			}
			fl.Flush()
		case <-ping.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

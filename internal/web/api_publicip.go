package web

import (
	"context"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/publicip"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// publicIPHistory bounds the changes /api/public-ip lists.
const (
	publicIPHistory     = 50
	publicIPHistorySpan = 90 * 24 * time.Hour
)

type publicIPCurrent struct {
	Family      string  `json:"family"`
	Addr        *string `json:"addr"`
	Since       *int64  `json:"since"`
	LastChecked *int64  `json:"last_checked"`
	LastOK      *int64  `json:"last_ok"`
	LastError   *string `json:"last_error"`
	Pending     *string `json:"pending"` // a different address waiting for confirmation
	ASN         *int    `json:"asn"`
	ASName      *string `json:"as_name"`
	Hostname    *string `json:"hostname"`
}

type publicIPChange struct {
	ID       int64   `json:"id"`
	Family   string  `json:"family"`
	Addr     string  `json:"addr"`
	Previous *string `json:"previous"`
	From     int64   `json:"from"`
	To       *int64  `json:"to"`
	ASN      *int    `json:"asn"`
	ASName   *string `json:"as_name"`
}

func optMS(t time.Time) *int64 {
	if t.IsZero() {
		return nil
	}
	return msPtr(t)
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func optInt(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}

// publicIPJSON is the body of /api/public-ip (and the public_ip part of /api/status uses
// its current addresses).
func (s *Server) publicIPJSON() (map[string]any, error) {
	m := s.d.PublicIP
	out := map[string]any{"available": m != nil, "enabled": false, "current": []publicIPCurrent{}, "history": []publicIPChange{}}
	if m == nil {
		return out, nil
	}
	cfg := m.Config()
	out["enabled"], out["source"], out["interval_ms"], out["skip_ipv6"] = cfg.Enabled, cfg.Source, cfg.Interval.D().Milliseconds(), cfg.SkipIPv6
	cur := make([]publicIPCurrent, 0, 2)
	for _, st := range m.States() {
		if st.Family == publicip.IPv6 && cfg.SkipIPv6 && st.Addr == "" {
			continue
		}
		c := publicIPCurrent{Family: st.Family, Addr: optStr(st.Addr), Since: optMS(st.Since), LastChecked: optMS(st.LastChecked),
			LastOK: optMS(st.LastOK), LastError: optStr(st.LastErr), Pending: optStr(st.Pending)}
		if a, err := netip.ParseAddr(st.Addr); err == nil && s.d.Enrich != nil {
			i := s.d.Enrich.Lookup(a)
			c.ASN, c.ASName, c.Hostname = optInt(i.ASN), optStr(i.ASName), optStr(i.Hostname)
		}
		cur = append(cur, c)
	}
	out["current"] = cur
	now := s.now()
	evs, err := s.d.Store.Events(store.EventQuery{From: now.Add(-publicIPHistorySpan), To: now.Add(time.Minute), Kinds: []string{publicip.EventKind}})
	if err != nil {
		return nil, err
	}
	sort.Slice(evs, func(i, j int) bool { return evs[i].From.After(evs[j].From) })
	hist := make([]publicIPChange, 0, len(evs))
	for _, ev := range evs {
		if len(hist) == publicIPHistory {
			break
		}
		d, ok := publicip.ParseDetails(ev.Details)
		if !ok {
			continue
		}
		c := publicIPChange{ID: ev.ID, Family: d.Family, Addr: d.Addr, Previous: optStr(d.Previous), From: ev.From.UnixMilli(), ASN: optInt(d.ASN), ASName: optStr(d.ASName)}
		if ev.To != nil {
			c.To = msPtr(*ev.To)
		}
		hist = append(hist, c)
	}
	out["history"] = hist
	return out, nil
}

func (s *Server) handlePublicIP(w http.ResponseWriter, r *http.Request) {
	out, err := s.publicIPJSON()
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handlePublicIPCheck runs a check now (the "Check now" button), even while monitoring is off.
func (s *Server) handlePublicIPCheck(w http.ResponseWriter, r *http.Request) {
	if s.d.PublicIP == nil {
		writeError(w, http.StatusServiceUnavailable, "public IP monitoring is not available")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	s.d.PublicIP.Check(ctx)
	s.handlePublicIP(w, r)
}

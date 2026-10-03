package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

// sectionJSON is one settings section: the effective value, where it comes from, and the
// config file's value (what "revert" restores).
type sectionJSON struct {
	Source string `json:"source"` // file | ui
	Value  any    `json:"value"`
	File   any    `json:"file"`
}

func source(edited bool) string {
	if edited {
		return "ui"
	}
	return "file"
}

func dnsList(l []config.DNSProbeConfig) []config.DNSProbeConfig {
	if l == nil {
		return []config.DNSProbeConfig{}
	}
	return l
}

// handleSettings returns every setting the UI can edit.
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if s.d.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	eff, file, ov := s.d.Settings.Effective(), s.d.Settings.File(), s.d.Settings.Overrides()
	types := append([]string(nil), config.RuleTypes...)
	sort.Strings(types)
	writeJSON(w, http.StatusOK, map[string]any{
		"defaults":   sectionJSON{source(ov.Defaults != nil), eff.Defaults, file.Defaults},
		"status":     sectionJSON{source(ov.Status != nil), eff.Status, file.Status},
		"alerts":     sectionJSON{source(ov.Alerts != nil), eff.Alerts.Settings(), file.Alerts.Settings()},
		"dns_probes": sectionJSON{source(ov.DNSProbes != nil), dnsList(eff.DNSProbes), dnsList(file.DNSProbes)},
		"channels": map[string]bool{
			"webhook": eff.Alerts.Notify.Webhook != nil,
			"email":   eff.Alerts.Notify.Email != nil,
		},
		"rule_types":  types,
		"max_retries": config.MaxRetries,
	})
}

func (s *Server) handlePutSetting(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	if s.d.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	var err error
	switch r.PathValue("section") {
	case "defaults":
		var v config.Defaults
		if !decodeStrict(w, r, &v) {
			return
		}
		err = s.d.Settings.SetDefaults(&v)
	case "status":
		var v config.StatusConfig
		if !decodeStrict(w, r, &v) {
			return
		}
		err = s.d.Settings.SetStatus(&v)
	case "alerts":
		var v config.AlertSettings
		if !decodeStrict(w, r, &v) {
			return
		}
		err = s.d.Settings.SetAlerts(&v)
	case "dns_probes":
		var v []config.DNSProbeConfig
		if !decodeStrict(w, r, &v) {
			return
		}
		err = s.d.Settings.SetDNSProbes(&v)
	default:
		writeError(w, http.StatusNotFound, "unknown settings section")
		return
	}
	if err != nil {
		s.settingsError(w, r, err, "")
		return
	}
	s.handleSettings(w, r)
}

func (s *Server) handleDeleteSetting(w http.ResponseWriter, r *http.Request) {
	if s.d.Settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings are not available")
		return
	}
	var err error
	switch r.PathValue("section") {
	case "defaults":
		err = s.d.Settings.SetDefaults(nil)
	case "status":
		err = s.d.Settings.SetStatus(nil)
	case "alerts":
		err = s.d.Settings.SetAlerts(nil)
	case "dns_probes":
		err = s.d.Settings.SetDNSProbes(nil)
	default:
		writeError(w, http.StatusNotFound, "unknown settings section")
		return
	}
	if err != nil {
		s.settingsError(w, r, err, "")
		return
	}
	s.handleSettings(w, r)
}

// Resolver looks up host names for /api/resolve (net.DefaultResolver by default).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// handleResolve validates a host as a target would and, for a hostname, resolves it with the
// system resolver, so the UI can check an FQDN before saving.
func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("host")
	host, err := config.NormalizeHost(in)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "error": err.Error()})
		return
	}
	out := map[string]any{"valid": true, "host": host, "kind": config.HostKind(host), "addresses": []string{}}
	if config.HostKind(host) != config.HostHostname {
		out["addresses"] = []string{host}
		writeJSON(w, http.StatusOK, out)
		return
	}
	res := s.d.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	addrs, err := res.LookupNetIP(ctx, "ip", host)
	if err != nil {
		msg := err.Error()
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			msg = "no such host"
		}
		out["resolve_error"] = strings.TrimSpace(msg)
		writeJSON(w, http.StatusOK, out)
		return
	}
	list := make([]string, 0, len(addrs))
	for _, a := range addrs {
		list = append(list, a.Unmap().String())
	}
	out["addresses"] = list
	writeJSON(w, http.StatusOK, out)
}

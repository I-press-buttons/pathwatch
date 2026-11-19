package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// The user's profile: preferences that follow the account rather than the browser. Today it holds
// the overview page layout. It is stored in the settings table under "profile:<user>" (the Basic
// auth user, or "default" when authentication is off), so it survives browser changes and is
// shared by every browser signed in as that user.

const (
	profileKeyPrefix = "profile:"
	maxLayoutItems   = 2000 // targets / DNS probes / groups listed in a layout
	maxGroupKeyLen   = 300
)

// overviewSections are the movable sections of the overview page, in their default order.
var overviewSections = []string{"network", "status", "targets", "dns"}

// dnsGroupModes are the ways the overview groups DNS probe cards.
var dnsGroupModes = map[string]bool{"none": true, "server": true, "query": true}

type layoutSection struct {
	ID     string `json:"id"`
	Hidden bool   `json:"hidden"`
}

type dnsLayout struct {
	GroupBy    string              `json:"group_by"`              // none | server | query
	ProbeOrder []int64             `json:"probe_order,omitempty"` // card order (within each group)
	GroupOrder map[string][]string `json:"group_order,omitempty"` // group_by mode -> group keys in order
}

type overviewLayout struct {
	Sections    []layoutSection `json:"sections"`
	TargetOrder []int64         `json:"target_order,omitempty"`
	DNS         dnsLayout       `json:"dns"`
}

type profileJSON struct {
	User     string          `json:"user"`
	Overview *overviewLayout `json:"overview"` // null: the default layout
}

// profileUser is the account a request belongs to.
func (s *Server) profileUser(r *http.Request) string {
	if s.d.Auth.Enabled {
		if u, _, ok := r.BasicAuth(); ok && u != "" {
			return u
		}
	}
	return "default"
}

type storedProfile struct {
	Overview *overviewLayout `json:"overview,omitempty"`
}

func (s *Server) loadProfile(user string) (storedProfile, error) {
	var p storedProfile
	raw, ok, err := s.d.Store.Setting(profileKeyPrefix + user)
	if err != nil || !ok {
		return p, err
	}
	if json.Unmarshal([]byte(raw), &p) != nil {
		s.log.Warn("ignoring unreadable profile", "user", user)
		return storedProfile{}, nil
	}
	if p.Overview != nil && p.Overview.normalize() != nil {
		p.Overview = nil
	}
	return p, nil
}

func (s *Server) saveProfile(user string, p storedProfile) error {
	if p.Overview == nil {
		return s.d.Store.SetSetting(profileKeyPrefix+user, "")
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.d.Store.SetSetting(profileKeyPrefix+user, string(b))
}

func (s *Server) handleProfile(w http.ResponseWriter, r *http.Request) {
	user := s.profileUser(r)
	p, err := s.loadProfile(user)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, profileJSON{User: user, Overview: p.Overview})
}

func (s *Server) handlePutOverviewLayout(w http.ResponseWriter, r *http.Request) {
	if !requireJSON(w, r) {
		return
	}
	var l overviewLayout
	if !decodeStrict(w, r, &l) {
		return
	}
	if err := l.normalize(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user := s.profileUser(r)
	p, err := s.loadProfile(user)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	p.Overview = &l
	if err := s.saveProfile(user, p); err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, profileJSON{User: user, Overview: p.Overview})
}

func (s *Server) handleDeleteOverviewLayout(w http.ResponseWriter, r *http.Request) {
	user := s.profileUser(r)
	p, err := s.loadProfile(user)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	p.Overview = nil
	if err := s.saveProfile(user, p); err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, profileJSON{User: user, Overview: nil})
}

// normalize validates a layout and completes it: every known section appears exactly once (sections
// missing from the layout, such as ones added in a later version, are appended in default order),
// and an empty DNS grouping means "server".
func (l *overviewLayout) normalize() error {
	known := map[string]bool{}
	for _, id := range overviewSections {
		known[id] = true
	}
	seen := map[string]bool{}
	out := make([]layoutSection, 0, len(overviewSections))
	for _, sec := range l.Sections {
		if !known[sec.ID] {
			return fmt.Errorf("unknown overview section %q", sec.ID)
		}
		if seen[sec.ID] {
			return fmt.Errorf("overview section %q is listed twice", sec.ID)
		}
		seen[sec.ID] = true
		out = append(out, sec)
	}
	for _, id := range overviewSections {
		if !seen[id] {
			out = append(out, layoutSection{ID: id})
		}
	}
	l.Sections = out
	if len(l.TargetOrder) > maxLayoutItems || len(l.DNS.ProbeOrder) > maxLayoutItems {
		return fmt.Errorf("layout lists too many items")
	}
	if l.DNS.GroupBy == "" {
		l.DNS.GroupBy = "server"
	}
	if !dnsGroupModes[l.DNS.GroupBy] {
		return fmt.Errorf("dns.group_by must be none, server or query")
	}
	for mode, keys := range l.DNS.GroupOrder {
		{
			if !dnsGroupModes[mode] || mode == "none" {
				return fmt.Errorf("unknown DNS grouping %q", mode)
			}
			if len(keys) > maxLayoutItems {
				return fmt.Errorf("layout lists too many DNS groups")
			}
			for _, k := range keys {
				if len(k) > maxGroupKeyLen || strings.ContainsAny(k, "\x00") {
					return fmt.Errorf("invalid DNS group name")
				}
			}
		}
	}
	return nil
}

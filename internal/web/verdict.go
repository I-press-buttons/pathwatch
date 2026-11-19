package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// networkJSON is the combined verdict for the whole network: one answer to "is something wrong,
// and where?", built from the gateway and local-outage detector, the DNS resolver probes, the
// ISP's first hops and every target's own diagnosis. Segments walk the path from this server
// outwards so the UI can show where along it the problem sits.
type networkJSON struct {
	Severity string          `json:"severity"` // ok | info | warn | crit
	Code     string          `json:"code"`
	Where    *string         `json:"where"`     // local | dns | isp | shared | path | destination | server; null when not localized
	Hop      *int            `json:"hop"`       // the hop the verdict is about, on TargetID's path
	TargetID *int64          `json:"target_id"` // the target whose diagnosis the verdict comes from
	Headline string          `json:"headline"`
	Detail   string          `json:"detail"`
	Segments []segmentJSON   `json:"segments"`
	Affected []affectedJSON  `json:"affected"`
	DNS      []dnsHealthJSON `json:"dns"`
}

// segmentJSON is one stretch of the path, from this server outwards.
type segmentJSON struct {
	Key   string `json:"key"` // local | dns | isp | internet | destinations
	Label string `json:"label"`
	State string `json:"state"` // ok | warn | crit | unknown
	Note  string `json:"note"`
}

// affectedJSON is a target with a problem.
type affectedJSON struct {
	ID       int64   `json:"id"`
	Name     string  `json:"name"`
	Severity string  `json:"severity"`
	Where    *string `json:"where"`
	Headline string  `json:"headline"`
}

// dnsHealthJSON is a DNS resolver probe over the last 5 minutes.
type dnsHealthJSON struct {
	ProbeID int64    `json:"probe_id"`
	Name    string   `json:"name"`
	Server  string   `json:"server"`
	Local   bool     `json:"local"` // the resolver is in the home network (a router, Pi-hole, AdGuard Home …)
	State   string   `json:"state"` // ok | slow | failing | nodata
	FailPct *float64 `json:"fail_pct"`
	AvgMS   *float64 `json:"avg_ms"`
	LastErr string   `json:"last_error"`
}

// dnsHealth is what the verdict knows about one DNS probe.
type dnsHealth struct {
	ProbeID   int64
	Name      string // the probe: "home", or "home · reddit.com" when the server has several queries
	Resolver  string // the DNS server entry's name ("home"); empty means Name
	Query     string // the name looked up
	Server    string
	Local     bool
	Samples   int64
	FailPct   *float64
	AvgMS     *float64
	LastErr   string
	FailAlert bool // a dns_failure alert is firing
	SlowAlert bool // a dns_latency alert is firing
}

func (d dnsHealth) failing() bool {
	return d.FailAlert || (d.Samples >= 2 && d.FailPct != nil && *d.FailPct >= 50)
}

func (d dnsHealth) slow() bool { return !d.failing() && d.SlowAlert }

// healthy reports whether most lookups of the window succeeded (one failed lookup alone is
// neither healthy nor an outage yet).
func (d dnsHealth) healthy() bool {
	return !d.failing() && d.Samples > 0 && (d.FailPct == nil || *d.FailPct < 50)
}

// label names the resolver: "home (192.168.1.1:53)".
func (d dnsHealth) label() string {
	n := d.Resolver
	if n == "" {
		n = d.Name
	}
	return n + " (" + d.Server + ")"
}

func (d dnsHealth) state() string {
	switch {
	case d.failing():
		return "failing"
	case d.slow():
		return "slow"
	case d.healthy():
		return "ok"
	}
	return "nodata"
}

// dnsErrKind sorts the last error of a DNS probe: the resolver does not answer at all
// ("silent"), answers SERVFAIL because its own upstream lookups fail ("upstream"), answers
// with another error code ("rcode"), or answers something an answer check rejects ("answer").
func dnsErrKind(e string) string {
	l := strings.ToLower(e)
	switch {
	case e == "":
		return ""
	case strings.HasPrefix(l, probe.WrongAnswerPrefix):
		return "answer"
	case strings.Contains(l, "servfail"):
		return "upstream"
	case strings.HasPrefix(l, "rcode"):
		return "rcode"
	}
	return "silent"
}

// localResolver reports whether a DNS server ("host:port" or a bare address) is in the home network.
func localResolver(server string) bool {
	host := server
	if h, _, err := net.SplitHostPort(server); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback()
}

// netTarget is a running target as the verdict sees it.
type netTarget struct {
	ID     int64
	Name   string
	Status string
	Diag   diagnosisJSON
}

// netInput is everything networkVerdict needs; the API layer fills it in.
type netInput struct {
	HasData      bool // the analyzer has judged at least one window
	Local        alert.LocalState
	GatewayKnown bool // some target's hop 1 was judged in the latest window
	GatewayOK    bool // ... and it answered cleanly
	GatewayTTL1  string
	ISPKnown     bool // some target's first public hop was judged in the latest window
	ISPOK        bool // ... and it answered cleanly
	ISPHop       string
	Targets      []netTarget
	DNS          []dnsHealth
}

var segmentOrder = []struct{ key, label string }{
	{"local", "Your network"}, {"dns", "DNS"}, {"isp", "ISP"}, {"internet", "Internet"}, {"destinations", "Destinations"},
}

// segmentOf maps a diagnosis location to the stretch of the path it belongs to.
func segmentOf(where *string) string {
	if where == nil {
		return "internet"
	}
	switch *where {
	case "local":
		return "local"
	case "dns":
		return "dns"
	case "isp":
		return "isp"
	case "shared", "path":
		return "internet"
	}
	return "destinations"
}

// wherePriority orders diagnosis locations from the most fundamental (a problem there breaks
// everything behind it) to the most specific.
var wherePriority = map[string]int{"local": 0, "isp": 1, "dns": 2, "shared": 3, "path": 4, "destination": 5, "server": 6}

func whereRank(w *string) int {
	if w == nil {
		return 7
	}
	if r, ok := wherePriority[*w]; ok {
		return r
	}
	return 7
}

func sevRank(s string) int {
	switch s {
	case "crit":
		return 3
	case "warn":
		return 2
	case "info":
		return 1
	}
	return 0
}

type segments struct {
	list []segmentJSON
}

func newSegments() *segments {
	s := &segments{}
	for _, x := range segmentOrder {
		s.list = append(s.list, segmentJSON{Key: x.key, Label: x.label, State: "unknown"})
	}
	return s
}

func (s *segments) get(key string) *segmentJSON {
	for i := range s.list {
		if s.list[i].Key == key {
			return &s.list[i]
		}
	}
	return nil
}

// set records a state for a segment, keeping the worse one (and its note) when there is one.
func (s *segments) set(key, state, note string) {
	g := s.get(key)
	rank := func(st string) int {
		switch st {
		case "crit":
			return 3
		case "warn":
			return 2
		case "ok":
			return 1
		}
		return 0
	}
	if rank(state) > rank(g.State) || (rank(state) == rank(g.State) && g.Note == "") {
		g.State, g.Note = state, note
	}
}

// networkVerdict combines the facts into one verdict. Like diagnose, it checks from the most
// fundamental cause (your own connection) outwards, so the headline names the cause rather than
// one of its symptoms.
func networkVerdict(in netInput) (out networkJSON) {
	segs := newSegments()
	out = networkJSON{Severity: "ok", Affected: []affectedJSON{}, DNS: []dnsHealthJSON{}}

	// --- what each segment looks like ---
	if in.GatewayKnown {
		if in.GatewayOK {
			segs.set("local", "ok", "Gateway answers"+in.GatewayTTL1)
		} else {
			segs.set("local", "warn", "Gateway answers poorly"+in.GatewayTTL1)
		}
	}
	if in.ISPKnown {
		if in.ISPOK {
			segs.set("isp", "ok", "First ISP hop answers"+in.ISPHop)
		} else {
			segs.set("isp", "warn", "First ISP hop answers poorly"+in.ISPHop)
		}
	}
	fresh, nodata := 0, 0
	for _, t := range in.Targets {
		if t.Status == "nodata" {
			nodata++
		} else {
			fresh++
		}
	}
	if fresh > 0 {
		segs.set("internet", "ok", "")
		segs.set("destinations", "ok", fmt.Sprintf("%d of %d %s fine", fresh, len(in.Targets), pickN(len(in.Targets), "target", "targets")))
	}
	var localDNS, publicDNS, slowDNS, okDNS []dnsHealth
	for _, d := range in.DNS {
		out.DNS = append(out.DNS, dnsHealthJSON{ProbeID: d.ProbeID, Name: d.Name, Server: d.Server, Local: d.Local, State: d.state(),
			FailPct: d.FailPct, AvgMS: d.AvgMS, LastErr: d.LastErr})
		switch {
		case d.failing() && d.Local:
			localDNS = append(localDNS, d)
			segs.set("dns", "crit", d.Name+" is failing")
		case d.failing():
			publicDNS = append(publicDNS, d)
			segs.set("dns", "warn", d.Name+" is failing")
		case d.slow():
			slowDNS = append(slowDNS, d)
			segs.set("dns", "warn", d.Name+" is slow")
		case d.healthy():
			okDNS = append(okDNS, d)
			note := d.Name + " answers"
			if d.AvgMS != nil {
				note += " in " + msText(*d.AvgMS)
			}
			segs.set("dns", "ok", note)
		}
	}
	if g := segs.get("dns"); len(in.DNS) == 0 {
		g.Note = "No DNS probe"
	} else if g.State == "unknown" {
		g.Note = "No results yet"
	}

	// --- targets with a problem ---
	var affected []netTarget
	for _, t := range in.Targets {
		if t.Diag.Severity != "warn" && t.Diag.Severity != "crit" {
			continue
		}
		affected = append(affected, t)
		segs.set(segmentOf(t.Diag.Where), t.Diag.Severity, t.Name+": "+t.Diag.Headline)
	}
	sort.SliceStable(affected, func(i, j int) bool {
		a, b := affected[i].Diag, affected[j].Diag
		if whereRank(a.Where) != whereRank(b.Where) {
			return whereRank(a.Where) < whereRank(b.Where)
		}
		return sevRank(a.Severity) > sevRank(b.Severity)
	})
	for _, t := range affected {
		out.Affected = append(out.Affected, affectedJSON{ID: t.ID, Name: t.Name, Severity: t.Diag.Severity, Where: t.Diag.Where, Headline: t.Diag.Headline})
	}

	// every return below carries the segments as they stand then
	defer func() { out.Segments = segs.list }()

	// --- the verdict ---
	switch {
	case len(in.Targets) == 0 && len(in.DNS) == 0:
		out.Severity, out.Code = "info", "nothing_monitored"
		out.Headline = "Nothing is monitored yet"
		out.Detail = "Add a target (your ISP's first hop, a well-known site) and a DNS probe for your resolver to get a verdict for the whole network."
		return out

	case in.Local.Down && in.Local.Reason == "gateway":
		out.Severity, out.Code, out.Where = "crit", "gateway_down", where("local")
		segs.set("local", "crit", "Gateway stopped answering")
		out.Headline = "Your local network is down: the router (gateway) stopped answering"
		out.Detail = "Nothing beyond the router can be reached, so every target fails with it. Check the router, its power, and the cable or Wi-Fi between it and this server."
		return out

	case in.Local.Down:
		out.Severity = "crit"
		if in.GatewayKnown && in.GatewayOK {
			out.Code, out.Where = "isp_outage", where("isp")
			segs.set("isp", "crit", "Nothing beyond the router answers")
			out.Headline = "Your internet connection is down: the router answers, nothing beyond it does"
			out.Detail = "Your home network works up to the router, but every destination fails. The modem, the line or your ISP is down: check the modem's status lights and your ISP's outage page."
		} else {
			out.Code, out.Where = "connection_down", where("local")
			segs.set("local", "crit", "Every target fails")
			out.Headline = "Every target is failing at once: the problem is your own connection"
			out.Detail = "When all destinations fail together, the part they share (your router, modem or ISP) is the cause."
		}
		if len(localDNS) > 0 {
			out.Detail += " " + dnsLabels(localDNS) + " fails too, as a consequence."
		}
		return out

	case len(localDNS) > 0:
		return localDNSVerdict(out, localDNS, okDNS, publicDNS, affected, fresh)
	}

	if len(affected) > 0 {
		return targetsVerdict(out, affected, in)
	}

	switch {
	case len(publicDNS) > 0:
		out.Severity, out.Code, out.Where = "warn", "dns_public_failing", where("dns")
		out.Headline = "DNS resolver " + dnsLabels(publicDNS) + " is failing"
		out.Detail = "It is outside your network (often your ISP's or a public resolver)."
		if fresh > 0 {
			out.Detail += " Your targets are reachable, so the connection itself works."
		}
		if len(okDNS) > 0 {
			out.Detail += " " + dnsLabels(okDNS) + " still answers: devices using it are not affected."
		}
		return out
	case len(slowDNS) > 0:
		out.Severity, out.Code, out.Where = "warn", "dns_slow", where("dns")
		out.Headline = "DNS lookups are slower than usual at " + dnsLabels(slowDNS)
		out.Detail = "Every new connection waits for the lookup, so pages start to load later. Check the resolver's load and its upstream servers."
		return out
	}

	if fresh == 0 && len(in.Targets) > 0 {
		out.Severity, out.Code = "info", "nodata"
		out.Headline = "No recent results"
		out.Detail = "Results normally arrive within seconds of starting. If this lasts, the pathwatch log says why probes are not running."
		return out
	}

	out.Code = "ok"
	out.Headline = "Your network, DNS and ISP look healthy"
	var parts []string
	if in.GatewayKnown {
		parts = append(parts, "The router answers.")
	}
	if fresh > 0 {
		parts = append(parts, fmt.Sprintf("%d %s reachable and no alert is firing.", fresh, pickN(fresh, "target is", "targets are")))
	}
	if nodata > 0 {
		parts = append(parts, fmt.Sprintf("%d %s no recent results.", nodata, pickN(nodata, "target has", "targets have")))
	}
	if len(okDNS) > 0 {
		parts = append(parts, dnsLabels(okDNS)+" "+pickN(resolverCount(okDNS), "answers", "answer")+".")
	}
	if !anyLocal(in.DNS) {
		parts = append(parts, "Add a DNS probe for your own resolver (Settings → DNS probe setup) so DNS outages show up here too.")
	}
	out.Detail = strings.Join(parts, " ")
	return out
}

func localDNSVerdict(out networkJSON, failing, okDNS, publicDNS []dnsHealth, affected []netTarget, fresh int) networkJSON {
	// A resolver that still answers some of its queries is up: only those names fail.
	answers := map[string][]string{} // server -> names it answers
	for _, o := range okDNS {
		answers[o.Server] = append(answers[o.Server], o.Query)
	}
	var down, names []dnsHealth
	for _, f := range failing {
		if len(answers[f.Server]) > 0 && f.Query != "" {
			names = append(names, f)
		} else {
			down = append(down, f)
		}
	}
	if len(down) == 0 {
		d := names[0]
		out.Severity, out.Code, out.Where = "warn", "dns_local_name", where("dns")
		out.Headline = "Your DNS resolver " + d.label() + " fails to look up " + d.Query
		out.Detail = "It still answers " + joinAnd(answers[d.Server]) + ", so the resolver itself is up. The lookup of " + d.Query
		if d.LastErr != "" {
			out.Detail += " fails (" + d.LastErr + ")"
		} else {
			out.Detail += " fails"
		}
		out.Detail += ": check the resolver's blocklists and the name, or whether that domain's own DNS has a problem."
		if len(names) > 1 {
			more := make([]string, 0, len(names)-1)
			for _, n := range names[1:] {
				more = append(more, n.Query+" on "+n.label())
			}
			out.Detail += " Also failing: " + joinAnd(more) + "."
		}
		return out
	}
	failing = down
	d := failing[0]
	out.Severity, out.Code, out.Where = "crit", "dns_local_down", where("dns")
	switch dnsErrKind(d.LastErr) {
	case "upstream":
		out.Code = "dns_local_upstream"
		out.Headline = "Your DNS resolver " + d.label() + " answers, but its upstream lookups fail"
		out.Detail = "It replies SERVFAIL: the resolver runs but cannot get answers from its upstream servers. Check its upstream DNS settings (DoH/DoT servers, or the ISP resolver it forwards to)."
	case "answer":
		out.Code = "dns_local_wrong_answer"
		out.Headline = "Your DNS resolver " + d.label() + " gives wrong answers"
		out.Detail = "It answers, but not what this probe expects (" + strings.TrimPrefix(d.LastErr, probe.WrongAnswerPrefix) + "). A stale cache, a broken blocklist or a resolver that rewrites names can cause this."
	case "rcode":
		out.Code = "dns_local_rejects"
		out.Headline = "Your DNS resolver " + d.label() + " rejects lookups"
		out.Detail = "It answers with an error (" + d.LastErr + "). Check its access settings and blocklists, and the name the probe looks up."
	default:
		out.Headline = "Your DNS resolver " + d.label() + " is not answering"
		if strings.Contains(strings.ToLower(d.LastErr), "refused") {
			out.Detail = "Nothing listens on that address and port any more"
		} else {
			out.Detail = "Lookups get no reply"
		}
		out.Detail += ", so devices that use it cannot open sites by name. Check the resolver itself: its container or host is down, stuck or restarting."
	}
	if k := dnsErrKind(d.LastErr); d.LastErr != "" && k != "rcode" && k != "answer" {
		out.Detail += ` Last error: "` + d.LastErr + `".`
	}
	var otherDown []dnsHealth // other resolvers that are down (not more queries of this one)
	for _, f := range failing[1:] {
		if f.label() != d.label() {
			otherDown = append(otherDown, f)
		}
	}
	if n := resolverCount(otherDown); n > 0 {
		out.Detail += " " + dnsLabels(otherDown) + " " + pickN(n, "fails", "fail") + " too."
	}
	switch {
	case len(okDNS) > 0:
		out.Detail += " " + dnsLabels(okDNS) + " still " + pickN(resolverCount(okDNS), "answers", "answer") + ", so the internet is reachable: the problem is your resolver."
	case len(publicDNS) > 0:
		out.Detail += " " + dnsLabels(publicDNS) + " " + pickN(resolverCount(publicDNS), "fails", "fail") + " as well."
	}
	if fresh > 0 && len(affected) == 0 {
		out.Detail += " Your targets are reachable, so the network connection itself works."
	} else if len(affected) > 0 {
		out.Detail += " " + affectedText(affected) + "."
	}
	return out
}

func targetsVerdict(out networkJSON, affected []netTarget, in netInput) networkJSON {
	top := affected[0]
	td := top.Diag
	out.Severity, out.Where, out.Hop = td.Severity, td.Where, td.Hop
	id := top.ID
	out.TargetID = &id
	for _, t := range affected {
		if sevRank(t.Diag.Severity) > sevRank(out.Severity) {
			out.Severity = t.Diag.Severity
		}
	}
	same := 0 // other affected targets with the same location
	for _, t := range affected[1:] {
		if whereRank(t.Diag.Where) == whereRank(td.Where) {
			same++
		}
	}
	w := ""
	if td.Where != nil {
		w = *td.Where
	}
	hopText := ""
	if td.Hop != nil {
		hopText = fmt.Sprintf(" (hop %d)", *td.Hop)
	}
	switch w {
	case "local":
		out.Code = "local_problem"
		out.Headline = "Your home network is losing packets or adding delay" + hopText
		out.Detail = td.Headline + ". " + td.Detail
	case "isp":
		out.Code = "isp_problem"
		out.Headline = "Your ISP is losing packets or adding delay" + hopText
		out.Detail = td.Headline + ". " + td.Detail
	case "dns":
		out.Code = "dns_problem"
		out.Headline = "Name lookups are failing or slow"
		out.Detail = top.Name + ": " + td.Headline + ". " + td.Detail
	case "shared":
		out.Code = "upstream_problem"
		out.Headline = "A router beyond your ISP, shared by several targets, has trouble" + hopText
		out.Detail = td.Headline + ". " + td.Detail
	default:
		out.Code = "target_problem"
		if len(affected) == 1 {
			out.Headline = "Only " + top.Name + " has a problem"
		} else {
			out.Headline = fmt.Sprintf("%d targets have problems, each on its own route or server", len(affected))
		}
		out.Detail = top.Name + ": " + td.Headline + ". "
		if !in.GatewayKnown || in.GatewayOK {
			out.Detail += "Your own network and ISP look fine, so the cause is on the way to that destination or at its server."
		} else {
			out.Detail += td.Detail
		}
	}
	if w == "local" || w == "isp" || w == "shared" || w == "dns" {
		if same > 0 || len(affected) > 1 {
			out.Detail += " " + affectedText(affected) + "."
		}
	} else if len(affected) > 1 {
		out.Detail += " " + affectedText(affected) + "."
	}
	return out
}

// affectedText is "Affected: alpha, beta and 2 more".
func affectedText(list []netTarget) string {
	names := make([]string, 0, len(list))
	for _, t := range list {
		names = append(names, t.Name)
	}
	if len(names) > 4 {
		names = append(names[:3], fmt.Sprintf("%d more", len(names)-3))
	}
	return "Affected: " + joinAnd(names)
}

func dnsLabels(list []dnsHealth) string {
	names := make([]string, 0, len(list))
	seen := map[string]bool{}
	for _, d := range list {
		if l := d.label(); !seen[l] { // one entry per resolver, however many of its queries fail
			seen[l] = true
			names = append(names, l)
		}
	}
	return joinAnd(names)
}

// resolverCount is the number of distinct resolvers in list (a resolver can have several queries).
func resolverCount(list []dnsHealth) int {
	seen := map[string]bool{}
	for _, d := range list {
		seen[d.label()] = true
	}
	return len(seen)
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

func pickN(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func anyLocal(list []dnsHealth) bool {
	for _, d := range list {
		if d.Local {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// gathering the facts

// dnsHealthWindow is how much DNS probe history the verdict judges (the same as the target cards).
const dnsHealthWindow = 5 * time.Minute

// dnsHealthOf judges every running DNS probe over the last 5 minutes.
func (s *Server) dnsHealthOf(ctx context.Context, active []store.Alert) []dnsHealth {
	if s.d.Sched == nil {
		return nil
	}
	now := s.now()
	since := now.Add(-dnsHealthWindow)
	plan := store.SinglePlan(since, now, store.TierRaw)
	firing := map[int64]map[string]bool{}
	for _, a := range active {
		if a.TargetID != nil || (a.RuleType != "dns_failure" && a.RuleType != "dns_latency") {
			continue
		}
		var d struct {
			ProbeID int64 `json:"probe_id"`
		}
		if json.Unmarshal([]byte(a.DetailsJSON), &d) != nil || d.ProbeID == 0 {
			continue
		}
		if firing[d.ProbeID] == nil {
			firing[d.ProbeID] = map[string]bool{}
		}
		firing[d.ProbeID][a.RuleType] = true
	}
	var out []dnsHealth
	for _, st := range s.d.Sched.DNSStates() {
		h := dnsHealth{ProbeID: st.ProbeID, Name: st.Spec.Label(), Resolver: st.Spec.Name, Query: st.Spec.Query, Server: st.Spec.Server, Local: localResolver(st.Spec.Server),
			FailAlert: firing[st.ProbeID]["dns_failure"], SlowAlert: firing[st.ProbeID]["dns_latency"]}
		if pc, err := s.d.Store.ProbeCells(ctx, st.ProbeID, config.ProbeDNS, plan, store.CellOpts{NoHist: true}); err == nil {
			t := pc.Total()
			h.Samples = t.N
			if v, ok := t.FailPct(); ok {
				h.FailPct = fp(v, true)
			}
			if v, ok := t.AvgTotal(); ok {
				h.AvgMS = fp(v, true)
			}
		}
		if e, ok := s.d.Store.LastProbeFailure(st.ProbeID, config.ProbeDNS, since); ok {
			h.LastErr = e
		}
		out = append(out, h)
	}
	return out
}

// answered reports whether a hop class means the hop replied cleanly in the window.
func answered(c string) bool { return c == analyze.ClassOK || c == analyze.ClassRateLimited }

// netInputOf collects what networkVerdict needs from the targets already built for the request.
func (s *Server) netInputOf(targets []targetJSON, dc *diagContext) netInput {
	in := netInput{Local: dc.local, DNS: dc.dns}
	if s.d.Analyzer != nil {
		in.HasData = s.d.Analyzer.HasData()
	}
	gwAddr, ispAddr := "", ""
	for _, t := range targets {
		if !t.Active {
			continue
		}
		in.Targets = append(in.Targets, netTarget{ID: t.ID, Name: t.Name, Status: t.Status, Diag: t.Diagnosis})
		a, ok := dc.analyses[t.ID]
		if !ok {
			continue
		}
		if c, ok := a.Classes[1]; ok && c != analyze.ClassNoReply && c != "" {
			in.GatewayKnown = true
			if answered(c) {
				in.GatewayOK = true
			}
			if gwAddr == "" {
				gwAddr, _ = dc.hopAt(t.ID, 1)
			}
		}
		if ttl, addr, ok := dc.firstPublic(t.ID); ok {
			if c, ok := a.Classes[ttl]; ok && c != analyze.ClassNoReply && c != "" {
				in.ISPKnown = true
				if answered(c) {
					in.ISPOK = true
				}
				if ispAddr == "" {
					ispAddr = fmt.Sprintf("hop %d, %s", ttl, addr)
				}
			}
		}
	}
	if gwAddr != "" {
		in.GatewayTTL1 = " (" + gwAddr + ")"
	}
	if ispAddr != "" {
		in.ISPHop = " (" + ispAddr + ")"
	}
	return in
}

// handleNetwork serves the combined verdict for the whole network.
func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	targets, dc, err := s.targetList(r.Context(), false)
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, networkVerdict(s.netInputOf(targets, dc)))
}

// localDNSDown names the first failing local DNS resolver ("adguard (192.168.1.5:53)"), or "".
func localDNSDown(list []dnsHealth) string {
	for _, d := range list {
		if d.Local && d.failing() {
			return d.label()
		}
	}
	return ""
}

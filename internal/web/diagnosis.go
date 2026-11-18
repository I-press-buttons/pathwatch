package web

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// diagnosisJSON is a plain-language verdict for a target: what is wrong (if anything) and where
// on the path, from what the hop classifier, the probes and the alert engine already know. It
// answers the question the hop grid and heatmap make the user work out: "is it my network, my
// ISP, the route, or the server?".
type diagnosisJSON struct {
	Severity string  `json:"severity"` // ok | info | warn | crit
	Code     string  `json:"code"`
	Where    *string `json:"where"` // local | shared | path | destination | server | dns; null when not localized
	Hop      *int    `json:"hop"`   // the hop the finding is about (where a degradation starts, or a rate-limited hop)
	Headline string  `json:"headline"`
	Detail   string  `json:"detail"`
}

// hopRef identifies a hop in the text.
type hopRef struct {
	TTL      int
	Address  string
	Hostname string
	ASN      int
	ASName   string
}

// label is "hop 3 (core1.example.net, 203.0.113.1)".
func (h hopRef) label() string {
	var id []string
	if h.Hostname != "" {
		id = append(id, h.Hostname)
	}
	if h.Address != "" {
		id = append(id, h.Address)
	}
	s := "hop " + strconv.Itoa(h.TTL)
	if len(id) > 0 {
		s += " (" + strings.Join(id, ", ") + ")"
	}
	return s
}

func (h hopRef) addr() (netip.Addr, bool) {
	a, err := netip.ParseAddr(h.Address)
	return a, err == nil
}

// inside reports whether the hop is in the user's own network (private, link-local or loopback).
func (h hopRef) inside() bool {
	a, ok := h.addr()
	return ok && (a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLoopback())
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// network names the network a hop belongs to, for "the problem is probably at …".
func (h hopRef) network() string {
	switch {
	case h.ASN != 0 && h.ASName != "":
		return fmt.Sprintf("AS%d (%s)", h.ASN, h.ASName)
	case h.ASN != 0:
		return fmt.Sprintf("AS%d", h.ASN)
	}
	if a, ok := h.addr(); ok && cgnat.Contains(a.Unmap()) {
		return "your ISP (the hop is in its carrier-grade NAT range)"
	}
	return "that hop's network"
}

// slowPhase attributes an HTTP latency alert to the phase that grew the most.
type slowPhase struct {
	Phase               string  // dns | connect | tls | ttfb | transfer
	Before, Now         float64 // phase average (ms) before the alert began and over the last 5 minutes
	ConnBefore, ConnNow float64 // TCP connect, for contrast
	haveConn            bool
}

// diagInput is everything diagnose needs; the API layer fills it in.
type diagInput struct {
	Status           string // the target's status (statusOf)
	Paused, Removed  bool
	ICMPAvailable    bool // hop tracing works on this server
	HasICMP          bool // the target traces hops
	HasEndpoint      bool // the target has an HTTP or TCP probe
	ICMPUnresponsive bool
	Local            alert.LocalState

	E2ELoss     *float64
	E2ESource   string // icmp | tcp | last_hop | http | "" (see e2eResult)
	LossLimit   float64
	HTTPSuccess *float64
	HTTPLimit   float64

	Degraded bool   // a fresh real degradation from the hop classifier
	Start    hopRef // the hop it starts at
	// LossFrom is, without a real degradation, the first hop from which every hop up to a lossy
	// destination loses pings (the classifier calls them rate-limited when the HTTP/TCP probes
	// stay clean, but loss that persists to the destination still points at where it starts).
	LossFrom       hopRef
	DestTTL        int
	SharedThrough  int   // other running targets whose current path includes Start (or LossFrom)
	SharedAffected int   // of those, how many are losing packets or degraded too
	RateLimited    []int // intermediate hops classified as ICMP rate-limited, ascending
	ProbesOK       bool  // the HTTP/TCP probes succeed (no failures, success above the threshold)

	Alerts    []store.Alert // active alerts of the target
	HTTPError string        // newest HTTP failure of the last 5 minutes
	TCPError  string        // newest TCP failure of the last 5 minutes
	Slow      *slowPhase
	Learning  bool
}

// e2eICMP is the e2eResult source of a destination that answers Echo Requests.
const e2eICMP = "icmp"

func where(s string) *string { return &s }

func pct(v float64) string {
	if v == math.Trunc(v) {
		return strconv.FormatFloat(v, 'f', 0, 64) + "%"
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + "%"
}

func msText(v float64) string {
	switch {
	case v >= 100:
		return strconv.FormatFloat(math.Round(v), 'f', 0, 64) + " ms"
	case v >= 10:
		return strconv.FormatFloat(v, 'f', 0, 64) + " ms"
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + " ms"
}

// diagnose turns the facts about a target into one verdict. Problems are checked from the most
// fundamental (your own connection) to the most specific (one probe's latency), so the headline
// names the cause rather than a symptom of it.
func diagnose(in diagInput) diagnosisJSON {
	switch {
	case in.Removed:
		return diagnosisJSON{Severity: "info", Code: "removed", Headline: "No longer monitored", Detail: "This target was removed from the config file; its history is kept."}
	case in.Paused:
		return diagnosisJSON{Severity: "info", Code: "paused", Headline: "Monitoring is paused", Detail: "Resume the target to measure it again."}
	case in.Local.Down:
		d := diagnosisJSON{Severity: "crit", Code: "local_outage", Where: where("local")}
		if in.Local.Reason == "gateway" {
			d.Headline = "Your local network is down: the gateway stopped answering"
			d.Detail = "Your router (hop 1 or 2) no longer replies, so nothing beyond it can be reached. Check the router, modem, cabling or Wi-Fi."
		} else {
			d.Headline = "Every target is failing at once: the problem is your own connection"
			d.Detail = "When all destinations fail together, the part they share (your router, modem or ISP) is the cause."
		}
		d.Detail += " Alerts for single targets are held back meanwhile; the notification goes out once the connection is back."
		return d
	case in.Status == "nodata":
		d := diagnosisJSON{Severity: "info", Code: "nodata", Headline: "No recent results"}
		switch {
		case !in.HasEndpoint && !in.HasICMP:
			d.Detail = "This target has no probes. Add hop tracing, an HTTP URL or a TCP port in Edit target."
		case !in.HasEndpoint && !in.ICMPAvailable:
			d.Detail = "Hop tracing is unavailable on this server (raw ICMP needs NET_RAW) and the target has no HTTP or TCP probe, so nothing measures it. Add one in Edit target."
		default:
			d.Detail = "Results normally arrive within seconds. If this lasts, the pathwatch log says why probes are not running."
		}
		return d
	}
	if in.Status != "alerting" && in.Status != "degraded" && in.Status != "silenced" {
		return healthy(in)
	}
	sev := "warn"
	if in.Status == "alerting" {
		sev = "crit"
	}
	if in.Degraded && in.Start.TTL > 0 {
		return pathDiagnosis(in, sev)
	}
	if l := in.E2ELoss; l != nil && in.networkE2E() && *l > in.LossLimit {
		return lossDiagnosis(in, *l, sev)
	}
	if alertOf(in.Alerts, "http_failure") != nil || (in.HTTPSuccess != nil && *in.HTTPSuccess < in.HTTPLimit) {
		return httpFailure(in, sev)
	}
	if alertOf(in.Alerts, "tcp_failure") != nil {
		return tcpFailure(in, sev)
	}
	if a := alertOf(in.Alerts, "http_latency"); a != nil {
		return httpSlow(in, a, sev)
	}
	if a := alertOf(in.Alerts, "cert_expiry"); a != nil {
		return diagnosisJSON{Severity: sev, Code: "cert_expiry", Where: where("server"), Headline: "The TLS certificate expires soon", Detail: a.Message}
	}
	if len(in.Alerts) > 0 {
		a := in.Alerts[0]
		return diagnosisJSON{Severity: sev, Code: "alert", Headline: "Alert " + a.Rule + " is firing", Detail: a.Message}
	}
	return diagnosisJSON{Severity: sev, Code: "degraded", Headline: "Degraded", Detail: "Loss or HTTP success crossed the status thresholds in the last 5 minutes (Settings → Status thresholds)."}
}

func alertOf(list []store.Alert, ruleType string) *store.Alert {
	for i := range list {
		if list[i].RuleType == ruleType {
			return &list[i]
		}
	}
	return nil
}

func pathDiagnosis(in diagInput, sev string) diagnosisJSON {
	k := in.Start
	hop := k.TTL
	d := diagnosisJSON{Severity: sev, Hop: &hop}
	switch {
	case in.DestTTL > 0 && k.TTL >= in.DestTTL:
		d.Code, d.Where = "destination", where("destination")
		d.Headline = "The destination itself is losing packets or answering slowly"
		d.Detail = "Every router on the way answers normally, so the problem is the destination host or the network right in front of it, not your connection."
	case k.TTL == 1 || k.inside():
		d.Code, d.Where = "path_local", where("local")
		d.Headline = "Loss or delay starts at " + k.label() + ", inside your network"
		d.Detail = "That hop and everything after it, including the destination, are affected. Check your router, Wi-Fi or cabling."
	case in.SharedAffected > 0:
		d.Code, d.Where = "path_shared", where("shared")
		d.Headline = "Loss or delay starts at " + k.label() + ", which other targets share"
		d.Detail = othersThrough(in.SharedAffected, in.SharedThrough, "affected too") + ", so the problem is probably at " + k.network() + " rather than at one destination."

	default:
		d.Code, d.Where = "path", where("path")
		d.Headline = "Loss or delay starts at " + k.label() + " and continues to the destination"
		if in.SharedThrough > 0 {
			d.Detail = "Other targets that go through this hop are fine, so only traffic towards this destination is affected (the route beyond the hop, or the hop treating it differently)."
		} else {
			d.Detail = "No other target goes through this hop: the problem is on the route to this destination, at " + k.network() + ", not in your own network."
		}
	}
	return d
}

func lossDiagnosis(in diagInput, loss float64, sev string) diagnosisJSON {
	d := diagnosisJSON{Severity: sev, Code: "e2e_loss"}
	k := in.LossFrom
	switch {
	case in.E2ESource == config.ProbeTCP:
		d.Headline = pct(loss) + " of TCP connections to the destination fail"
		d.Detail = "The destination does not answer ping, so this is measured with the TCP probe."
		return d
	case k.TTL == 0:
		d.Headline = pct(loss) + " packet loss to the destination"
		if !in.HasICMP || !in.ICMPAvailable {
			d.Detail = "Hop tracing is off for this target, so pathwatch cannot tell where on the path it starts."
		} else {
			d.Detail = "The hop analysis has not located where it starts yet; it judges each full minute of data."
		}
		return d
	}
	hop := k.TTL
	d.Hop = &hop
	if in.DestTTL > 0 && k.TTL >= in.DestTTL {
		d.Code, d.Where = "destination_loss", where("destination")
		d.Headline = pct(loss) + " of pings to the destination are lost"
		d.Detail = "Every router on the way answers normally; only the destination drops replies."
		if in.ProbesOK {
			d.Detail += " Its HTTP/TCP probes still succeed, so it probably limits its ping replies and real traffic is not affected."
		}
		return d
	}
	d.Headline = pct(loss) + " packet loss to the destination, starting at " + k.label()
	d.Detail = "Every hop from there to the destination loses pings, which points at that hop or the link in front of it."
	switch {
	case k.TTL == 1 || k.inside():
		d.Where = where("local")
		d.Detail += " It is inside your network: check your router, Wi-Fi or cabling."
	case in.SharedAffected > 0:
		d.Where = where("shared")
		d.Detail += " " + othersThrough(in.SharedAffected, in.SharedThrough, "losing packets too") + ", so the problem is probably at " + k.network() + "."

	default:
		d.Where = where("path")
		if in.SharedThrough > 0 {
			d.Detail += " Other targets through this hop are fine, so only the route towards this destination is affected."
		}
	}
	if in.ProbesOK {
		d.Detail += " The HTTP/TCP probes still succeed because TCP resends lost packets: web pages still load, if more slowly, while calls and games feel the loss directly."
	}
	return d
}

// othersThrough is "The other target through this hop is <what>", "Both other targets …",
// "All 3 other targets …" or "2 of the 3 other targets … are <what>".
func othersThrough(affected, through int, what string) string {
	subject, verb := "", "are"
	switch {
	case through == 1:
		subject, verb = "The other target", "is"
	case affected == through && through == 2:
		subject = "Both other targets"
	case affected == through:
		subject = fmt.Sprintf("All %d other targets", through)
	default:
		subject = fmt.Sprintf("%d of the %d other targets", affected, through)
		if affected == 1 {
			verb = "is"
		}
	}
	return subject + " through this hop " + verb + " " + what
}

// probeErrKind sorts a probe error into what it says about the cause.
func probeErrKind(e string) string {
	l := strings.ToLower(e)
	switch {
	case strings.HasPrefix(l, "unexpected status"):
		return "status"
	case strings.Contains(l, "no such host"), strings.Contains(l, "lookup "), strings.Contains(l, "resolve"):
		return "dns"
	case strings.Contains(l, "refused"):
		return "refused"
	case strings.Contains(l, "x509"), strings.Contains(l, "tls"), strings.Contains(l, "certificate"):
		return "tls"
	case strings.Contains(l, "timeout"), strings.Contains(l, "deadline"):
		return "timeout"
	case strings.Contains(l, "unreachable"), strings.Contains(l, "no route"):
		return "unreachable"
	case strings.Contains(l, "reset"), strings.Contains(l, "eof"), strings.Contains(l, "broken pipe"):
		return "reset"
	}
	return "other"
}

// networkE2E reports whether the end-to-end figures measure the network to the destination
// itself: its Echo Replies or TCP handshakes (not the last router, not HTTP).
func (in diagInput) networkE2E() bool {
	return in.E2ELoss != nil && (in.E2ESource == e2eICMP || in.E2ESource == config.ProbeTCP)
}

// pathClean reports whether the end-to-end ICMP/TCP signal says the network path is fine.
func (in diagInput) pathClean() bool {
	return in.networkE2E() && *in.E2ELoss <= in.LossLimit
}

func httpFailure(in diagInput, sev string) diagnosisJSON {
	d := diagnosisJSON{Severity: sev, Code: "http_failure"}
	tail := ""
	if in.HTTPSuccess != nil {
		tail = " " + pct(*in.HTTPSuccess) + " of HTTP requests succeeded in the last 5 minutes."
	}
	e := in.HTTPError
	if e == "" {
		d.Headline = "HTTP requests have been failing"
		if a := alertOf(in.Alerts, "http_failure"); a != nil {
			d.Detail = a.Message
		}
		d.Detail = strings.TrimSpace(d.Detail + tail)
		return d
	}
	last := ` Last error: "` + e + `".`
	switch probeErrKind(e) {
	case "status":
		d.Where = where("server")
		d.Headline = "The web server answers with an error (HTTP " + strings.TrimSpace(strings.TrimPrefix(strings.ToLower(e), "unexpected status")) + ")"
		d.Detail = "The network path works; the server or the application behind it returns the error."
	case "dns":
		d.Where = where("dns")
		d.Headline = "The host name does not resolve"
		d.Detail = "Check the name or your DNS resolver (a DNS probe in Settings can watch the resolver)."
	case "refused":
		d.Where = where("server")
		d.Headline = "The server refuses connections"
		d.Detail = "The host is reachable, but nothing accepts connections on that port: the web server is down or a firewall rejects them."
	case "tls":
		d.Where = where("server")
		d.Headline = "The TLS handshake fails"
		d.Detail = "The server's certificate or TLS setup is rejected."
	case "timeout":
		d.Headline = "HTTP requests time out"
		switch {
		case in.pathClean():
			d.Where = where("server")
			d.Headline += ", but the network path is clean"
			d.Detail = "Probes reach the destination normally, so the server, or a firewall in front of it, is not answering HTTP."
		case in.networkE2E():
			d.Where = where("path")
			d.Detail = "The destination is losing packets too, so the network is the likely cause."
		}
	case "unreachable":
		d.Where = where("path")
		d.Headline = "The destination is unreachable"
		d.Detail = "A router reports that it has no route to the destination."
	case "reset":
		d.Headline = "HTTP connections are cut off"
		d.Detail = "The connection is reset or closed early, often by a proxy, a firewall or an overloaded server."
	default:
		d.Headline = "HTTP requests fail"
	}
	d.Detail = strings.TrimSpace(d.Detail + tail + last)
	return d
}

func tcpFailure(in diagInput, sev string) diagnosisJSON {
	d := diagnosisJSON{Severity: sev, Code: "tcp_failure", Headline: "TCP connections fail"}
	e := in.TCPError
	if e == "" {
		if a := alertOf(in.Alerts, "tcp_failure"); a != nil {
			d.Detail = a.Message
		}
		return d
	}
	switch probeErrKind(e) {
	case "refused":
		d.Where = where("server")
		d.Headline = "The server refuses TCP connections"
		d.Detail = "The host is reachable, but nothing listens on that port or a firewall rejects it."
	case "timeout":
		d.Headline = "TCP connections time out"
		if in.E2ESource == e2eICMP && in.pathClean() {
			d.Where = where("server")
			d.Detail = "The destination answers ping normally, so a firewall is probably dropping that port, or the service is down."
		}
	case "unreachable":
		d.Where = where("path")
		d.Headline = "The destination is unreachable"
		d.Detail = "A router reports that it has no route to the destination."
	}
	d.Detail = strings.TrimSpace(d.Detail + ` Last error: "` + e + `".`)
	return d
}

func httpSlow(in diagInput, a *store.Alert, sev string) diagnosisJSON {
	d := diagnosisJSON{Severity: sev, Code: "http_slow", Headline: "Web requests are slower than usual", Detail: a.Message}
	p := in.Slow
	if p == nil {
		return d
	}
	rose := func(what string) string {
		return fmt.Sprintf("%s rose from %s to %s", what, msText(p.Before), msText(p.Now))
	}
	conn := ""
	if p.haveConn {
		if dc := p.ConnNow - p.ConnBefore; dc < math.Max(5, 0.2*(p.Now-p.Before)) {
			conn = fmt.Sprintf(", while TCP connect stayed at about %s, so the network path is not the cause", msText(p.ConnNow))
		} else {
			conn = fmt.Sprintf("; TCP connect also rose from %s to %s, so the network adds to it", msText(p.ConnBefore), msText(p.ConnNow))
		}
	}
	switch p.Phase {
	case "dns":
		d.Code, d.Where = "http_slow_dns", where("dns")
		d.Headline = "Web requests are slow because DNS lookups take longer"
		d.Detail = rose("DNS lookup time") + ". Check your DNS resolver."
	case "connect":
		d.Code, d.Where = "http_slow_network", where("path")
		d.Headline = "Web requests are slow because the network got slower"
		d.Detail = rose("TCP connect time") + ": that is round-trip time on the path, not the server."
	case "tls":
		d.Code, d.Where = "http_slow_server", where("server")
		d.Headline = "Web requests are slow: the TLS handshake takes longer"
		d.Detail = rose("TLS handshake time") + conn + "."
	case "ttfb":
		d.Code, d.Where = "http_slow_server", where("server")
		d.Headline = "The web server is slow to respond"
		d.Detail = rose("Time to first byte") + conn + "."
	case "transfer":
		d.Code, d.Where = "http_slow_transfer", where("path")
		d.Headline = "Responses take longer to download"
		d.Detail = rose("Transfer time") + ": limited bandwidth on the path, or a slow server."
	}
	return d
}

func hopsList(ttls []int) string {
	parts := make([]string, len(ttls))
	for i, t := range ttls {
		parts[i] = strconv.Itoa(t)
	}
	if len(parts) == 1 {
		return "Hop " + parts[0]
	}
	return "Hops " + strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

func healthy(in diagInput) diagnosisJSON {
	d := diagnosisJSON{Severity: "ok", Code: "ok", Headline: "No problems detected"}
	var parts []string
	switch {
	case in.ICMPUnresponsive && in.E2ESource == "tcp":
		parts = append(parts, "The destination does not answer ping, so end-to-end figures come from the TCP probe; it succeeds and no alert is firing.")
	case in.ICMPUnresponsive && in.E2ESource == "last_hop":
		parts = append(parts, "The destination does not answer ping and the target has no TCP probe, so end-to-end figures come from the last router that answers. Add a TCP probe for a real end-to-end signal.")
	case in.E2ESource == e2eICMP:
		parts = append(parts, "The destination answers normally and no alert is firing.")
	case in.HasEndpoint:
		parts = append(parts, "The probes succeed and no alert is firing.")
	default:
		parts = append(parts, "No alert is firing.")
	}
	if n := len(in.RateLimited); n > 0 {
		hop := in.RateLimited[0]
		d.Code, d.Hop = "ok_rate_limited", &hop
		verb, them := "drops", "it"
		if n > 1 {
			verb, them = "drop", "them"
		}
		parts = append(parts, fmt.Sprintf("%s %s some pings while the path beyond %s stays clean: the router limits its ping replies (ICMP rate-limiting), and real traffic is not affected.", hopsList(in.RateLimited), verb, them))
	}
	if in.Learning {
		if d.Code == "ok" {
			d.Code = "learning"
		}
		parts = append(parts, "Latency alerts start once enough history is collected (learning baseline).")
	}
	d.Detail = strings.Join(parts, " ")
	return d
}

// ---------------------------------------------------------------------------
// gathering the facts

// diagContext is what the diagnosis of one target needs to know about the others; it is built
// once per /api/targets request.
type diagContext struct {
	local    alert.LocalState
	alerts   map[int64][]store.Alert // active alerts by target
	paths    map[int64]store.PathRow // latest path by target
	hops     map[int64][]store.PathHopRow
	through  map[string]map[int64]bool  // hop address -> running targets whose latest path has it
	analyses map[int64]analyze.Analysis // fresh classifier results by target
	degraded map[int64]analyze.Analysis // the ones with a real degradation
}

// affected reports whether a target is losing packets to its destination or degraded.
func (dc *diagContext) affected(targetID int64) bool {
	if _, ok := dc.degraded[targetID]; ok {
		return true
	}
	a, ok := dc.analyses[targetID]
	return ok && lossOnset(a.Classes, dc.paths[targetID].DestTTL) > 0
}

func lossyClass(c string) bool { return c == analyze.ClassRateLimited || c == analyze.ClassDegraded }

// lossOnset returns the first TTL from which every answering hop up to the destination is
// classified rate-limited or degraded, or 0 when the destination itself is clean. Hops that
// never answer are skipped: they say nothing about where loss starts.
func lossOnset(classes map[int]string, dest int) int {
	if dest <= 0 || !lossyClass(classes[dest]) {
		return 0
	}
	k := dest
	for t := dest - 1; t >= 1; t-- {
		c := classes[t]
		if c == "" || c == analyze.ClassNoReply {
			continue
		}
		if !lossyClass(c) {
			break
		}
		k = t
	}
	return k
}

// freshAnalysis is the age up to which a classifier result counts (the same as statusOf).
const freshAnalysis = 5 * time.Minute

func (s *Server) newDiagContext(rows []store.TargetRow) *diagContext {
	dc := &diagContext{alerts: map[int64][]store.Alert{}, paths: map[int64]store.PathRow{}, hops: map[int64][]store.PathHopRow{},
		through: map[string]map[int64]bool{}, analyses: map[int64]analyze.Analysis{}, degraded: map[int64]analyze.Analysis{}}
	now := s.now()
	if s.d.Analyzer != nil {
		dc.local = s.d.Analyzer.Local()
	}
	if as, err := s.d.Store.ActiveAlerts(); err == nil {
		for _, a := range as {
			if a.TargetID != nil {
				dc.alerts[*a.TargetID] = append(dc.alerts[*a.TargetID], a)
			}
		}
	}
	var ids []int64
	for _, row := range rows {
		if !row.Active || row.Paused {
			continue
		}
		if p, err := s.d.Store.LatestPath(row.ID); err == nil {
			dc.paths[row.ID] = p
			ids = append(ids, p.ID)
		}
		if s.d.Analyzer != nil {
			if a, ok := s.d.Analyzer.Latest(row.ID); ok && now.Sub(a.At) < freshAnalysis {
				dc.analyses[row.ID] = a
				if a.Real {
					dc.degraded[row.ID] = a
				}
			}
		}
	}
	if hops, err := s.d.Store.PathHops(ids); err == nil {
		for tid, p := range dc.paths {
			dc.hops[tid] = hops[p.ID]
			for _, h := range hops[p.ID] {
				if dc.through[h.Address] == nil {
					dc.through[h.Address] = map[int64]bool{}
				}
				dc.through[h.Address][tid] = true
			}
		}
	}
	return dc
}

// hopAt returns the main responder of a TTL on the target's latest path.
func (dc *diagContext) hopAt(targetID int64, ttl int) (string, bool) {
	for _, h := range dc.hops[targetID] {
		if h.TTL == ttl && h.Idx == 0 {
			return h.Address, true
		}
	}
	for _, h := range dc.hops[targetID] {
		if h.TTL == ttl {
			return h.Address, true
		}
	}
	return "", false
}

// diagnosisOf gathers the facts about one target and diagnoses it.
func (s *Server) diagnosisOf(ctx context.Context, v targetView, tj targetJSON, e2eSource string, dc *diagContext) diagnosisJSON {
	return diagnose(s.diagInputOf(ctx, v, tj, e2eSource, dc))
}

// diagInputOf collects what diagnose needs. The probe error and phase lookups only run for a
// target that has a problem.
func (s *Server) diagInputOf(ctx context.Context, v targetView, tj targetJSON, e2eSource string, dc *diagContext) diagInput {
	now := s.now()
	th := s.cfg().Status
	in := diagInput{
		Status: tj.Status, Paused: v.row.Paused, Removed: !v.row.Active,
		ICMPAvailable:    s.d.Sched == nil || s.d.Sched.ICMPMode() != "unavailable",
		HasICMP:          !v.hasSt || v.state.Spec.ICMP != nil,
		HasEndpoint:      len(v.probesOfType(config.ProbeHTTP))+len(v.probesOfType(config.ProbeTCP)) > 0,
		ICMPUnresponsive: tj.ICMPUnresponsive,
		Local:            dc.local,
		E2ELoss:          tj.Summary.E2ELoss, E2ESource: e2eSource, LossLimit: th.DegradedLossPct,
		HTTPSuccess: tj.Summary.HTTPSuccess, HTTPLimit: th.DegradedHTTPSuccessPct,
		Alerts:   dc.alerts[v.row.ID],
		Learning: tj.Status == "learning",
	}
	if p, ok := dc.paths[v.row.ID]; ok {
		in.DestTTL = p.DestTTL
	}
	an, haveAn := dc.analyses[v.row.ID]
	if a, ok := dc.degraded[v.row.ID]; ok && a.StartTTL > 0 {
		in.Degraded = true
		in.Start = s.hopRefOf(dc, v.row.ID, a.StartTTL)
		in.SharedThrough, in.SharedAffected = dc.shared(v.row.ID, in.Start.Address)
	} else if haveAn {
		if k := lossOnset(an.Classes, in.DestTTL); k > 0 {
			in.LossFrom = s.hopRefOf(dc, v.row.ID, k)
			in.SharedThrough, in.SharedAffected = dc.shared(v.row.ID, in.LossFrom.Address)
		}
	}
	if haveAn {
		for ttl, c := range an.Classes {
			if c == analyze.ClassRateLimited && (in.DestTTL == 0 || ttl < in.DestTTL) {
				in.RateLimited = append(in.RateLimited, ttl)
			}
		}
		sortInts(in.RateLimited)
	}
	problem := tj.Status == "alerting" || tj.Status == "degraded" || tj.Status == "silenced"
	if problem {
		since := now.Add(-5 * time.Minute)
		for _, p := range v.probesOfType(config.ProbeHTTP) {
			if e, ok := s.d.Store.LastProbeFailure(p.ID, p.Type, since); ok {
				in.HTTPError = e
				break
			}
		}
		for _, p := range v.probesOfType(config.ProbeTCP) {
			if e, ok := s.d.Store.LastProbeFailure(p.ID, p.Type, since); ok {
				in.TCPError = e
				break
			}
		}
		if a := alertOf(in.Alerts, "http_latency"); a != nil {
			in.Slow = s.slowPhaseOf(ctx, v, a, now)
		}
		in.ProbesOK = in.HasEndpoint && in.HTTPError == "" && in.TCPError == "" &&
			alertOf(in.Alerts, "http_failure") == nil && alertOf(in.Alerts, "tcp_failure") == nil
	}
	return in
}

// hopRefOf names a hop of the target's latest path (address, and hostname and AS when known).
func (s *Server) hopRefOf(dc *diagContext, targetID int64, ttl int) hopRef {
	h := hopRef{TTL: ttl}
	addr, ok := dc.hopAt(targetID, ttl)
	if !ok {
		return h
	}
	h.Address = addr
	if s.d.Enrich != nil {
		if ip, err := netip.ParseAddr(addr); err == nil {
			info := s.d.Enrich.Lookup(ip)
			h.Hostname, h.ASN, h.ASName = info.Hostname, info.ASN, info.ASName
		}
	}
	return h
}

// shared counts the other running targets whose path goes through addr, and how many of them
// are losing packets or degraded too.
func (dc *diagContext) shared(targetID int64, addr string) (through, affected int) {
	if addr == "" {
		return 0, 0
	}
	for other := range dc.through[addr] {
		if other == targetID {
			continue
		}
		through++
		if dc.affected(other) {
			affected++
		}
	}
	return through, affected
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// slowPhaseWindow is how much history before an HTTP latency alert serves as "usual".
const slowPhaseWindow = 6 * time.Hour

// slowPhaseOf compares the HTTP phase averages of the last 5 minutes with those of the hours
// before the alert began and names the phase that grew the most.
func (s *Server) slowPhaseOf(ctx context.Context, v targetView, a *store.Alert, now time.Time) *slowPhase {
	var probeID int64
	var d struct {
		ProbeID int64 `json:"probe_id"`
	}
	if json.Unmarshal([]byte(a.DetailsJSON), &d) == nil {
		probeID = d.ProbeID
	}
	var before, cur store.ProbeRoll
	for _, p := range v.probesOfType(config.ProbeHTTP) {
		if probeID != 0 && p.ID != probeID {
			continue
		}
		// the minute the alert began already carries the slowdown (the plan's end bucket is inclusive)
		end := a.StartedAt.Add(-time.Minute)
		b, err := s.d.Store.ProbeCells(ctx, p.ID, p.Type, store.SinglePlan(end.Add(-slowPhaseWindow), end, store.Tier1m), store.CellOpts{NoHist: true})
		if err != nil {
			return nil
		}
		c, err := s.d.Store.ProbeCells(ctx, p.ID, p.Type, store.SinglePlan(now.Add(-5*time.Minute), now, store.TierRaw), store.CellOpts{NoHist: true})
		if err != nil {
			return nil
		}
		before.Merge(b.Total())
		cur.Merge(c.Total())
	}
	type ph struct {
		name string
		avg  func(*store.ProbeRoll) (float64, bool)
	}
	phases := []ph{
		{"dns", (*store.ProbeRoll).AvgDNS}, {"connect", (*store.ProbeRoll).AvgConnect}, {"tls", (*store.ProbeRoll).AvgTLS},
		{"ttfb", (*store.ProbeRoll).AvgTTFB}, {"transfer", (*store.ProbeRoll).AvgTransfer},
	}
	var best *slowPhase
	for _, x := range phases {
		b, ok1 := x.avg(&before)
		c, ok2 := x.avg(&cur)
		if !ok1 || !ok2 {
			continue
		}
		if best == nil || c-b > best.Now-best.Before {
			best = &slowPhase{Phase: x.name, Before: b, Now: c}
		}
	}
	if best == nil || best.Now-best.Before < 5 {
		return nil // nothing grew noticeably: no attribution
	}
	if cb, ok := before.AvgConnect(); ok {
		if cc, ok := cur.AvgConnect(); ok {
			best.ConnBefore, best.ConnNow, best.haveConn = cb, cc, true
		}
	}
	return best
}

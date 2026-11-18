package web

import (
	"strings"
	"testing"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

func diagOK() diagnosisJSON {
	return diagnosisJSON{Severity: "ok", Code: "ok", Headline: "No problems detected"}
}

// healthyNet is a home network with a working gateway and ISP hop, two healthy targets, a local
// AdGuard resolver and a public one.
func healthyNet() netInput {
	return netInput{
		HasData: true, GatewayKnown: true, GatewayOK: true, GatewayTTL1: " (192.168.1.1)", ISPKnown: true, ISPOK: true, ISPHop: " (hop 2, 203.0.113.1)",
		Targets: []netTarget{{ID: 1, Name: "cloudflare", Status: "ok", Diag: diagOK()}, {ID: 2, Name: "google", Status: "ok", Diag: diagOK()}},
		DNS: []dnsHealth{
			{ProbeID: 10, Name: "adguard", Server: "192.168.1.5:53", Local: true, Samples: 10, FailPct: f64(0), AvgMS: f64(4)},
			{ProbeID: 11, Name: "quad9", Server: "9.9.9.9:53", Samples: 10, FailPct: f64(0), AvgMS: f64(15)},
		},
	}
}

func segState(v networkJSON, key string) string {
	for _, s := range v.Segments {
		if s.Key == key {
			return s.State
		}
	}
	return "missing"
}

func TestNetworkVerdict(t *testing.T) {
	ispHop := 3
	cases := []struct {
		name     string
		mod      func(*netInput)
		code     string
		severity string
		where    string
		segs     map[string]string
		want     []string
		not      []string
	}{
		{name: "healthy", mod: func(in *netInput) {}, code: "ok", severity: "ok",
			segs: map[string]string{"local": "ok", "dns": "ok", "isp": "ok", "internet": "ok", "destinations": "ok"},
			want: []string{"look healthy", "router answers", "2 targets are reachable", "adguard (192.168.1.5:53) and quad9 (9.9.9.9:53) answer"},
			not:  []string{"Add a DNS probe"}},
		{name: "healthy without a local DNS probe suggests one", mod: func(in *netInput) { in.DNS = nil }, code: "ok", severity: "ok",
			segs: map[string]string{"dns": "unknown"}, want: []string{"Add a DNS probe for your own resolver"}},
		{name: "nothing configured", mod: func(in *netInput) { in.Targets, in.DNS = nil, nil }, code: "nothing_monitored", severity: "info"},
		{name: "gateway down", mod: func(in *netInput) {
			in.Local = alert.LocalState{Down: true, Reason: "gateway"}
			in.GatewayOK = false
		}, code: "gateway_down", severity: "crit", where: "local", segs: map[string]string{"local": "crit"},
			want: []string{"router (gateway) stopped answering"}},
		{name: "everything fails but the router answers: ISP outage", mod: func(in *netInput) {
			in.Local = alert.LocalState{Down: true, Reason: "all_targets"}
			in.ISPOK = false
		}, code: "isp_outage", severity: "crit", where: "isp", segs: map[string]string{"local": "ok", "isp": "crit"},
			want: []string{"internet connection is down", "modem"}},
		{name: "everything fails, gateway unknown", mod: func(in *netInput) {
			in.Local = alert.LocalState{Down: true, Reason: "all_targets"}
			in.GatewayKnown, in.GatewayOK = false, false
		}, code: "connection_down", severity: "crit", where: "local"},
		{name: "local resolver not answering", mod: func(in *netInput) {
			in.DNS[0].FailPct, in.DNS[0].LastErr = f64(100), "read udp 172.17.0.2:41000->192.168.1.5:53: i/o timeout"
		}, code: "dns_local_down", severity: "crit", where: "dns", segs: map[string]string{"dns": "crit", "local": "ok", "isp": "ok"},
			want: []string{"Your DNS resolver adguard (192.168.1.5:53) is not answering", "container", "quad9 (9.9.9.9:53) still answers", "the problem is your resolver", "network connection itself works"}},
		{name: "local resolver upstream broken", mod: func(in *netInput) {
			in.DNS[0].FailAlert, in.DNS[0].LastErr = true, "rcode SERVFAIL"
		}, code: "dns_local_upstream", severity: "crit", where: "dns", want: []string{"upstream lookups fail", "SERVFAIL"}},
		{name: "local resolver rejects", mod: func(in *netInput) {
			in.DNS[0].FailAlert, in.DNS[0].LastErr = true, "rcode REFUSED"
		}, code: "dns_local_rejects", severity: "crit", where: "dns", want: []string{"rejects lookups", "rcode REFUSED"}},
		{name: "local DNS beats a target problem and lists it", mod: func(in *netInput) {
			in.DNS[0].FailAlert = true
			in.Targets[0].Status = "alerting"
			in.Targets[0].Diag = diagnosisJSON{Severity: "crit", Code: "http_failure", Where: where("dns"), Headline: "The host name does not resolve"}
		}, code: "dns_local_down", severity: "crit", where: "dns", want: []string{"Affected: cloudflare"}},
		{name: "a few failed lookups are not an outage", mod: func(in *netInput) { in.DNS[0].FailPct = f64(20) }, code: "ok", severity: "ok"},
		{name: "one failed first lookup is neither healthy nor an outage", mod: func(in *netInput) { in.DNS[0].Samples, in.DNS[0].FailPct = 1, f64(100) },
			code: "ok", severity: "ok", not: []string{"adguard (192.168.1.5:53) and"}},
		{name: "public resolver failing only", mod: func(in *netInput) { in.DNS[1].FailAlert = true }, code: "dns_public_failing", severity: "warn", where: "dns",
			want: []string{"quad9", "adguard (192.168.1.5:53) still answers"}},
		{name: "slow resolver", mod: func(in *netInput) { in.DNS[0].SlowAlert = true }, code: "dns_slow", severity: "warn", where: "dns",
			segs: map[string]string{"dns": "warn"}},
		{name: "loss at the ISP across targets", mod: func(in *netInput) {
			for i := range in.Targets {
				in.Targets[i].Status = "degraded"
				in.Targets[i].Diag = diagnosisJSON{Severity: "warn", Code: "path_isp", Where: where("isp"), Hop: &ispHop, Headline: "Loss or delay starts at hop 3 (203.0.113.1), at your ISP", Detail: "x"}
			}
		}, code: "isp_problem", severity: "warn", where: "isp", segs: map[string]string{"isp": "warn", "local": "ok"},
			want: []string{"Your ISP is losing packets or adding delay (hop 3)", "Affected: cloudflare and google"}},
		{name: "loss inside the home network wins over a server error", mod: func(in *netInput) {
			hop1 := 1
			in.Targets[0].Status, in.Targets[1].Status = "alerting", "degraded"
			in.Targets[0].Diag = diagnosisJSON{Severity: "crit", Code: "http_failure", Where: where("server"), Headline: "The web server answers with an error (HTTP 503)"}
			in.Targets[1].Diag = diagnosisJSON{Severity: "warn", Code: "path_local", Where: where("local"), Hop: &hop1, Headline: "Loss or delay starts at hop 1, inside your network", Detail: "Check your router."}
		}, code: "local_problem", severity: "crit", where: "local", segs: map[string]string{"local": "warn", "destinations": "crit"},
			want: []string{"Your home network", "(hop 1)", "Affected: google and cloudflare"}},
		{name: "a single destination", mod: func(in *netInput) {
			in.Targets[1].Status = "alerting"
			in.Targets[1].Diag = diagnosisJSON{Severity: "crit", Code: "destination", Where: where("destination"), Headline: "The destination itself is losing packets"}
		}, code: "target_problem", severity: "crit", where: "destination", segs: map[string]string{"destinations": "crit", "isp": "ok"},
			want: []string{"Only google has a problem", "own network and ISP look fine"}},
		{name: "no results yet", mod: func(in *netInput) {
			for i := range in.Targets {
				in.Targets[i].Status = "nodata"
				in.Targets[i].Diag = diagnosisJSON{Severity: "info", Code: "nodata", Headline: "No recent results"}
			}
			in.DNS = nil
		}, code: "nodata", severity: "info"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := healthyNet()
			c.mod(&in)
			v := networkVerdict(in)
			text := v.Headline + " | " + v.Detail
			if v.Code != c.code || v.Severity != c.severity {
				t.Errorf("code/severity %s/%s, want %s/%s (%s)", v.Code, v.Severity, c.code, c.severity, text)
			}
			if got := deref(v.Where); got != c.where {
				t.Errorf("where %q, want %q", got, c.where)
			}
			if len(v.Segments) != 5 {
				t.Errorf("segments %+v", v.Segments)
			}
			for k, want := range c.segs {
				if got := segState(v, k); got != want {
					t.Errorf("segment %s = %s, want %s (%+v)", k, got, want, v.Segments)
				}
			}
			for _, w := range c.want {
				if !strings.Contains(text, w) {
					t.Errorf("missing %q in %q", w, text)
				}
			}
			for _, w := range c.not {
				if strings.Contains(text, w) {
					t.Errorf("unexpected %q in %q", w, text)
				}
			}
			if v.Affected == nil || v.DNS == nil {
				t.Error("affected/dns must be arrays, not null")
			}
		})
	}
}

func TestLocalResolver(t *testing.T) {
	for s, want := range map[string]bool{"192.168.1.5:53": true, "10.0.0.53:5353": true, "[fd00::53]:53": true, "127.0.0.1:53": true,
		"9.9.9.9:53": false, "1.1.1.1": false, "dns.example:53": false} {
		if got := localResolver(s); got != want {
			t.Errorf("%s: %v, want %v", s, got, want)
		}
	}
}

func TestDNSErrKind(t *testing.T) {
	for e, want := range map[string]string{"": "", "rcode SERVFAIL": "upstream", "rcode NXDOMAIN": "rcode", "rcode REFUSED": "rcode",
		"read udp 1.2.3.4:5->6.7.8.9:53: i/o timeout": "silent", "dial udp: connection refused": "silent"} {
		if got := dnsErrKind(e); got != want {
			t.Errorf("%q: %q, want %q", e, got, want)
		}
	}
}

// A hop at the ISP gets its own location in the per-target diagnosis, and a failing local
// resolver is named when a target's host name does not resolve.
func TestDiagnoseISPAndDNS(t *testing.T) {
	in := base()
	in.Status = "degraded"
	in.Degraded, in.Start = true, hopRef{TTL: 2, Address: "203.0.113.1", ISP: true}
	d := diagnose(in)
	if d.Code != "path_isp" || deref(d.Where) != "isp" || !strings.Contains(d.Headline, "at your ISP") {
		t.Errorf("isp path: %+v", d)
	}
	in = base()
	in.Status, in.E2ELoss = "degraded", f64(20)
	in.LossFrom = hopRef{TTL: 2, Address: "100.64.0.1", ISP: true}
	if d := diagnose(in); deref(d.Where) != "isp" || !strings.Contains(d.Detail, "at your ISP") {
		t.Errorf("isp loss: %+v", d)
	}
	in = base()
	in.Status, in.HTTPError, in.DNSDown = "alerting", "lookup example.com: no such host", "adguard (192.168.1.5:53)"
	in.Alerts = []store.Alert{{Rule: "http", RuleType: "http_failure"}}
	if d := diagnose(in); deref(d.Where) != "dns" || !strings.Contains(d.Headline, "your DNS resolver is failing") || !strings.Contains(d.Detail, "adguard") {
		t.Errorf("dns down: %+v", d)
	}
}

// isISP: the first public hop, CGNAT addresses and nothing else without AS data.
func TestIsISP(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	dc := &diagContext{paths: map[int64]store.PathRow{1: {ID: 7, DestTTL: 6}}, hops: map[int64][]store.PathHopRow{1: {
		{TTL: 1, Address: "192.168.1.1"}, {TTL: 2, Address: "100.64.0.1"}, {TTL: 3, Address: "203.0.113.1"},
		{TTL: 4, Address: "198.51.100.1"}, {TTL: 6, Address: "192.0.2.10"},
	}}}
	if ttl, addr, ok := dc.firstPublic(1); !ok || ttl != 3 || addr != "203.0.113.1" {
		t.Fatalf("first public: %d %s %v", ttl, addr, ok)
	}
	for ttl, want := range map[int]bool{1: false, 2: true, 3: true, 4: false, 6: false} {
		h := f.srv.hopRefOf(dc, 1, ttl)
		if h.ISP != want {
			t.Errorf("hop %d (%s): ISP %v, want %v", ttl, h.Address, h.ISP, want)
		}
	}
}

// The endpoint answers with a verdict and the five segments.
func TestNetworkAPI(t *testing.T) {
	f := newFixture(t, fixtureOpts{startTargets: true})
	var v networkJSON
	if resp := f.getJSON("/api/network", &v); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if v.Headline == "" || v.Code == "" || len(v.Segments) != 5 || v.Segments[0].Key != "local" || v.Segments[4].Key != "destinations" {
		t.Errorf("verdict %+v", v)
	}
}

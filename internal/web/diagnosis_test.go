package web

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

func f64(v float64) *float64 { return &v }

// base is a healthy, ICMP-traced target with an HTTP probe.
func base() diagInput {
	return diagInput{Status: "ok", ICMPAvailable: true, HasICMP: true, HasEndpoint: true, E2ELoss: f64(0), E2ESource: "icmp",
		LossLimit: 5, HTTPSuccess: f64(100), HTTPLimit: 95, DestTTL: 8}
}

func TestDiagnose(t *testing.T) {
	isp := hopRef{TTL: 3, Address: "203.0.113.1", Hostname: "core1.isp.example", ASN: 64500, ASName: "Example ISP"}
	cases := []struct {
		name     string
		mod      func(*diagInput)
		code     string
		severity string
		where    string // "" = null
		hop      int    // 0 = null
		want     []string
		not      []string
	}{
		{name: "healthy", mod: func(in *diagInput) {}, code: "ok", severity: "ok",
			want: []string{"No problems detected", "destination answers normally"}},
		{name: "rate-limited hops are explained, not alarming", mod: func(in *diagInput) { in.RateLimited = []int{4, 6} }, code: "ok_rate_limited", severity: "ok", hop: 4,
			want: []string{"Hops 4 and 6 drop some pings", "ICMP rate-limiting", "real traffic is not affected"}},
		{name: "learning", mod: func(in *diagInput) { in.Status = "learning"; in.Learning = true }, code: "learning", severity: "ok",
			want: []string{"learning baseline"}},
		{name: "no ping, TCP end-to-end", mod: func(in *diagInput) { in.ICMPUnresponsive = true; in.E2ESource = "tcp" }, code: "ok", severity: "ok",
			want: []string{"does not answer ping", "TCP probe"}},
		{name: "no ping, last hop only", mod: func(in *diagInput) { in.ICMPUnresponsive = true; in.E2ESource = "last_hop" }, code: "ok", severity: "ok",
			want: []string{"Add a TCP probe"}},
		{name: "paused", mod: func(in *diagInput) { in.Paused = true; in.Status = "nodata" }, code: "paused", severity: "info"},
		{name: "removed", mod: func(in *diagInput) { in.Removed = true; in.Status = "nodata" }, code: "removed", severity: "info"},
		{name: "no data, nothing can measure it", mod: func(in *diagInput) { in.Status = "nodata"; in.ICMPAvailable = false; in.HasEndpoint = false },
			code: "nodata", severity: "info", want: []string{"NET_RAW", "nothing measures it"}},
		{name: "local outage beats everything else", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.Local = alert.LocalState{Down: true, Reason: "gateway"}
			in.Degraded, in.Start = true, isp
		}, code: "local_outage", severity: "crit", where: "local", want: []string{"gateway stopped answering", "held back"}},
		{name: "every target failing", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.Local = alert.LocalState{Down: true, Reason: "all_targets"}
		},
			code: "local_outage", severity: "crit", where: "local", want: []string{"your own connection"}},
		{name: "degradation at the gateway", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.Degraded, in.Start = true, hopRef{TTL: 1, Address: "192.168.1.1", Hostname: "router.lan"}
		}, code: "path_local", severity: "warn", where: "local", hop: 1, want: []string{"hop 1 (router.lan, 192.168.1.1), inside your network"}},
		{name: "degradation on a private hop beyond the gateway", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.Degraded, in.Start = true, hopRef{TTL: 2, Address: "10.0.0.1"}
		}, code: "path_local", severity: "warn", where: "local", hop: 2},
		{name: "degradation shared with other targets", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.Degraded, in.Start, in.SharedThrough, in.SharedAffected = true, isp, 4, 3
		}, code: "path_shared", severity: "crit", where: "shared", hop: 3,
			want: []string{"hop 3 (core1.isp.example, 203.0.113.1)", "3 of the 4 other targets through this hop are affected too", "AS64500 (Example ISP)"}},
		{name: "one other target affected", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.Degraded, in.Start, in.SharedThrough, in.SharedAffected = true, isp, 1, 1
		}, code: "path_shared", where: "shared", severity: "warn", hop: 3, want: []string{"The other target through this hop is affected too"}},
		{name: "degradation only on this route", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.Degraded, in.Start = true, hopRef{TTL: 5, Address: "198.51.100.7"}
		}, code: "path", severity: "warn", where: "path", hop: 5, want: []string{"No other target goes through this hop", "that hop's network"}},
		{name: "shared hop but others fine", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.Degraded, in.Start, in.SharedThrough = true, hopRef{TTL: 5, Address: "198.51.100.7"}, 2
		}, code: "path", where: "path", severity: "warn", hop: 5, want: []string{"Other targets that go through this hop are fine"}},
		{name: "CGNAT hop names the ISP", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.Degraded, in.Start = true, hopRef{TTL: 2, Address: "100.72.0.1"}
		}, code: "path", where: "path", severity: "warn", hop: 2, want: []string{"your ISP"}},
		{name: "destination only", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.Degraded, in.Start = true, hopRef{TTL: 8, Address: "93.184.215.14"}
		}, code: "destination", severity: "warn", where: "destination", hop: 8, want: []string{"destination itself"}},
		{name: "loss not yet localized", mod: func(in *diagInput) { in.Status = "degraded"; in.E2ELoss = f64(12.5) }, code: "e2e_loss", severity: "warn",
			want: []string{"12.5% packet loss to the destination"}},
		{name: "TCP loss", mod: func(in *diagInput) { in.Status = "degraded"; in.E2ELoss = f64(20); in.E2ESource = "tcp" }, code: "e2e_loss", severity: "warn",
			want: []string{"20% of TCP connections"}},
		{name: "loss from a shared hop while TCP hides it", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.E2ELoss, in.LossFrom, in.SharedThrough, in.SharedAffected, in.ProbesOK = f64(24.3), isp, 1, 1, true
		}, code: "e2e_loss", severity: "crit", where: "shared", hop: 3,
			want: []string{"24.3% packet loss to the destination, starting at hop 3", "The other target through this hop is losing packets too", "AS64500", "TCP resends lost packets"}},
		{name: "loss from a hop on this route only", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.E2ELoss, in.LossFrom, in.SharedThrough = f64(8), hopRef{TTL: 5, Address: "198.51.100.7"}, 2
		}, code: "e2e_loss", severity: "warn", where: "path", hop: 5, want: []string{"Other targets through this hop are fine"}, not: []string{"TCP resends"}},
		{name: "loss from the home router", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.E2ELoss, in.LossFrom = f64(8), hopRef{TTL: 1, Address: "192.168.1.1"}
		}, code: "e2e_loss", severity: "warn", where: "local", hop: 1, want: []string{"inside your network"}},
		{name: "only the destination drops pings, probes fine", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.E2ELoss, in.LossFrom, in.ProbesOK = f64(30), hopRef{TTL: 8, Address: "93.184.215.14"}, true
		}, code: "destination_loss", severity: "warn", where: "destination", hop: 8, want: []string{"30% of pings to the destination are lost", "limits its ping replies"}},
		{name: "last-hop loss never counts as end-to-end", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.E2ELoss, in.E2ESource, in.HTTPSuccess = f64(40), "last_hop", f64(50)
			in.HTTPError = "unexpected status 503"
		}, code: "http_failure", severity: "warn", where: "server", want: []string{"HTTP 503"}, not: []string{"packet loss"}},
		{name: "HTTP status error", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.HTTPSuccess, in.HTTPError = f64(10), "unexpected status 502"
			in.Alerts = []store.Alert{{Rule: "http-down", RuleType: "http_failure", Message: "3 consecutive failures"}}
		}, code: "http_failure", severity: "crit", where: "server", want: []string{"(HTTP 502)", "network path works", "10% of HTTP requests", `Last error: "unexpected status 502"`}},
		{name: "HTTP timeout with a clean path blames the server", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.HTTPSuccess, in.HTTPError = f64(60), "timeout"
		}, code: "http_failure", severity: "warn", where: "server", want: []string{"but the network path is clean"}},
		{name: "HTTP timeout over HTTP-only end-to-end is not localized", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.E2ESource, in.HTTPSuccess, in.HTTPError = "http", f64(60), "timeout"
		}, code: "http_failure", severity: "warn", want: []string{"HTTP requests time out"}, not: []string{"clean"}},
		{name: "HTTP refused", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.HTTPSuccess, in.HTTPError = f64(0), "dial: connect: connection refused"
		},
			code: "http_failure", severity: "warn", where: "server", want: []string{"refuses connections"}},
		{name: "HTTP TLS", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.HTTPSuccess, in.HTTPError = f64(0), "tls: failed to verify certificate: x509: certificate has expired"
		}, code: "http_failure", severity: "warn", where: "server", want: []string{"TLS handshake fails", "x509"}},
		{name: "HTTP DNS", mod: func(in *diagInput) {
			in.Status = "degraded"
			in.HTTPSuccess, in.HTTPError = f64(0), "lookup example.invalid: no such host"
		},
			code: "http_failure", severity: "warn", where: "dns"},
		{name: "HTTP failure alert still firing after the errors stopped", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.Alerts = []store.Alert{{Rule: "http-down", RuleType: "http_failure", Message: "HTTP failing: 3 consecutive failures"}}
		}, code: "http_failure", severity: "crit", want: []string{"have been failing", "3 consecutive failures"}},
		{name: "TCP timeout while ping works", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.HTTPSuccess = nil
			in.TCPError = "timeout"
			in.Alerts = []store.Alert{{Rule: "tcp-down", RuleType: "tcp_failure"}}
		}, code: "tcp_failure", severity: "crit", where: "server", want: []string{"firewall"}},
		{name: "slow server", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.Alerts = []store.Alert{{Rule: "http-slow", RuleType: "http_latency", Message: "HTTP total 412ms vs baseline 85ms"}}
			in.Slow = &slowPhase{Phase: "ttfb", Before: 60, Now: 380, ConnBefore: 12, ConnNow: 13, haveConn: true}
		}, code: "http_slow_server", severity: "crit", where: "server",
			want: []string{"slow to respond", "Time to first byte rose from 60 ms to 380 ms", "TCP connect stayed at about 13 ms", "not the cause"}},
		{name: "slow server and network", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.Alerts = []store.Alert{{Rule: "http-slow", RuleType: "http_latency"}}
			in.Slow = &slowPhase{Phase: "ttfb", Before: 60, Now: 380, ConnBefore: 12, ConnNow: 150, haveConn: true}
		}, code: "http_slow_server", severity: "crit", where: "server", want: []string{"TCP connect also rose from 12 ms to 150 ms"}},
		{name: "slow network", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.Alerts = []store.Alert{{Rule: "http-slow", RuleType: "http_latency"}}
			in.Slow = &slowPhase{Phase: "connect", Before: 12, Now: 140}
		}, code: "http_slow_network", severity: "crit", where: "path", want: []string{"TCP connect time rose from 12 ms to 140 ms"}},
		{name: "slow without attribution falls back to the alert", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.Alerts = []store.Alert{{Rule: "http-slow", RuleType: "http_latency", Message: "HTTP total 412ms vs baseline 85ms"}}
		}, code: "http_slow", severity: "crit", want: []string{"slower than usual", "412ms"}},
		{name: "certificate", mod: func(in *diagInput) {
			in.Status = "alerting"
			in.Alerts = []store.Alert{{Rule: "cert", RuleType: "cert_expiry", Message: "certificate expires in 5 days"}}
		}, code: "cert_expiry", severity: "crit", where: "server"},
		{name: "silenced problem is still explained", mod: func(in *diagInput) {
			in.Status = "silenced"
			in.Degraded, in.Start = true, hopRef{TTL: 5, Address: "198.51.100.7"}
		}, code: "path", severity: "warn", where: "path", hop: 5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base()
			c.mod(&in)
			d := diagnose(in)
			text := d.Headline + " | " + d.Detail
			if d.Code != c.code || d.Severity != c.severity {
				t.Errorf("code/severity %s/%s, want %s/%s (%s)", d.Code, d.Severity, c.code, c.severity, text)
			}
			if got := deref(d.Where); got != c.where {
				t.Errorf("where %q, want %q", got, c.where)
			}
			if got := 0; d.Hop != nil {
				got = *d.Hop
				if got != c.hop {
					t.Errorf("hop %d, want %d", got, c.hop)
				}
			} else if c.hop != 0 {
				t.Errorf("hop null, want %d", c.hop)
			}
			if d.Headline == "" {
				t.Error("empty headline")
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
		})
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestOthersThrough(t *testing.T) {
	for _, c := range []struct {
		affected, through int
		want              string
	}{
		{1, 1, "The other target through this hop is hit"},
		{2, 2, "Both other targets through this hop are hit"},
		{3, 3, "All 3 other targets through this hop are hit"},
		{1, 3, "1 of the 3 other targets through this hop is hit"},
		{2, 3, "2 of the 3 other targets through this hop are hit"},
	} {
		if got := othersThrough(c.affected, c.through, "hit"); got != c.want {
			t.Errorf("%d/%d: %q, want %q", c.affected, c.through, got, c.want)
		}
	}
}

func TestLossOnset(t *testing.T) {
	rl, dg, ok, nr := "rate_limited", "degraded", "ok", "no_reply"
	for _, c := range []struct {
		classes map[int]string
		dest    int
		want    int
	}{
		{map[int]string{1: ok, 2: rl, 3: rl}, 3, 2},
		{map[int]string{1: ok, 2: rl, 3: nr, 4: dg}, 4, 2}, // a silent hop does not break the chain
		{map[int]string{1: rl, 2: ok, 3: rl}, 3, 3},        // a clean hop in between: loss starts after it
		{map[int]string{1: ok, 2: rl, 3: ok}, 3, 0},        // destination clean: rate-limiting only
		{map[int]string{1: rl, 2: rl}, 2, 1},
		{map[int]string{1: rl}, 0, 0}, // unknown destination
	} {
		if got := lossOnset(c.classes, c.dest); got != c.want {
			t.Errorf("lossOnset(%v, %d) = %d, want %d", c.classes, c.dest, got, c.want)
		}
	}
}

func TestProbeErrKind(t *testing.T) {
	for e, want := range map[string]string{
		"unexpected status 503":                         "status",
		"lookup x.invalid on 1.1.1.1:53: no such host":  "dns",
		"dial: connect: connection refused":             "refused",
		"tls: handshake failure":                        "tls",
		"x509: certificate signed by unknown authority": "tls",
		"timeout":                         "timeout",
		"timeout (failed 3 attempts)":     "timeout",
		"dial: connect: no route to host": "unreachable",
		"read: connection reset by peer":  "reset",
		"unexpected EOF":                  "reset",
		"something odd":                   "other",
	} {
		if got := probeErrKind(e); got != want {
			t.Errorf("%q: %s, want %s", e, got, want)
		}
	}
}

// Two targets on the same path: the diagnosis of one knows the other goes through the same hop,
// and whether it is degraded too.
func TestDiagnosisComparesPaths(t *testing.T) {
	f := newFixture(t, fixtureOpts{startTargets: true})
	resp, b := f.postJSON("/api/targets", map[string]any{"name": "beta", "host": "127.0.0.1", "icmp_interval_ms": 500})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	rows, err := f.st.Targets(false)
	if err != nil || len(rows) != 2 {
		t.Fatalf("targets %v %v", rows, err)
	}
	f.waitFor("both paths", func() bool {
		dc := f.srv.newDiagContext(rows)
		return len(dc.through["10.0.0.2"]) == 2
	})
	dc := f.srv.newDiagContext(rows)
	alpha, beta := rows[0], rows[1]
	if alpha.Name != "alpha" {
		alpha, beta = beta, alpha
	}
	if addr, ok := dc.hopAt(alpha.ID, 2); !ok || addr != "10.0.0.2" {
		t.Fatalf("hop 2 of alpha: %q %v", addr, ok)
	}
	now := f.srv.now()
	dc.degraded[alpha.ID] = analyze.Analysis{At: now, Real: true, StartTTL: 2}
	v := f.srv.viewOf(alpha)
	tj := targetJSON{Status: "degraded", Summary: summaryJSON{E2ELoss: f64(30)}}
	in := f.srv.diagInputOf(context.Background(), v, tj, "icmp", dc)
	if !in.Degraded || in.Start.Address != "10.0.0.2" || in.SharedThrough != 1 || in.SharedAffected != 0 || in.DestTTL != 3 {
		t.Errorf("alone: %+v", in)
	}
	dc.degraded[beta.ID] = analyze.Analysis{At: now, Real: true, StartTTL: 2}
	in = f.srv.diagInputOf(context.Background(), v, tj, "icmp", dc)
	if in.SharedThrough != 1 || in.SharedAffected != 1 {
		t.Errorf("both degraded: through %d affected %d", in.SharedThrough, in.SharedAffected)
	}
	if d := diagnose(in); d.Code != "path_local" || d.Hop == nil || *d.Hop != 2 { // 10.0.0.2 is a private address
		t.Errorf("diagnosis %+v", d)
	}

	// the live API carries a diagnosis for every target
	var list []map[string]any
	f.getJSON("/api/targets", &list)
	for _, x := range list {
		d, _ := x["diagnosis"].(map[string]any)
		if d == nil || d["headline"] == "" || d["severity"] == nil || d["code"] == nil {
			t.Errorf("%v: diagnosis %v", x["name"], x["diagnosis"])
		}
	}
}

// slowPhaseOf compares the phases of the last 5 minutes with the hours before the alert.
func TestSlowPhaseOf(t *testing.T) {
	t0 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	now := t0.Add(2 * time.Hour)
	st, err := store.Open(filepath.Join(t.TempDir(), "slow.db"), store.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), NoBackground: true, FlushInterval: 20 * time.Millisecond, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tr, err := st.SyncConfigTarget("web", "web.example")
	if err != nil {
		t.Fatal(err)
	}
	pid, err := st.EnsureProbe(tr.ID, "http", "http|web", "GET https://web.example/")
	if err != nil {
		t.Fatal(err)
	}
	start := t0.Add(90 * time.Minute)
	for ts := t0; ts.Before(now); ts = ts.Add(30 * time.Second) {
		ttfb := 50 * time.Millisecond
		if !ts.Before(start) {
			ttfb = 400 * time.Millisecond
		}
		smp := store.HTTPSample{ProbeID: pid, TS: ts, Status: 200, DNS: time.Millisecond, Connect: 10 * time.Millisecond, TLS: 20 * time.Millisecond, TTFB: ttfb, Transfer: 5 * time.Millisecond}
		smp.Total = smp.DNS + smp.Connect + smp.TLS + smp.TTFB + smp.Transfer
		st.RecordHTTP(smp)
	}
	if err := st.Sync(); err != nil {
		t.Fatal(err)
	}
	st.FlushDue(now)
	if err := st.Sync(); err != nil {
		t.Fatal(err)
	}
	srv := New(Deps{Store: st, Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	row, err := st.Target(tr.ID)
	if err != nil {
		t.Fatal(err)
	}
	v := srv.viewOf(row)
	a := &store.Alert{Rule: "http-slow", RuleType: "http_latency", StartedAt: start, DetailsJSON: fmt.Sprintf(`{"probe_id":%d}`, pid)}
	p := srv.slowPhaseOf(context.Background(), v, a, now)
	if p == nil || p.Phase != "ttfb" || math.Abs(p.Before-50) > 1 || math.Abs(p.Now-400) > 1 || !p.haveConn || math.Abs(p.ConnNow-10) > 1 {
		t.Fatalf("slow phase %+v", p)
	}
	if d := diagnose(diagInput{Status: "alerting", Alerts: []store.Alert{*a}, Slow: p}); d.Code != "http_slow_server" || !strings.Contains(d.Detail, "from 50 ms to 400 ms") {
		t.Errorf("diagnosis %+v", d)
	}
	// before the slowdown nothing grew: no attribution
	if p := srv.slowPhaseOf(context.Background(), v, &store.Alert{StartedAt: t0.Add(60 * time.Minute)}, t0.Add(80*time.Minute)); p != nil {
		t.Errorf("no growth, got %+v", p)
	}
}

package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
	"github.com/i-press-buttons/pathwatch/internal/settings"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// fakeProber replays a scripted path: 10.0.0.1, 10.0.0.2, then the destination at TTL 3.
type fakeProber struct {
	mu   sync.Mutex
	path []string
}

func (f *fakeProber) Mode() string { return probe.ModeRaw }
func (f *fakeProber) Close() error { return nil }
func (f *fakeProber) Probe(ctx context.Context, req probe.Request) probe.Result {
	f.mu.Lock()
	path := f.path
	f.mu.Unlock()
	n := len(path)
	if req.TTL < n {
		return probe.Result{Status: probe.StatusTTLExceeded, Addr: netip.MustParseAddr(path[req.TTL-1]), RTT: time.Duration(req.TTL) * time.Millisecond}
	}
	return probe.Result{Status: probe.StatusReply, Addr: netip.MustParseAddr(path[n-1]), RTT: time.Duration(n) * time.Millisecond}
}

type staticResolver map[string][]string

func (r staticResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	v, ok := r[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, a := range v {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

type fixture struct {
	t      *testing.T
	st     *store.Store
	sched  *scheduler.Scheduler
	mgr    *settings.Manager
	an     *analyze.Analyzer
	srv    *Server
	ts     *httptest.Server
	client *http.Client
	user   string
	pass   string
	httpd  *httptest.Server
}

type fixtureOpts struct {
	auth         bool
	startTargets bool
}

func newFixture(t *testing.T, o fixtureOpts) *fixture {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"), store.Options{Logger: log, FlushInterval: 20 * time.Millisecond, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	hub := NewHub()
	fp := &fakeProber{path: []string{"10.0.0.1", "10.0.0.2", "127.0.0.1"}}
	sched := scheduler.New(scheduler.Options{Store: st, Prober: fp, Observer: hub, Logger: log, Stagger: time.Millisecond, Version: "test"})
	an := analyze.New(st, sched, nil, log)
	an.Start()
	sched.Start(context.Background())

	httpd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cfg, err := config.Parse(nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.Alerts.MaintenanceWindows = []config.MaintenanceWindow{{Name: "always", Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}, Start: "00:00", End: "00:00", Timezone: "UTC"}}
	f := &fixture{t: t, st: st, sched: sched, an: an, httpd: httpd, client: &http.Client{Timeout: 10 * time.Second}}
	auth := config.Auth{}
	if o.auth {
		auth = config.Auth{Enabled: true, User: "admin", Password: "s3cret"}
		f.user, f.pass = "admin", "s3cret"
	}
	static := fstest.MapFS{
		"index.html": {Data: []byte("<!doctype html><title>ui</title>app shell")},
		"app.js":     {Data: []byte("console.log(1)")},
	}
	mgr, err := settings.New(st, sched, cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	f.mgr = mgr
	f.srv = New(Deps{Store: st, Sched: sched, Analyzer: an, Hub: hub, Config: cfg, Settings: mgr, Auth: auth, Version: "9.9.9", Logger: log, Static: static,
		Resolver: staticResolver{"pathwatch.test": {"192.0.2.10", "2001:db8::10"}}})
	f.ts = httptest.NewServer(f.srv.Handler())
	t.Cleanup(func() {
		f.ts.Close()
		hub.Close()
		sched.Close()
		st.Close()
		httpd.Close()
		ln.Close()
	})
	if o.startTargets {
		tcpPort := ln.Addr().(*net.TCPAddr).Port
		tg := config.Target{Name: "alpha", Host: "127.0.0.1", Source: config.SourceConfig,
			ICMP: &config.ICMPSettings{Interval: 20 * time.Millisecond, Timeout: 20 * time.Millisecond, Rediscovery: time.Hour, MaxHops: 10},
			Probes: []config.Probe{
				{Type: config.ProbeHTTP, URL: httpd.URL + "/", Method: "GET", Interval: 40 * time.Millisecond, Timeout: time.Second, MaxBody: 1 << 20, PinIP: true},
				{Type: config.ProbeTCP, Port: tcpPort, Interval: 40 * time.Millisecond, Timeout: time.Second, PinIP: true},
			}}
		dnsAddr, stop := fakeDNS(t)
		t.Cleanup(stop)
		dp := config.DNSProbe{Name: "resolver", Server: dnsAddr, Query: "example.com", Record: "A", Interval: 50 * time.Millisecond, Timeout: time.Second}
		if err := sched.SyncConfig([]config.Target{tg}, []config.DNSProbe{dp}); err != nil {
			t.Fatal(err)
		}
		f.waitFor("data", func() bool {
			var ts []map[string]any
			f.getJSON("/api/targets", &ts)
			if len(ts) == 0 {
				return false
			}
			s := ts[0]["summary"].(map[string]any)
			return s["e2e_rtt_ms"] != nil && s["http_total_ms"] != nil
		})
		time.Sleep(300 * time.Millisecond)
	}
	return f
}

func fakeDNS(t *testing.T) (string, func()) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := append([]byte{}, buf[:n]...)
			resp[2], resp[3] = 0x81, 0x80
			resp[7] = 1
			resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
			pc.WriteTo(resp, from)
		}
	}()
	return pc.LocalAddr().String(), func() { pc.Close() }
}

func (f *fixture) waitFor(what string, cond func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatalf("timeout waiting for %s", what)
}

func (f *fixture) do(method, path, ct string, body any) (*http.Response, []byte) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		default:
			j, _ := json.Marshal(b)
			rd = bytes.NewReader(j)
		}
	}
	req, _ := http.NewRequest(method, f.ts.URL+path, rd)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if f.user != "" {
		req.SetBasicAuth(f.user, f.pass)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func (f *fixture) getJSON(path string, v any) *http.Response {
	f.t.Helper()
	resp, b := f.do("GET", path, "", nil)
	if resp.StatusCode == 200 {
		if err := json.Unmarshal(b, v); err != nil {
			f.t.Fatalf("GET %s: bad json %v: %s", path, err, b)
		}
	}
	return resp
}

func (f *fixture) postJSON(path string, body any) (*http.Response, []byte) {
	return f.do("POST", path, "application/json", body)
}

func errMsg(b []byte) string {
	var e map[string]string
	_ = json.Unmarshal(b, &e)
	return e["error"]
}

func TestAuthAndHealthz(t *testing.T) {
	f := newFixture(t, fixtureOpts{auth: true})
	// healthz needs no credentials
	resp, err := http.Get(f.ts.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v %v", resp, err)
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(b)) != `{"ok":true}` {
		t.Errorf("healthz body %s", b)
	}
	for _, path := range []string{"/api/status", "/api/targets", "/", "/api/stream"} {
		resp, err := http.Get(f.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s without credentials: %d", path, resp.StatusCode)
		}
		if path != "/" {
			b, _ := io.ReadAll(resp.Body)
			if errMsg(b) == "" {
				t.Errorf("%s: 401 without JSON error body: %s", path, b)
			}
		}
	}
	req, _ := http.NewRequest("GET", f.ts.URL+"/api/status", nil)
	req.SetBasicAuth("admin", "wrong")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Error("wrong password accepted")
	}
	req.SetBasicAuth("root", "s3cret")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Error("wrong user accepted")
	}
	var st map[string]any
	if resp := f.getJSON("/api/status", &st); resp.StatusCode != 200 {
		t.Fatalf("status with credentials: %d", resp.StatusCode)
	}
	if st["auth_enabled"] != true {
		t.Error("auth_enabled")
	}
}

func TestStatusShape(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	var st map[string]any
	f.getJSON("/api/status", &st)
	for _, k := range []string{"version", "now", "uptime_s", "icmp_mode", "local_status", "active_alerts", "auth_enabled", "read_only_config"} {
		if _, ok := st[k]; !ok {
			t.Errorf("status missing %q", k)
		}
	}
	if st["version"] != "9.9.9" || st["icmp_mode"] != "raw" || st["local_status"] != "unknown" || st["auth_enabled"] != false || st["read_only_config"] != false {
		t.Errorf("status: %v", st)
	}
	if n, _ := st["now"].(float64); n < 1.6e12 {
		t.Errorf("now should be Unix ms: %v", st["now"])
	}
}

func TestSPAFallbackAndErrors(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	resp, b := f.do("GET", "/", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "app shell") {
		t.Errorf("/: %d %s", resp.StatusCode, b)
	}
	resp, b = f.do("GET", "/targets/3/anything", "", nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "app shell") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("SPA route: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	resp, b = f.do("GET", "/app.js", "", nil)
	if resp.StatusCode != 200 || string(b) != "console.log(1)" {
		t.Errorf("asset: %d %s", resp.StatusCode, b)
	}
	if resp, _ = f.do("GET", "/missing.js", "", nil); resp.StatusCode != 404 {
		t.Errorf("missing asset: %d", resp.StatusCode)
	}
	resp, b = f.do("GET", "/api/nonexistent", "", nil)
	if resp.StatusCode != 404 || errMsg(b) == "" {
		t.Errorf("unknown api: %d %s", resp.StatusCode, b)
	}
	resp, b = f.do("PUT", "/api/status", "", nil)
	if resp.StatusCode != 405 || errMsg(b) == "" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Errorf("405: %d %s", resp.StatusCode, b)
	}
	resp, b = f.do("GET", "/api/targets/abc/hops", "", nil)
	if resp.StatusCode != 400 || errMsg(b) == "" {
		t.Errorf("bad id: %d %s", resp.StatusCode, b)
	}
	resp, b = f.do("GET", "/api/targets/9999/hops", "", nil)
	if resp.StatusCode != 404 || errMsg(b) == "" {
		t.Errorf("unknown target: %d %s", resp.StatusCode, b)
	}
}

func TestCreateDeletePauseTargets(t *testing.T) {
	f := newFixture(t, fixtureOpts{startTargets: true})

	// non-JSON content type is refused
	resp, b := f.do("POST", "/api/targets", "text/plain", `{"name":"x","host":"127.0.0.1"}`)
	if resp.StatusCode != 415 {
		t.Errorf("content type: %d %s", resp.StatusCode, b)
	}
	resp, b = f.do("POST", "/api/targets", "application/x-www-form-urlencoded", `name=x&host=y`)
	if resp.StatusCode != 415 {
		t.Errorf("form post: %d", resp.StatusCode)
	}
	// validation
	for _, body := range []any{`{"name":"","host":"127.0.0.1"}`, `{"name":"a","host":"not a host"}`, `{"name":"a","host":"x.com","http_url":"ftp://x"}`, `{"name":"a","host":"x.com","tcp_port":99999}`, `not json`} {
		if resp, b = f.postJSON("/api/targets", body); resp.StatusCode != 400 || errMsg(b) == "" {
			t.Errorf("validation %v: %d %s", body, resp.StatusCode, b)
		}
	}
	// duplicate of the config target (case-insensitive)
	if resp, b = f.postJSON("/api/targets", map[string]any{"name": "ALPHA", "host": "127.0.0.1"}); resp.StatusCode != 409 {
		t.Errorf("duplicate: %d %s", resp.StatusCode, b)
	}
	// cross-origin POST is refused even with a JSON body
	req, _ := http.NewRequest("POST", f.ts.URL+"/api/targets", strings.NewReader(`{"name":"evil","host":"127.0.0.1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	if r2, _ := f.client.Do(req); r2.StatusCode != 403 {
		t.Errorf("cross-origin: %d", r2.StatusCode)
	}

	resp, b = f.postJSON("/api/targets", map[string]any{"name": "my-isp", "host": "127.0.0.1", "icmp_interval_ms": 500, "http_url": f.httpd.URL + "/", "tcp_port": 8080})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	var created map[string]any
	json.Unmarshal(b, &created)
	checkTargetShape(t, created)
	if created["source"] != "ui" || created["name"] != "my-isp" || created["icmp_interval_ms"] != float64(500) {
		t.Errorf("created: %v", created)
	}
	if probes := created["probes"].([]any); len(probes) != 3 {
		t.Errorf("probes: %v", probes)
	}
	id := int64(created["id"].(float64))

	var list []map[string]any
	f.getJSON("/api/targets", &list)
	if len(list) != 2 {
		t.Fatalf("targets: %d", len(list))
	}
	// the new target starts being probed without a restart
	f.waitFor("ui target rounds", func() bool {
		var ts []map[string]any
		f.getJSON("/api/targets", &ts)
		for _, x := range ts {
			if x["name"] == "my-isp" && x["last_round"] != nil {
				return true
			}
		}
		return false
	})
	// pause / resume
	if resp, _ = f.do("POST", "/api/targets/"+itoa(id)+"/pause", "", nil); resp.StatusCode != 204 {
		t.Fatalf("pause: %d", resp.StatusCode)
	}
	f.getJSON("/api/targets", &list)
	for _, x := range list {
		if x["id"] == float64(id) {
			if x["paused"] != true || x["active"] != false || x["status"] != "nodata" {
				t.Errorf("paused target: active=%v paused=%v status=%v", x["active"], x["paused"], x["status"])
			}
		}
	}
	if resp, _ = f.do("POST", "/api/targets/"+itoa(id)+"/resume", "", nil); resp.StatusCode != 204 {
		t.Fatalf("resume: %d", resp.StatusCode)
	}
	f.getJSON("/api/targets", &list)
	for _, x := range list {
		if x["id"] == float64(id) && (x["paused"] != false || x["active"] != true) {
			t.Errorf("resumed target: %v", x)
		}
	}
	if resp, _ = f.do("POST", "/api/targets/99999/pause", "", nil); resp.StatusCode != 404 {
		t.Errorf("pause unknown: %d", resp.StatusCode)
	}

	// config targets can be paused but not deleted
	var cfgID int64
	for _, x := range list {
		if x["source"] == "config" {
			cfgID = int64(x["id"].(float64))
		}
	}
	if resp, b = f.do("DELETE", "/api/targets/"+itoa(cfgID), "", nil); resp.StatusCode != 403 || errMsg(b) == "" {
		t.Errorf("delete config target: %d %s", resp.StatusCode, b)
	}
	if resp, _ = f.do("POST", "/api/targets/"+itoa(cfgID)+"/pause", "", nil); resp.StatusCode != 204 {
		t.Errorf("pause config target: %d", resp.StatusCode)
	}
	// delete ui target
	if resp, _ = f.do("DELETE", "/api/targets/"+itoa(id), "", nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp, _ = f.do("DELETE", "/api/targets/"+itoa(id), "", nil); resp.StatusCode != 404 {
		t.Errorf("delete twice: %d", resp.StatusCode)
	}
	f.getJSON("/api/targets", &list)
	if len(list) != 1 {
		t.Errorf("targets after delete: %d", len(list))
	}
}

func itoa(i int64) string { b, _ := json.Marshal(i); return string(b) }

func checkTargetShape(t *testing.T, x map[string]any) {
	t.Helper()
	for _, k := range []string{"id", "name", "host", "source", "active", "status", "resolved_ip", "icmp_unresponsive", "icmp_interval_ms", "last_round", "summary", "probes"} {
		if _, ok := x[k]; !ok {
			t.Errorf("target missing %q: %v", k, x)
		}
	}
	sum, ok := x["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary: %v", x["summary"])
	}
	for _, k := range []string{"e2e_rtt_ms", "e2e_p95_ms", "e2e_loss_pct", "jitter_ms", "mos", "hop_count", "http_total_ms", "http_success_pct", "cert_not_after", "active_alerts"} {
		if _, ok := sum[k]; !ok {
			t.Errorf("summary missing %q", k)
		}
	}
	switch x["status"] {
	case "ok", "degraded", "alerting", "silenced", "nodata", "learning":
	default:
		t.Errorf("status %v", x["status"])
	}
	for _, p := range x["probes"].([]any) {
		pm := p.(map[string]any)
		for _, k := range []string{"id", "type", "label"} {
			if _, ok := pm[k]; !ok {
				t.Errorf("probe missing %q", k)
			}
		}
	}
}

func TestTargetsSummary(t *testing.T) {
	f := newFixture(t, fixtureOpts{startTargets: true})
	var list []map[string]any
	f.getJSON("/api/targets", &list)
	if len(list) != 1 {
		t.Fatalf("targets: %v", list)
	}
	x := list[0]
	checkTargetShape(t, x)
	if x["name"] != "alpha" || x["host"] != "127.0.0.1" || x["source"] != "config" || x["active"] != true || x["resolved_ip"] != "127.0.0.1" || x["icmp_unresponsive"] != false {
		t.Errorf("target: %v", x)
	}
	if x["status"] != "learning" { // a brand-new database is still learning its baseline
		t.Errorf("status %v, want learning", x["status"])
	}
	sum := x["summary"].(map[string]any)
	if v, _ := sum["e2e_rtt_ms"].(float64); v < 2.9 || v > 3.1 {
		t.Errorf("e2e rtt %v want 3ms (destination at TTL 3)", sum["e2e_rtt_ms"])
	}
	if sum["e2e_loss_pct"] != float64(0) || sum["hop_count"] != float64(3) {
		t.Errorf("summary: %v", sum)
	}
	if m, _ := sum["mos"].(float64); m < 4.3 || m > 4.5 {
		t.Errorf("mos %v", sum["mos"])
	}
	if sum["http_success_pct"] != float64(100) || sum["http_total_ms"] == nil {
		t.Errorf("http summary: %v", sum)
	}
	if sum["cert_not_after"] != nil {
		t.Errorf("cert for plain http: %v", sum["cert_not_after"])
	}
	probes := x["probes"].([]any)
	types := map[string]bool{}
	for _, p := range probes {
		types[p.(map[string]any)["type"].(string)] = true
	}
	if !types["icmp-trace"] || !types["http"] || !types["tcp"] {
		t.Errorf("probe types: %v", types)
	}
	if v, ok := x["icmp_interval_ms"].(float64); !ok || v != 20 {
		t.Errorf("icmp_interval_ms %v", x["icmp_interval_ms"])
	}
	if lr, _ := x["last_round"].(float64); lr < 1.6e12 {
		t.Errorf("last_round %v", x["last_round"])
	}
}

func TestHistoryEndpoints(t *testing.T) {
	f := newFixture(t, fixtureOpts{startTargets: true})
	if err := f.st.Sync(); err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	f.getJSON("/api/targets", &list)
	id := itoa(int64(list[0]["id"].(float64)))

	// hops
	var hops map[string]any
	if resp := f.getJSON("/api/targets/"+id+"/hops?range=1h", &hops); resp.StatusCode != 200 {
		t.Fatalf("hops: %d", resp.StatusCode)
	}
	for _, k := range []string{"target_id", "path_id", "resolved_ip", "from", "to", "hops"} {
		if _, ok := hops[k]; !ok {
			t.Errorf("hops missing %q", k)
		}
	}
	hl := hops["hops"].([]any)
	if len(hl) != 3 {
		t.Fatalf("hops: %v", hl)
	}
	for i, h := range hl {
		hm := h.(map[string]any)
		for _, k := range []string{"ttl", "address", "hostname", "asn", "as_name", "responders", "alt_addresses", "sent", "lost", "loss_pct", "min_ms", "avg_ms", "max_ms", "cur_ms", "p95_ms", "jitter_ms", "classification", "is_destination"} {
			if _, ok := hm[k]; !ok {
				t.Errorf("hop %d missing %q", i, k)
			}
		}
		if hm["ttl"] != float64(i+1) || hm["sent"].(float64) < 5 || hm["loss_pct"] != float64(0) {
			t.Errorf("hop %d: %v", i, hm)
		}
	}
	h0, h2 := hl[0].(map[string]any), hl[2].(map[string]any)
	if h0["address"] != "10.0.0.1" || h0["classification"] != "ok" || h0["is_destination"] != false {
		t.Errorf("hop 1: %v", h0)
	}
	if h2["address"] != "127.0.0.1" || h2["is_destination"] != true || h2["classification"] != "destination" {
		t.Errorf("hop 3: %v", h2)
	}
	if a := h0["avg_ms"].(float64); a < 0.9 || a > 1.1 {
		t.Errorf("hop 1 avg %v", a)
	}

	// timeline
	var tl map[string]any
	f.getJSON("/api/targets/"+id+"/timeline?range=1h&buckets=60", &tl)
	for _, k := range []string{"from", "to", "step_ms", "resolution", "ttls", "labels", "rtt", "loss", "gaps", "events"} {
		if _, ok := tl[k]; !ok {
			t.Errorf("timeline missing %q", k)
		}
	}
	if tl["resolution"] != "raw" || tl["step_ms"] != float64(60000) {
		t.Errorf("timeline resolution/step: %v %v", tl["resolution"], tl["step_ms"])
	}
	if ttls := tl["ttls"].([]any); len(ttls) != 3 {
		t.Errorf("ttls: %v", ttls)
	}
	rtt := tl["rtt"].([]any)
	loss := tl["loss"].([]any)
	if len(rtt) != 3 || len(loss) != 3 {
		t.Fatalf("rtt/loss rows: %d %d", len(rtt), len(loss))
	}
	nb := len(rtt[0].([]any))
	if nb < 60 || nb > 62 || len(loss[0].([]any)) != nb {
		t.Errorf("bucket count %d", nb)
	}
	lastRTT := rtt[2].([]any)
	var found bool
	for _, v := range lastRTT {
		if v != nil {
			found = true
		}
	}
	if !found || lastRTT[0] != nil {
		t.Errorf("rtt nulls: first bucket should be empty (null), some bucket should have data")
	}
	if lastLoss := loss[0].([]any)[0]; lastLoss != nil {
		t.Errorf("empty bucket loss should be null: %v", lastLoss)
	}
	labels := tl["labels"].([]any)
	if labels[0].(map[string]any)["address"] != "10.0.0.1" {
		t.Errorf("labels: %v", labels)
	}
	if _, ok := tl["gaps"].([]any); !ok {
		t.Error("gaps must be an array")
	}
	if _, ok := tl["events"].([]any); !ok {
		t.Error("events must be an array")
	}

	// series: default destination, and explicit ttl
	var ser map[string]any
	f.getJSON("/api/targets/"+id+"/series?range=1h&buckets=30", &ser)
	if ser["ttl"] != float64(3) || ser["step_ms"] != float64(120000) {
		t.Errorf("series: ttl=%v step=%v", ser["ttl"], ser["step_ms"])
	}
	var got bool
	for _, p := range ser["points"].([]any) {
		pt := p.([]any)
		if len(pt) != 5 {
			t.Fatalf("point shape: %v", pt)
		}
		if pt[1] != nil {
			got = true
			if pt[1].(float64) < 2.9 || pt[1].(float64) > 3.1 || pt[4] != float64(0) {
				t.Errorf("series point: %v", pt)
			}
		}
	}
	if !got {
		t.Error("no series data")
	}
	f.getJSON("/api/targets/"+id+"/series?ttl=1&range=1h&buckets=10", &ser)
	if ser["ttl"] != float64(1) {
		t.Errorf("ttl=1 series: %v", ser["ttl"])
	}
	if resp, b := f.do("GET", "/api/targets/"+id+"/series?ttl=abc", "", nil); resp.StatusCode != 400 {
		t.Errorf("bad ttl: %d %s", resp.StatusCode, b)
	}

	// probes
	var pr map[string]any
	f.getJSON("/api/targets/"+id+"/probes?range=1h&buckets=20", &pr)
	httpS, tcpS := pr["http"].([]any), pr["tcp"].([]any)
	if len(httpS) != 1 || len(tcpS) != 1 {
		t.Fatalf("probes: %v", pr)
	}
	hp := httpS[0].(map[string]any)
	if hp["probe_id"] == nil || hp["label"] == nil || hp["cert_not_after"] != nil {
		t.Errorf("http probe: %v", hp)
	}
	var okPts int
	for _, p := range hp["points"].([]any) {
		pt := p.([]any)
		if len(pt) != 8 {
			t.Fatalf("http point shape: %v", pt)
		}
		if pt[6] != nil {
			okPts++
			if pt[7] != float64(100) {
				t.Errorf("success pct: %v", pt)
			}
		}
	}
	if okPts == 0 {
		t.Error("no http data points")
	}
	for _, p := range tcpS[0].(map[string]any)["points"].([]any) {
		if len(p.([]any)) != 3 {
			t.Fatalf("tcp point shape: %v", p)
		}
	}

	// dns
	var dns []map[string]any
	f.getJSON("/api/dns?range=1h&buckets=20", &dns)
	if len(dns) != 1 || dns[0]["name"] != "resolver" || dns[0]["query"] != "example.com" || dns[0]["server"] == nil {
		t.Fatalf("dns: %v", dns)
	}
	var dnsData bool
	for _, p := range dns[0]["points"].([]any) {
		pt := p.([]any)
		if len(pt) != 3 {
			t.Fatalf("dns point: %v", pt)
		}
		if pt[1] != nil {
			dnsData = true
		}
	}
	if !dnsData {
		t.Error("no dns data")
	}

	// overview
	var ov []map[string]any
	f.getJSON("/api/overview?range=1h", &ov)
	if len(ov) != 1 || ov[0]["target_id"] != list[0]["id"] || ov[0]["step_ms"] != float64(60000) {
		t.Fatalf("overview: %v", ov)
	}
	pts := ov[0]["points"].([]any)
	if n := len(pts); n < 60 || n > 62 {
		t.Errorf("overview buckets: %d", n)
	}
	var data bool
	for _, p := range pts {
		pt := p.([]any)
		if len(pt) != 3 {
			t.Fatalf("overview point: %v", pt)
		}
		if pt[1] != nil {
			data = true
		}
	}
	if !data {
		t.Error("overview has no data")
	}

	// longer ranges choose the rollup tiers; flush the open minute first
	f.st.FlushDue(time.Now().Add(2 * time.Minute))
	f.st.Sync()
	f.getJSON("/api/targets/"+id+"/timeline?range=24h&buckets=100", &tl)
	if tl["resolution"] != "1m" {
		t.Errorf("24h resolution %v", tl["resolution"])
	}
	f.getJSON("/api/targets/"+id+"/timeline?range=30d", &tl)
	if tl["resolution"] != "1h" {
		t.Errorf("30d resolution %v", tl["resolution"])
	}
	var found24 bool
	for _, v := range tl["rtt"].([]any)[2].([]any) {
		if v != nil {
			found24 = true
		}
	}
	if !found24 {
		t.Error("1h tier has no data for the current hour")
	}
	f.getJSON("/api/targets/"+id+"/hops?range=7d", &hops)
	if hl := hops["hops"].([]any); len(hl) != 3 || hl[2].(map[string]any)["sent"].(float64) < 5 {
		t.Errorf("hops from rollups: %v", hops["hops"])
	}
	f.getJSON("/api/overview?range=24h", &ov)
	if ov[0]["step_ms"].(float64) < 60000 {
		t.Errorf("overview 24h step %v", ov[0]["step_ms"])
	}

	// from/to in ms, and range precedence
	now := time.Now().UnixMilli()
	var tl2 map[string]any
	f.getJSON("/api/targets/"+id+"/timeline?from="+itoa(now-1800000)+"&to="+itoa(now)+"&range=90d&buckets=30", &tl2)
	if tl2["resolution"] != "raw" {
		t.Errorf("from beats range: %v", tl2["resolution"])
	}
	for _, bad := range []string{"range=abc", "from=x", "to=y", "buckets=0", "buckets=99999", "from=" + itoa(now) + "&to=" + itoa(now-1000)} {
		if resp, b := f.do("GET", "/api/targets/"+id+"/timeline?"+bad, "", nil); resp.StatusCode != 400 || errMsg(b) == "" {
			t.Errorf("%s: %d %s", bad, resp.StatusCode, b)
		}
	}
}

func TestAlertsEventsSilences(t *testing.T) {
	f := newFixture(t, fixtureOpts{startTargets: true})
	var list []map[string]any
	f.getJSON("/api/targets", &list)
	tid := int64(list[0]["id"].(float64))

	// no alerts yet
	var alerts []map[string]any
	f.getJSON("/api/alerts", &alerts)
	if alerts == nil || len(alerts) != 0 {
		t.Errorf("alerts: %v", alerts)
	}
	val, peak, base := 412.0, 530.1, 85.0
	end := time.Now().Add(-time.Minute)
	a := &store.Alert{TargetID: &tid, Rule: "http-slow", RuleType: "http_latency", State: "resolved", StartedAt: time.Now().Add(-10 * time.Minute), EndedAt: &end,
		Value: &val, PeakValue: &peak, Baseline: &base, Message: "HTTP total 412ms vs baseline 85ms"}
	if err := f.st.SaveAlert(a); err != nil {
		t.Fatal(err)
	}
	a2 := &store.Alert{TargetID: &tid, Rule: "http-down", RuleType: "http_failure", State: "suppressed", SuppressedReason: "silence", StartedAt: time.Now().Add(-5 * time.Minute), Message: "suppressed"}
	f.st.SaveAlert(a2)
	f.getJSON("/api/alerts?limit=10", &alerts)
	if len(alerts) != 2 {
		t.Fatalf("alerts: %v", alerts)
	}
	x := alerts[1] // oldest last
	for _, k := range []string{"id", "target_id", "target_name", "rule", "rule_type", "state", "suppressed_reason", "started_at", "ended_at", "value", "peak_value", "baseline", "message", "deliveries"} {
		if _, ok := x[k]; !ok {
			t.Errorf("alert missing %q", k)
		}
	}
	if x["target_name"] != "alpha" || x["state"] != "resolved" || x["value"] != 412.0 || x["suppressed_reason"] != nil {
		t.Errorf("alert: %v", x)
	}
	if alerts[0]["suppressed_reason"] != "silence" || alerts[0]["ended_at"] != nil {
		t.Errorf("suppressed alert: %v", alerts[0])
	}
	if d, ok := x["deliveries"].([]any); !ok || len(d) != 0 {
		t.Errorf("deliveries must be an array: %v", x["deliveries"])
	}
	f.getJSON("/api/alerts?target_id=999", &alerts)
	if len(alerts) != 0 {
		t.Error("target filter")
	}
	// the timeline shows alerts as markers
	var tl map[string]any
	f.getJSON("/api/targets/"+itoa(tid)+"/timeline?range=1h", &tl)
	var marker map[string]any
	for _, e := range tl["events"].([]any) {
		if em := e.(map[string]any); em["kind"] == "alert" {
			marker = em
		}
	}
	if marker == nil || marker["details"].(map[string]any)["rule"] != "http-slow" {
		t.Errorf("alert marker: %v", tl["events"])
	}

	// events
	f.st.RecordGap(tid, time.Now().Add(-30*time.Minute), time.Now().Add(-20*time.Minute), "stopped")
	f.st.Sync()
	var evs []map[string]any
	f.getJSON("/api/events?target_id="+itoa(tid)+"&range=1h", &evs)
	var gapEv map[string]any
	for _, e := range evs {
		for _, k := range []string{"id", "target_id", "kind", "ttl", "from", "to", "details"} {
			if _, ok := e[k]; !ok {
				t.Errorf("event missing %q: %v", k, e)
			}
		}
		if e["kind"] == "gap" {
			gapEv = e
		}
		if e["kind"] == "degraded" {
			t.Error("internal degraded events must not be exposed")
		}
	}
	if gapEv == nil || gapEv["to"] == nil {
		t.Errorf("gap event: %v", evs)
	}

	// silences: maintenance window from config is listed with source "maintenance"
	var sils []map[string]any
	f.getJSON("/api/silences", &sils)
	if len(sils) != 1 || sils[0]["source"] != "maintenance" || sils[0]["reason"] != "always" || sils[0]["target_id"] != nil {
		t.Fatalf("silences: %v", sils)
	}
	if resp, b := f.do("DELETE", "/api/silences/"+itoa(int64(sils[0]["id"].(float64))), "", nil); resp.StatusCode != 400 {
		t.Errorf("deleting a maintenance window: %d %s", resp.StatusCode, b)
	}
	// create
	if resp, _ := f.do("POST", "/api/silences", "text/plain", `{"duration_ms":1000}`); resp.StatusCode != 415 {
		t.Errorf("content type: %d", resp.StatusCode)
	}
	for _, bad := range []any{`{}`, `{"duration_ms":-5}`, `{"duration_ms":1000,"target_id":9999}`, `{"starts_at":2000,"ends_at":1000}`, `bad`} {
		if resp, b := f.postJSON("/api/silences", bad); resp.StatusCode != 400 || errMsg(b) == "" {
			t.Errorf("silence %v: %d %s", bad, resp.StatusCode, b)
		}
	}
	resp, b := f.postJSON("/api/silences", map[string]any{"target_id": nil, "rule": nil, "duration_ms": 3600000, "reason": "router upgrade"})
	if resp.StatusCode != 201 {
		t.Fatalf("create silence: %d %s", resp.StatusCode, b)
	}
	var sil map[string]any
	json.Unmarshal(b, &sil)
	for _, k := range []string{"id", "target_id", "rule", "starts_at", "ends_at", "reason", "source"} {
		if _, ok := sil[k]; !ok {
			t.Errorf("silence missing %q", k)
		}
	}
	if sil["source"] != "ui" || sil["reason"] != "router upgrade" || sil["ends_at"].(float64)-sil["starts_at"].(float64) != 3600000 {
		t.Errorf("silence: %v", sil)
	}
	resp, b = f.postJSON("/api/silences", map[string]any{"target_id": tid, "rule": "http-slow", "starts_at": time.Now().Add(time.Hour).UnixMilli(), "ends_at": time.Now().Add(2 * time.Hour).UnixMilli()})
	if resp.StatusCode != 201 {
		t.Fatalf("scheduled silence: %d %s", resp.StatusCode, b)
	}
	f.getJSON("/api/silences", &sils)
	if len(sils) != 3 {
		t.Errorf("silences: %d", len(sils))
	}
	id := itoa(int64(sil["id"].(float64)))
	if resp, _ := f.do("DELETE", "/api/silences/"+id, "", nil); resp.StatusCode != 204 {
		t.Errorf("delete silence: %d", resp.StatusCode)
	}
	if resp, _ := f.do("DELETE", "/api/silences/"+id, "", nil); resp.StatusCode != 404 {
		t.Errorf("delete again: %d", resp.StatusCode)
	}
	// the all-targets silence turns a degraded target into "silenced"
	if !f.srv.silenced(time.Now(), tid) {
		t.Error("maintenance window should silence")
	}
}

type sseReader struct {
	resp *http.Response
	ch   chan [2]string
}

func openSSE(t *testing.T, f *fixture) *sseReader {
	t.Helper()
	req, _ := http.NewRequest("GET", f.ts.URL+"/api/stream", nil)
	if f.user != "" {
		req.SetBasicAuth(f.user, f.pass)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	r := &sseReader{resp: resp, ch: make(chan [2]string, 1000)}
	go func() {
		sc := bufio.NewScanner(resp.Body)
		var ev string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				ev = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				r.ch <- [2]string{ev, strings.TrimPrefix(line, "data: ")}
			case strings.HasPrefix(line, ":"):
				r.ch <- [2]string{"comment", line}
			}
		}
		close(r.ch)
	}()
	t.Cleanup(func() { resp.Body.Close() })
	return r
}

func (r *sseReader) next(t *testing.T, event string, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case m, ok := <-r.ch:
			if !ok {
				t.Fatalf("stream closed waiting for %q", event)
			}
			if m[0] == event {
				return m[1]
			}
		case <-deadline:
			t.Fatalf("timeout waiting for SSE %q", event)
		}
	}
}

func TestSSEStream(t *testing.T) {
	f := newFixture(t, fixtureOpts{startTargets: true, auth: true})
	s := openSSE(t, f)
	s.next(t, "comment", 2*time.Second) // ": connected"

	var round struct {
		TargetID int64 `json:"target_id"`
		TS       int64 `json:"ts"`
		Hops     []struct {
			TTL     int      `json:"ttl"`
			Address *string  `json:"address"`
			RTT     *float64 `json:"rtt_ms"`
		} `json:"hops"`
	}
	if err := json.Unmarshal([]byte(s.next(t, "round", 3*time.Second)), &round); err != nil {
		t.Fatal(err)
	}
	if round.TargetID == 0 || round.TS < 1.6e12 || len(round.Hops) != 3 || round.Hops[0].Address == nil || *round.Hops[0].Address != "10.0.0.1" || round.Hops[0].RTT == nil {
		t.Errorf("round event: %+v", round)
	}
	var pe map[string]any
	if err := json.Unmarshal([]byte(s.next(t, "probe", 3*time.Second)), &pe); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"target_id", "probe_id", "type", "ts", "ok", "total_ms"} {
		if _, ok := pe[k]; !ok {
			t.Errorf("probe event missing %q: %v", k, pe)
		}
	}
	// DNS probe events carry target_id null
	var sawDNS bool
	deadline := time.Now().Add(3 * time.Second)
	for !sawDNS && time.Now().Before(deadline) {
		var m map[string]any
		json.Unmarshal([]byte(s.next(t, "probe", 3*time.Second)), &m)
		if m["type"] == "dns" {
			sawDNS = true
			if m["target_id"] != nil {
				t.Errorf("dns probe target_id: %v", m["target_id"])
			}
		}
	}
	if !sawDNS {
		t.Error("no dns probe event")
	}
	// creating a target pushes "targets"
	resp, b := f.postJSON("/api/targets", map[string]any{"name": "sse-new", "host": "127.0.0.1"})
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	if d := s.next(t, "targets", 3*time.Second); d != "{}" {
		t.Errorf("targets event data %q", d)
	}
	// alert events carry the alert object
	tid := int64(1)
	al := &store.Alert{TargetID: &tid, Rule: "r", RuleType: "http_failure", State: "firing", StartedAt: time.Now(), Message: "m"}
	f.st.SaveAlert(al)
	f.srv.Hub().AlertChanged(al.ID)
	var ae map[string]any
	json.Unmarshal([]byte(s.next(t, "alert", 3*time.Second)), &ae)
	if ae["rule"] != "r" || ae["state"] != "firing" || ae["deliveries"] == nil {
		t.Errorf("alert event: %v", ae)
	}
	// active alert count shows up in status and the target list
	var st map[string]any
	f.getJSON("/api/status", &st)
	if st["active_alerts"] != float64(1) {
		t.Errorf("active_alerts: %v", st["active_alerts"])
	}
	var list []map[string]any
	f.getJSON("/api/targets", &list)
	if list[0]["status"] != "alerting" || list[0]["summary"].(map[string]any)["active_alerts"] != float64(1) {
		t.Errorf("alerting target: %v", list[0]["status"])
	}
}

func TestHubDropsForSlowSubscribers(t *testing.T) {
	h := NewHub()
	ch, unsub := h.Subscribe()
	defer unsub()
	for i := 0; i < 1000; i++ {
		h.Publish("x", i) // never read: must not block
	}
	if len(ch) != cap(ch) {
		t.Errorf("buffered %d", len(ch))
	}
	if h.Subscribers() != 1 {
		t.Error("subscriber count")
	}
	h.Close()
	if h.Subscribers() != 0 {
		t.Error("close")
	}
}

func TestCheckCreds(t *testing.T) {
	s := New(Deps{Auth: config.Auth{Enabled: true, User: "u", Password: "p"}, Store: nil})
	if !s.checkCreds("u", "p") || s.checkCreds("u", "q") || s.checkCreds("v", "p") || s.checkCreds("", "") {
		t.Error("checkCreds")
	}
}

func TestEnrichedHostnames(t *testing.T) {
	// hostnames come from the enricher cache; without one they are null
	f := newFixture(t, fixtureOpts{startTargets: true})
	var list []map[string]any
	f.getJSON("/api/targets", &list)
	var hops map[string]any
	f.getJSON("/api/targets/"+itoa(int64(list[0]["id"].(float64)))+"/hops", &hops)
	if h := hops["hops"].([]any)[0].(map[string]any); h["hostname"] != nil || h["asn"] != nil || h["as_name"] != nil {
		t.Errorf("enrichment: %v", h)
	}
}

func TestSchedulerStatusCodesUnderLoad(t *testing.T) {
	f := newFixture(t, fixtureOpts{startTargets: true})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				var list []map[string]any
				if resp := f.getJSON("/api/targets", &list); resp.StatusCode != 200 {
					t.Errorf("targets: %d", resp.StatusCode)
				}
			}
		}()
	}
	wg.Wait()
}

func TestCSRFChecks(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	post := func(h map[string]string) int {
		req, _ := http.NewRequest("POST", f.ts.URL+"/api/silences", strings.NewReader(`{"duration_ms":60000}`))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range h {
			req.Header.Set(k, v)
		}
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	host := strings.TrimPrefix(f.ts.URL, "http://")
	cases := []struct {
		name string
		h    map[string]string
		want int
	}{
		{"no browser headers (curl)", nil, 201},
		{"same origin", map[string]string{"Origin": "http://" + host}, 201},
		{"cross origin", map[string]string{"Origin": "http://evil.example"}, 403},
		{"null origin", map[string]string{"Origin": "null"}, 403},
		{"sec-fetch same-origin behind a rewriting proxy", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://nas.example.com"}, 201},
		{"sec-fetch cross-site", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "http://" + host}, 403},
		{"sec-fetch same-site", map[string]string{"Sec-Fetch-Site": "same-site"}, 403},
		{"forwarded host", map[string]string{"Origin": "https://nas.example.com", "X-Forwarded-Host": "nas.example.com"}, 201},
	}
	for _, c := range cases {
		if got := post(c.h); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// TestHostCheckWhenAuthIsOff covers DNS rebinding: with auth off, a request addressed to a
// foreign name is refused before any handler runs, however convincing its Origin looks.
func TestHostCheckWhenAuthIsOff(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	f.srv.d.Config.PublicURL = "https://pathwatch.nas.example:8443/"
	port := f.ts.URL[strings.LastIndex(f.ts.URL, ":")+1:]
	do := func(method, path, host string, hdr map[string]string) int {
		t.Helper()
		var body io.Reader
		switch {
		case path == "/api/targets":
			body = strings.NewReader(`{"name":"x","host":"10.0.0.1"}`)
		case method == "POST":
			body = strings.NewReader(`{"duration_ms":60000}`)
		}
		req, _ := http.NewRequest(method, f.ts.URL+path, body)
		req.Host = host
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := f.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	for _, host := range []string{"rebind.example:" + port, "rebind.example", "127.0.0.1.evil.example:" + port, "localhost.evil.example", "192.168.1.5:" + port, "[2001:db8::1]:" + port, "pathwatch.nas.example.evil.test"} {
		for _, sf := range []string{"same-origin", ""} {
			hdr := map[string]string{"Origin": "http://" + host, "X-Forwarded-Host": host}
			if sf != "" {
				hdr["Sec-Fetch-Site"] = sf
			}
			for _, c := range []struct{ method, path string }{
				{"GET", "/api/status"}, {"GET", "/"}, {"GET", "/api/stream"}, {"GET", "/healthz"},
				{"POST", "/api/targets"}, {"POST", "/api/silences"},
			} {
				if got := do(c.method, c.path, host, hdr); got != http.StatusMisdirectedRequest {
					t.Errorf("%s %s Host %q Sec-Fetch-Site %q: %d, want 421", c.method, c.path, host, sf, got)
				}
			}
		}
	}

	for _, host := range []string{
		"localhost:" + port, "localhost", "LOCALHOST:" + port, "localhost.:" + port, "127.0.0.1:" + port, "127.0.0.1",
		"127.1.2.3:" + port, "[::1]:" + port, "[::1]", "pathwatch.nas.example:8443", "PathWatch.NAS.example",
	} {
		if got := do("GET", "/api/status", host, nil); got != 200 {
			t.Errorf("Host %q: %d, want 200", host, got)
		}
		if got := do("POST", "/api/silences", host, map[string]string{"Origin": "http://" + host, "Sec-Fetch-Site": "same-origin"}); got != 201 {
			t.Errorf("POST Host %q: %d, want 201", host, got)
		}
	}

	// X-Forwarded-Host never rescues a foreign Host.
	if got := do("GET", "/api/status", "rebind.example", map[string]string{"X-Forwarded-Host": "localhost"}); got != 421 {
		t.Errorf("X-Forwarded-Host trusted: %d", got)
	}

	// With auth on the check is off: LAN access by IP or NAS name keeps working.
	fa := newFixture(t, fixtureOpts{auth: true})
	req, _ := http.NewRequest("GET", fa.ts.URL+"/api/status", nil)
	req.Host = "nas.lan:8095"
	req.SetBasicAuth(fa.user, fa.pass)
	resp, err := fa.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("auth on, LAN host: %d, want 200", resp.StatusCode)
	}
}

package probe

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func TestChecksumKnownVector(t *testing.T) {
	// RFC 1071 example words: 0001 f203 f4f5 f6f7 -> checksum 0x220d
	b := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	if got := Checksum(b); got != 0x220d {
		t.Errorf("Checksum = %#04x, want 0x220d", got)
	}
}

func TestParisChecksumCompensation(t *testing.T) {
	for _, flow := range []uint16{1, 2, 0x1234, 0xfffe, 0xffff, 40000} {
		want := FlowChecksum(flow)
		if want == 0 || want == 0xffff {
			t.Fatalf("FlowChecksum(%d) = %#x is reserved", flow, want)
		}
		for seq := 0; seq < 70000; seq += 37 {
			pkt := BuildEcho(flow, uint16(seq), want)
			if got := binary.BigEndian.Uint16(pkt[2:]); got != want {
				t.Fatalf("flow %d seq %d: checksum field %#x != %#x", flow, seq, got, want)
			}
			// A packet with a valid checksum sums to zero when verified.
			if v := Checksum(pkt); v != 0 {
				t.Fatalf("flow %d seq %d: packet fails checksum verification (%#x)", flow, seq, v)
			}
			if binary.BigEndian.Uint16(pkt[4:]) != flow || binary.BigEndian.Uint16(pkt[6:]) != uint16(seq) {
				t.Fatalf("id/seq not preserved")
			}
		}
	}
}

func TestChecksumConstantAcrossSeq(t *testing.T) {
	flow := uint16(777)
	var first uint16
	for seq := uint16(0); seq < 1000; seq++ {
		pkt := BuildEcho(flow, seq, FlowChecksum(flow))
		c := binary.BigEndian.Uint16(pkt[2:])
		if seq == 0 {
			first = c
		} else if c != first {
			t.Fatalf("checksum changed at seq %d", seq)
		}
	}
}

func TestParseReplies(t *testing.T) {
	// Echo reply
	rep := make([]byte, 8)
	rep[0] = icmpEchoReply
	binary.BigEndian.PutUint16(rep[4:], 0xabcd)
	binary.BigEndian.PutUint16(rep[6:], 42)
	r, err := ParseICMP(rep)
	if err != nil || r.ID != 0xabcd || r.Seq != 42 || r.Type != icmpEchoReply {
		t.Fatalf("echo reply: %+v %v", r, err)
	}

	// Time exceeded embedding an original IPv4 header + echo request header
	orig := make([]byte, 20)
	orig[0] = 0x45
	orig[9] = 1
	copy(orig[12:16], []byte{10, 0, 0, 1})
	copy(orig[16:20], []byte{1, 2, 3, 4})
	echo := BuildEcho(0x1111, 7, FlowChecksum(0x1111))[:8]
	msg := append([]byte{icmpTimeExceeded, 0, 0, 0, 0, 0, 0, 0}, orig...)
	msg = append(msg, echo...)
	r, err = ParseICMP(msg)
	if err != nil || r.ID != 0x1111 || r.Seq != 7 || r.Dst != netip.MustParseAddr("1.2.3.4") || r.Type != icmpTimeExceeded {
		t.Fatalf("time exceeded: %+v %v", r, err)
	}

	// Full IP packet wrapper
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 1
	copy(ip[12:16], []byte{192, 168, 1, 1})
	r, err = ParseIPv4ICMP(append(ip, msg...))
	if err != nil || r.Src != netip.MustParseAddr("192.168.1.1") || r.Seq != 7 {
		t.Fatalf("ip wrapper: %+v %v", r, err)
	}
	// Garbage is rejected
	if _, err := ParseICMP([]byte{1, 2, 3}); err == nil {
		t.Error("short message accepted")
	}
	// An echo *request* (our own looped back packet) is not relevant
	if _, err := ParseICMP(BuildEcho(1, 1, FlowChecksum(1))); err == nil {
		t.Error("echo request accepted")
	}
}

func TestRawLoopbackProbe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	p, mode, err := NewICMPProber("raw")
	if err != nil {
		t.Skipf("raw sockets unavailable: %v", err)
	}
	defer p.Close()
	if mode != ModeRaw || p.Mode() != ModeRaw {
		t.Fatalf("mode %q", mode)
	}
	res := p.Probe(context.Background(), Request{Dst: netip.MustParseAddr("127.0.0.1"), TTL: 1, Flow: 4242, Seq: 1, Timeout: time.Second})
	if res.Status != StatusReply || res.Addr != netip.MustParseAddr("127.0.0.1") || res.RTT <= 0 {
		t.Fatalf("loopback probe: %+v", res)
	}
	// Concurrent probes keep distinct seq matching.
	done := make(chan Result, 20)
	for i := 0; i < 20; i++ {
		go func(i int) {
			done <- p.Probe(context.Background(), Request{Dst: netip.MustParseAddr("127.0.0.1"), TTL: 5, Flow: 4242, Seq: uint16(100 + i), Timeout: time.Second})
		}(i)
	}
	for i := 0; i < 20; i++ {
		if r := <-done; r.Status != StatusReply {
			t.Fatalf("concurrent probe %d: %+v", i, r)
		}
	}
}

func TestDNSCodecRoundTrip(t *testing.T) {
	q, err := BuildDNSQuery(0xbeef, "Example.com.", DNSTypeA)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(q) != 0xbeef || binary.BigEndian.Uint16(q[2:]) != dnsFlagRD || binary.BigEndian.Uint16(q[4:]) != 1 {
		t.Fatalf("bad header: % x", q[:12])
	}
	wantName := []byte("\x07Example\x03com\x00\x00\x01\x00\x01")
	if string(q[12:]) != string(wantName) {
		t.Fatalf("bad question: % x", q[12:])
	}
	for _, bad := range []string{"", "a..b", string(make([]byte, 70)) + ".com"} {
		if _, err := BuildDNSQuery(1, bad, DNSTypeA); err == nil {
			t.Errorf("BuildDNSQuery(%q) should fail", bad)
		}
	}
}

// buildResponse crafts a response to q with a compressed-name A record and an AAAA record.
func buildResponse(q []byte, rcode int, truncated bool) []byte {
	r := append([]byte{}, q...)
	flags := uint16(dnsFlagQR | dnsFlagRD | rcode)
	if truncated {
		flags |= dnsFlagTC
	}
	binary.BigEndian.PutUint16(r[2:], flags)
	if rcode != 0 {
		return r
	}
	binary.BigEndian.PutUint16(r[6:], 2)
	// A record with pointer to the question name at offset 12
	r = append(r, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34)
	// AAAA record
	r = append(r, 0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 30, 0, 16)
	aaaa := netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946").As16()
	r = append(r, aaaa[:]...)
	return r
}

func TestDNSParseResponse(t *testing.T) {
	q, _ := BuildDNSQuery(7, "example.com", DNSTypeA)
	m, err := ParseDNSResponse(buildResponse(q, 0, false))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Response || m.ID != 7 || m.RCode != 0 || m.Questions != 1 || len(m.Answers) != 2 {
		t.Fatalf("%+v", m)
	}
	if m.Answers[0].Addr != netip.MustParseAddr("93.184.216.34") || m.Answers[0].Name != "example.com" || m.Answers[0].TTL != 60 {
		t.Errorf("A answer: %+v", m.Answers[0])
	}
	if m.Answers[1].Type != DNSTypeAAAA || m.Answers[1].Addr != netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946") {
		t.Errorf("AAAA answer: %+v", m.Answers[1])
	}
	m, err = ParseDNSResponse(buildResponse(q, RCodeServFail, false))
	if err != nil || m.RCode != RCodeServFail {
		t.Fatalf("servfail: %+v %v", m, err)
	}
	if RCodeName(RCodeNXDomain) != "NXDOMAIN" || RCodeName(99) != "RCODE99" {
		t.Error("rcode names")
	}
}

func TestDNSParseMalicious(t *testing.T) {
	q, _ := BuildDNSQuery(7, "example.com", DNSTypeA)
	// Truncations of a valid response must never panic.
	full := buildResponse(q, 0, false)
	for i := 0; i < len(full); i++ {
		_, _ = ParseDNSResponse(full[:i])
	}
	// Compression pointer loop.
	loop := append([]byte{}, q[:12]...)
	loop[5] = 1
	loop = append(loop, 0xc0, 12, 0, 1, 0, 1)
	if _, err := ParseDNSResponse(loop); err == nil {
		t.Error("pointer loop accepted")
	}
}

func fakeDNSServer(t *testing.T, rcode int, truncateUDP bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { pc.Close() })
	addr := pc.LocalAddr().String()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// junk first, to exercise id mismatch handling
			pc.WriteTo([]byte{1, 2, 3}, from)
			pc.WriteTo(buildResponse(buf[:n], rcode, truncateUDP), from)
		}
	}()
	if truncateUDP {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			t.Cleanup(func() { ln.Close() })
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						var lb [2]byte
						if _, err := c.Read(lb[:]); err != nil {
							return
						}
						q := make([]byte, binary.BigEndian.Uint16(lb[:]))
						if _, err := c.Read(q); err != nil {
							return
						}
						resp := buildResponse(q, rcode, false)
						out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
						c.Write(append(out, resp...))
					}()
				}
			}()
		}
	}
	return addr
}

func TestDNSQueryAgainstFakeServer(t *testing.T) {
	addr := fakeDNSServer(t, 0, false)
	res := DNSQuery(context.Background(), addr, "example.com", "A", time.Second)
	if !res.OK || res.Err != nil || res.Answers != 2 || res.RTT <= 0 {
		t.Fatalf("%+v", res)
	}
	addr = fakeDNSServer(t, RCodeServFail, false)
	res = DNSQuery(context.Background(), addr, "example.com", "A", time.Second)
	if res.OK || res.Err == nil || res.RCode != RCodeServFail {
		t.Fatalf("servfail: %+v", res)
	}
	addr = fakeDNSServer(t, 0, true) // truncated over UDP -> TCP fallback
	res = DNSQuery(context.Background(), addr, "example.com", "A", time.Second)
	if !res.OK || res.Answers != 2 {
		t.Fatalf("tcp fallback: %+v", res)
	}
	// Timeout against a silent server
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	res = DNSQuery(context.Background(), pc.LocalAddr().String(), "example.com", "A", 150*time.Millisecond)
	if res.OK || res.Err == nil || res.Err.Error() != "timeout" {
		t.Fatalf("timeout: %+v", res)
	}
}

func TestTCPConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	res := TCPConnect(context.Background(), netip.MustParseAddr("127.0.0.1"), port, time.Second)
	if !res.OK || res.Connect <= 0 {
		t.Fatalf("%+v", res)
	}
	ln.Close()
	res = TCPConnect(context.Background(), netip.MustParseAddr("127.0.0.1"), port, time.Second)
	if res.OK || res.Err == nil {
		t.Fatalf("closed port should fail: %+v", res)
	}
}

func httpProbeCfg(url string) config.Probe {
	return config.Probe{Type: "http", URL: url, Method: "GET", Timeout: 3 * time.Second, Interval: time.Second, MaxBody: 1 << 20, PinIP: true}
}

func TestHTTPProbe(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.UserAgent()
		switch r.URL.Path {
		case "/redir":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.Write([]byte("hello world"))
		case "/slow":
			time.Sleep(500 * time.Millisecond)
		case "/err":
			w.WriteHeader(503)
		default:
			time.Sleep(20 * time.Millisecond)
			w.Write(make([]byte, 5000))
		}
	}))
	defer srv.Close()

	res := HTTPProbe(context.Background(), httpProbeCfg(srv.URL+"/"), HTTPOptions{Version: "9.9"})
	if !res.OK || res.Status != 200 || res.Total <= 0 || res.Connect <= 0 || res.TTFB <= 0 {
		t.Fatalf("basic: %+v", res)
	}
	if gotUA != "pathwatch/9.9" {
		t.Errorf("user agent %q", gotUA)
	}
	if !res.CertNotAfter.IsZero() {
		t.Error("cert for plain http")
	}

}

func TestHTTPProbePinAndRedirects(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		switch r.URL.Path {
		case "/redir":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/err":
			w.WriteHeader(503)
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	p := httpProbeCfg("http://pinned.invalid:" + itoa(port) + "/")
	res := HTTPProbe(context.Background(), p, HTTPOptions{Pin: netip.MustParseAddr("127.0.0.1"), PinDNS: 3 * time.Millisecond})
	if !res.OK || gotHost != "pinned.invalid:"+itoa(port) {
		t.Fatalf("pinned: %+v host=%q", res, gotHost)
	}
	if res.DNS != 3*time.Millisecond || res.Total < 3*time.Millisecond {
		t.Errorf("pinned dns phase: %+v", res)
	}
	// Without pinning the unresolvable name fails.
	p.PinIP = false
	if res := HTTPProbe(context.Background(), p, HTTPOptions{Pin: netip.MustParseAddr("127.0.0.1")}); res.OK {
		t.Error("unpinned lookup of .invalid should fail")
	}

	// Redirects: not followed by default (302 counts as OK), followed on request.
	p = httpProbeCfg(srv.URL + "/redir")
	res = HTTPProbe(context.Background(), p, HTTPOptions{})
	if !res.OK || res.Status != 302 || res.Redirects != 0 {
		t.Fatalf("no-follow: %+v", res)
	}
	p.FollowRedirects = true
	res = HTTPProbe(context.Background(), p, HTTPOptions{})
	if !res.OK || res.Status != 200 || res.Redirects != 1 || res.FinalURL != srv.URL+"/final" {
		t.Fatalf("follow: %+v", res)
	}

	// expect_status
	p = httpProbeCfg(srv.URL + "/err")
	if res := HTTPProbe(context.Background(), p, HTTPOptions{}); res.OK || res.Err == nil || res.Status != 503 {
		t.Fatalf("503 should fail: %+v", res)
	}
	p.ExpectStatus = []int{503}
	if res := HTTPProbe(context.Background(), p, HTTPOptions{}); !res.OK {
		t.Fatalf("503 expected: %+v", res)
	}

	// Timeout
	p = httpProbeCfg(srv.URL + "/")
	p.Timeout = 50 * time.Millisecond
	l, _ := net.Listen("tcp", "127.0.0.1:0") // accepts but never answers
	defer l.Close()
	p.URL = "http://" + l.Addr().String() + "/"
	res = HTTPProbe(context.Background(), p, HTTPOptions{})
	if res.OK || res.Err == nil || res.Err.Error() != "timeout" {
		t.Fatalf("timeout: %+v", res)
	}
}

func TestHTTPSCertAndFreshConnections(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("x")) }))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	p := httpProbeCfg(srv.URL + "/")
	p.InsecureSkipVerify = true
	for i := 0; i < 3; i++ {
		res := HTTPProbe(context.Background(), p, HTTPOptions{})
		if !res.OK || res.CertNotAfter.IsZero() || res.TLS <= 0 {
			t.Fatalf("https: %+v", res)
		}
	}
	if conns.Load() != 3 {
		t.Errorf("connections = %d, want a fresh one per probe (3)", conns.Load())
	}
	p.InsecureSkipVerify = false
	if res := HTTPProbe(context.Background(), p, HTTPOptions{}); res.OK {
		t.Error("self-signed cert should fail verification")
	}
}

func TestProxyEnvIgnored(t *testing.T) {
	hit := false
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("direct")) }))
	defer target.Close()
	p := httpProbeCfg(target.URL + "/")
	if res := HTTPProbe(context.Background(), p, HTTPOptions{}); !res.OK || hit {
		t.Fatalf("proxy env must be ignored: %+v proxyHit=%v", res, hit)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

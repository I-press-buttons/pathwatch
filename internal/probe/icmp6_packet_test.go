package probe

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

var (
	t6src = netip.MustParseAddr("2001:db8::1")
	t6dst = netip.MustParseAddr("2001:db8:ffff::53")
)

// kernelChecksum recomputes the checksum the kernel would put on pkt.
func kernelChecksum(src, dst netip.Addr, pkt []byte) uint16 {
	c := append([]byte(nil), pkt...)
	c[2], c[3] = 0, 0
	return Checksum6(src, dst, c)
}

func TestBuildEcho6FlowChecksumConstant(t *testing.T) {
	for _, flow := range []uint16{1, 2, 4242, 0xfffe, 0xffff} {
		want := FlowChecksum(flow)
		for seq := 0; seq < 3000; seq += 7 {
			pkt := BuildEcho6(flow, uint16(seq), want, t6src, t6dst)
			if pkt[0] != icmp6EchoRequest {
				t.Fatalf("type %d", pkt[0])
			}
			if got := kernelChecksum(t6src, t6dst, pkt); got != want {
				t.Fatalf("flow %d seq %d: kernel checksum %#x, want %#x", flow, seq, got, want)
			}
			if binary.BigEndian.Uint16(pkt[4:]) != flow || binary.BigEndian.Uint16(pkt[6:]) != uint16(seq) {
				t.Fatal("id/seq not encoded")
			}
		}
	}
}

func TestBuildEcho6ChecksumDependsOnSource(t *testing.T) {
	// With a different source the same packet checksums differently: this is why the
	// compensation needs the real local address.
	want := FlowChecksum(7)
	pkt := BuildEcho6(7, 1, want, t6src, t6dst)
	other := netip.MustParseAddr("2001:db8::2")
	if kernelChecksum(other, t6dst, pkt) == want {
		t.Fatal("checksum unexpectedly independent of the source address")
	}
}

func echoReply6(id, seq uint16) []byte {
	m := make([]byte, 16)
	m[0] = icmp6EchoReply
	binary.BigEndian.PutUint16(m[4:], id)
	binary.BigEndian.PutUint16(m[6:], seq)
	return m
}

func quote6(id, seq uint16, dst netip.Addr) []byte {
	ip := make([]byte, ipv6HeaderBytes)
	ip[0] = 0x60
	ip[6] = ipv6NextICMPv6
	ip[7] = 1
	s := t6src.As16()
	d := dst.As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	return append(ip, BuildEcho6(id, seq, FlowChecksum(id), t6src, dst)...)
}

func TestParseICMPv6RoundTrip(t *testing.T) {
	r, err := ParseICMPv6(echoReply6(0xabcd, 42))
	if err != nil || r.Type != icmp6EchoReply || r.ID != 0xabcd || r.Seq != 42 {
		t.Fatalf("echo reply: %+v %v", r, err)
	}
	for _, typ := range []uint8{icmp6TimeExceeded, icmp6DestUnreach} {
		msg := append([]byte{typ, 0, 0, 0, 0, 0, 0, 0}, quote6(0x1111, 7, t6dst)...)
		r, err := ParseICMPv6(msg)
		if err != nil || r.Type != typ || r.ID != 0x1111 || r.Seq != 7 || r.Dst != t6dst {
			t.Fatalf("type %d: %+v %v", typ, r, err)
		}
		if st, ok := statusForICMPv6Type(typ); !ok || st == StatusReply {
			t.Fatalf("status for %d: %v %v", typ, st, ok)
		}
	}
	// Embedded forms accepted by the datagram error queue parser.
	q := quote6(0x2222, 9, t6dst)
	for _, b := range [][]byte{q, q[ipv6HeaderBytes:]} {
		id, seq, ok := ParseEmbeddedEcho6(b)
		if !ok || id != 0x2222 || seq != 9 {
			t.Fatalf("embedded: %d %d %v", id, seq, ok)
		}
	}
}

func TestParseICMPv6Untrusted(t *testing.T) {
	good := append([]byte{icmp6TimeExceeded, 0, 0, 0, 0, 0, 0, 0}, quote6(1, 1, t6dst)...)
	// Every truncation must be rejected or parsed without panicking.
	for n := 0; n < len(good); n++ {
		_, err := ParseICMPv6(good[:n])
		if n < echoHeaderLen+ipv6HeaderBytes+echoHeaderLen && err == nil {
			t.Fatalf("truncated to %d bytes accepted", n)
		}
		ParseEmbeddedEcho6(good[:n])
	}
	mut := func(f func(b []byte)) []byte {
		b := append([]byte(nil), good...)
		f(b)
		return b
	}
	bad := map[string][]byte{
		"ipv4 version":      mut(func(b []byte) { b[8] = 0x45 }),
		"wrong next header": mut(func(b []byte) { b[8+6] = 17 }),
		"quoted not echo":   mut(func(b []byte) { b[8+ipv6HeaderBytes] = 129 }),
		"unknown type":      {134, 0, 0, 0, 0, 0, 0, 0},
		"empty":             nil,
	}
	for name, b := range bad {
		if _, err := ParseICMPv6(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, _, ok := ParseEmbeddedEcho6([]byte{icmp6EchoReply, 0, 0, 0, 0, 0, 0, 0}); ok {
		t.Error("embedded echo reply accepted")
	}
}

func TestEchoReply6OnlyFromDestination(t *testing.T) {
	p := newPendingTable()
	key := pendKey(4242, 17)
	w := newTestWaiter(p, key, t6dst)
	p.deliver(key, time.Now(), StatusReply, netip.MustParseAddr("2001:db8::bad"), netip.Addr{})
	if len(w.ch) != 0 {
		t.Fatal("Echo Reply from another source completed the probe")
	}
	p.deliver(key, time.Now(), StatusReply, t6dst, netip.Addr{})
	if r := p.wait(context.Background(), key, w, 100*time.Millisecond); r.Status != StatusReply || r.Addr != t6dst {
		t.Fatalf("got %+v", r)
	}
	// An error from a router quoting another destination is not ours either.
	w = newTestWaiter(p, key, t6dst)
	router := netip.MustParseAddr("2001:db8:1::1")
	p.deliver(key, time.Now(), StatusTTLExceeded, router, netip.MustParseAddr("2001:db8::99"))
	if len(w.ch) != 0 {
		t.Fatal("error quoting another destination accepted")
	}
	p.deliver(key, time.Now(), StatusTTLExceeded, router, t6dst)
	if len(w.ch) != 1 {
		t.Fatal("router error quoting our destination rejected")
	}
}

type fakeProber struct {
	mode  string
	got   []Request
	freed []uint16
}

func (f *fakeProber) Probe(_ context.Context, r Request) Result {
	f.got = append(f.got, r)
	return Result{Status: StatusReply, Addr: r.Dst}
}
func (f *fakeProber) Mode() string          { return f.mode }
func (f *fakeProber) Close() error          { return nil }
func (f *fakeProber) ReleaseFlow(fl uint16) { f.freed = append(f.freed, fl) }

func TestDualProberDispatch(t *testing.T) {
	v4, v6 := &fakeProber{mode: ModeRaw}, &fakeProber{mode: ModeDgram}
	d := &dualProber{v4: v4, v6: v6}
	d.Probe(context.Background(), Request{Dst: netip.MustParseAddr("::ffff:192.0.2.1")})
	d.Probe(context.Background(), Request{Dst: t6dst})
	if len(v4.got) != 1 || !v4.got[0].Dst.Is4() || len(v6.got) != 1 {
		t.Fatalf("dispatch: v4=%v v6=%v", v4.got, v6.got)
	}
	if d.Mode() != ModeRaw {
		t.Fatalf("mode %q", d.Mode())
	}
	d.ReleaseFlow(3)
	if len(v4.freed) != 1 || len(v6.freed) != 1 {
		t.Fatal("ReleaseFlow not forwarded")
	}
	only4 := &dualProber{v4: v4}
	if r := only4.Probe(context.Background(), Request{Dst: t6dst}); r.Err == nil {
		t.Fatal("missing IPv6 prober should yield an error")
	}
	if (&dualProber{v6: v6}).Mode() != ModeDgram {
		t.Fatal("v6-only mode")
	}
}

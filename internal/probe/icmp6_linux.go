//go:build linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// ICMPv6 counterparts of the raw and datagram probers in icmp_linux.go. The differences:
//   - the hop limit is set with IPV6_UNICAST_HOPS;
//   - raw ICMPv6 sockets do not deliver the IPv6 header, so a responder's address is the
//     recvfrom source address;
//   - the kernel computes the ICMPv6 checksum itself over a pseudo-header that includes the
//     source address, so the Paris flow checksum is held constant by compensating with the
//     local source address the kernel will pick (see BuildEcho6 and srcCache).

const (
	soEEOriginICMP6 = 3 // SO_EE_ORIGIN_ICMP6
	srcCacheTTL     = 10 * time.Minute
)

func addr6(a netip.Addr) (*unix.SockaddrInet6, bool) {
	a = a.Unmap()
	if !a.Is6() {
		return nil, false
	}
	sa := &unix.SockaddrInet6{Addr: a.As16()}
	if z := a.Zone(); z != "" {
		if n, err := strconv.Atoi(z); err == nil && n > 0 {
			sa.ZoneId = uint32(n)
		} else if ifi, err := net.InterfaceByName(z); err == nil {
			sa.ZoneId = uint32(ifi.Index)
		}
	}
	return sa, true
}

func from6(sa unix.Sockaddr) netip.Addr {
	if in6, ok := sa.(*unix.SockaddrInet6); ok {
		return netip.AddrFrom16(in6.Addr)
	}
	return netip.Addr{}
}

// localSource6 asks the kernel which source address it would use for dst by connecting a UDP
// socket (nothing is sent).
func localSource6(dst netip.Addr) (netip.Addr, error) {
	c, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: dst.AsSlice(), Zone: dst.Zone(), Port: 9})
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("unexpected local address type")
	}
	a, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.Addr{}, errors.New("invalid local address")
	}
	return a.Unmap().WithZone(""), nil
}

// srcCache caches the local source address per destination so probes do not open a socket
// each time. Entries expire so a changed route is picked up; a stale source only makes the
// flow checksum differ from the intended constant, it never breaks probing.
type srcCache struct {
	mu sync.Mutex
	m  map[netip.Addr]srcEntry
}

type srcEntry struct {
	src netip.Addr
	at  time.Time
}

func (c *srcCache) get(dst netip.Addr) (netip.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[dst]; ok && time.Since(e.at) < srcCacheTTL {
		return e.src, nil
	}
	src, err := localSource6(dst)
	if err != nil {
		return netip.Addr{}, err
	}
	if c.m == nil || len(c.m) > 1024 {
		c.m = make(map[netip.Addr]srcEntry)
	}
	c.m[dst] = srcEntry{src: src, at: time.Now()}
	return src, nil
}

// ---------------------------------------------------------------------------
// raw mode

type raw6Prober struct {
	fd     int
	sendMu sync.Mutex // serialises setsockopt(IPV6_UNICAST_HOPS)+sendto
	pend   *pendingTable
	src    srcCache
	closed atomic.Bool
	done   chan struct{}
}

func newRaw6Prober() (*raw6Prober, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		return nil, err
	}
	// ICMP6_FILTER: a set bit BLOCKS that type. Pass only Dest Unreachable, Time Exceeded
	// and Echo Reply. Best effort.
	var f unix.ICMPv6Filter
	for i := range f.Data {
		f.Data[i] = ^uint32(0)
	}
	for _, t := range []uint8{icmp6DestUnreach, icmp6TimeExceeded, icmp6EchoReply} {
		f.Data[t>>5] &^= 1 << (t & 31)
	}
	_ = unix.SetsockoptICMPv6Filter(fd, unix.IPPROTO_ICMPV6, unix.ICMPV6_FILTER, &f)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	tv := unix.NsecToTimeval(int64(500 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, err
	}
	p := &raw6Prober{fd: fd, pend: newPendingTable(), done: make(chan struct{})}
	go p.recvLoop()
	return p, nil
}

func (p *raw6Prober) Mode() string { return ModeRaw }

func (p *raw6Prober) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	<-p.done
	return unix.Close(p.fd)
}

func (p *raw6Prober) recvLoop() {
	defer close(p.done)
	buf := make([]byte, 4096)
	for !p.closed.Load() {
		n, from, err := unix.Recvfrom(p.fd, buf, 0)
		recvAt := time.Now()
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.ETIMEDOUT) {
				continue
			}
			if p.closed.Load() {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		r, err := ParseICMPv6(buf[:n])
		if err != nil {
			continue
		}
		st, ok := statusForICMPv6Type(r.Type)
		if !ok {
			continue
		}
		// No IPv6 header on raw ICMPv6 sockets: the responder is the datagram source.
		p.pend.deliver(pendKey(r.ID, r.Seq), recvAt, st, from6(from), r.Dst)
	}
}

func (p *raw6Prober) Probe(ctx context.Context, req Request) Result {
	sa, ok := addr6(req.Dst)
	if !ok {
		return Result{Err: errors.New("IPv6 prober supports IPv6 destinations only")}
	}
	if p.closed.Load() {
		return Result{Err: errors.New("prober closed")}
	}
	dst := req.Dst.Unmap()
	src, err := p.src.get(dst)
	if err != nil {
		return Result{Err: fmt.Errorf("no IPv6 route/source address for %s: %w", dst.WithZone(""), err)}
	}
	pkt := BuildEcho6(req.Flow, req.Seq, FlowChecksum(req.Flow), src, dst.WithZone(""))
	key := pendKey(req.Flow, req.Seq)
	w := &waiter{ch: make(chan Result, 1), dst: dst.WithZone("")}
	if !p.pend.add(key, w) {
		return Result{Err: errors.New("duplicate probe id/seq in flight")}
	}
	p.sendMu.Lock()
	err = unix.SetsockoptInt(p.fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, req.TTL)
	if err == nil {
		w.sent.Store(monoNow())
		err = unix.Sendto(p.fd, pkt, 0, sa)
	}
	p.sendMu.Unlock()
	if err != nil {
		p.pend.take(key)
		return Result{Err: fmt.Errorf("send: %w", err)}
	}
	return p.pend.wait(ctx, key, w, req.Timeout)
}

// ---------------------------------------------------------------------------
// datagram mode: unprivileged ICMPv6 ping sockets with IPV6_RECVERR, one socket per flow.
// As for IPv4 the kernel rewrites the identifier to the socket's port and recomputes the
// checksum; we build with that port as the identifier and compensate for the pseudo-header.
// NOTE: written against the kernel's documented behaviour but not exercised on a host with
// IPv6 (the development sandbox has none). The layout of the error-queue payload differs
// between kernels, so ParseEmbeddedEcho6 accepts both known forms.

type dgram6Prober struct {
	mu     sync.Mutex
	flows  map[uint16]*dgram6Flow
	src    srcCache
	closed bool
}

type dgram6Flow struct {
	fd     int
	id     uint16
	sendMu sync.Mutex
	pend   *pendingTable
	closed atomic.Bool
	done   chan struct{}
}

func newDgram6Prober() (*dgram6Prober, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMPV6)
	if err != nil {
		return nil, err
	}
	unix.Close(fd)
	return &dgram6Prober{flows: make(map[uint16]*dgram6Flow)}, nil
}

func (p *dgram6Prober) Mode() string { return ModeDgram }

func (p *dgram6Prober) Close() error {
	p.mu.Lock()
	p.closed = true
	flows := p.flows
	p.flows = map[uint16]*dgram6Flow{}
	p.mu.Unlock()
	for _, f := range flows {
		f.close()
	}
	return nil
}

func (p *dgram6Prober) ReleaseFlow(flow uint16) {
	p.mu.Lock()
	f := p.flows[flow]
	delete(p.flows, flow)
	p.mu.Unlock()
	if f != nil {
		f.close()
	}
}

func (p *dgram6Prober) flow(key uint16) (*dgram6Flow, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("prober closed")
	}
	if f := p.flows[key]; f != nil {
		return f, nil
	}
	f, err := newDgram6Flow()
	if err != nil {
		return nil, err
	}
	p.flows[key] = f
	return f, nil
}

func newDgram6Flow() (*dgram6Flow, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_ICMPV6)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*dgram6Flow, error) { unix.Close(fd); return nil, err }
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1); err != nil {
		return fail(fmt.Errorf("IPV6_RECVERR: %w", err))
	}
	if err := unix.Bind(fd, &unix.SockaddrInet6{}); err != nil {
		return fail(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return fail(err)
	}
	in6, ok := sa.(*unix.SockaddrInet6)
	if !ok {
		return fail(errors.New("unexpected socket address type"))
	}
	f := &dgram6Flow{fd: fd, id: uint16(in6.Port), pend: newPendingTable(), done: make(chan struct{})}
	go f.recvLoop()
	return f, nil
}

func (f *dgram6Flow) close() {
	if f.closed.Swap(true) {
		return
	}
	<-f.done
	unix.Close(f.fd)
}

func (f *dgram6Flow) recvLoop() {
	defer close(f.done)
	buf := make([]byte, 2048)
	oob := make([]byte, 1024)
	pfd := []unix.PollFd{{Fd: int32(f.fd), Events: unix.POLLIN}}
	for !f.closed.Load() {
		pfd[0].Revents = 0
		if _, err := unix.Poll(pfd, 500); err != nil && !errors.Is(err, unix.EINTR) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if pfd[0].Revents == 0 {
			continue
		}
		for {
			n, oobn, _, from, err := unix.Recvmsg(f.fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
			recvAt := time.Now()
			if err != nil {
				break
			}
			// For ICMP errors the kernel reports the original destination as the
			// error-queue message's source address.
			f.handleErr(buf[:n], oob[:oobn], recvAt, from6(from))
		}
		for {
			n, from, err := unix.Recvfrom(f.fd, buf, unix.MSG_DONTWAIT)
			recvAt := time.Now()
			if err != nil {
				break
			}
			r, perr := ParseICMPv6(buf[:n])
			if perr != nil || r.Type != icmp6EchoReply {
				continue
			}
			f.pend.deliver(pendKey(f.id, r.Seq), recvAt, StatusReply, from6(from), netip.Addr{})
		}
		if pfd[0].Revents&(unix.POLLNVAL|unix.POLLHUP) != 0 {
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func (f *dgram6Flow) handleErr(data, oob []byte, recvAt time.Time, origDst netip.Addr) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_IPV6 || m.Header.Type != unix.IPV6_RECVERR {
			continue
		}
		const eeLen = 16 // struct sock_extended_err
		// struct sockaddr_in6 follows: family(2) port(2) flowinfo(4) addr(16) scope(4)
		if len(m.Data) < eeLen+24 {
			continue
		}
		if m.Data[4] != soEEOriginICMP6 {
			continue
		}
		st, ok := statusForICMPv6Type(m.Data[5])
		if !ok {
			continue
		}
		src, _ := netip.AddrFromSlice(m.Data[eeLen+8 : eeLen+24])
		_, seq, ok := ParseEmbeddedEcho6(data)
		if !ok {
			continue
		}
		f.pend.deliver(pendKey(f.id, seq), recvAt, st, src, origDst)
	}
}

func (p *dgram6Prober) Probe(ctx context.Context, req Request) Result {
	sa, ok := addr6(req.Dst)
	if !ok {
		return Result{Err: errors.New("IPv6 prober supports IPv6 destinations only")}
	}
	f, err := p.flow(req.Flow)
	if err != nil {
		return Result{Err: err}
	}
	dst := req.Dst.Unmap()
	src, err := p.src.get(dst)
	if err != nil {
		return Result{Err: fmt.Errorf("no IPv6 route/source address for %s: %w", dst.WithZone(""), err)}
	}
	pkt := BuildEcho6(f.id, req.Seq, FlowChecksum(f.id), src, dst.WithZone(""))
	key := pendKey(f.id, req.Seq)
	w := &waiter{ch: make(chan Result, 1), dst: dst.WithZone("")}
	if !f.pend.add(key, w) {
		return Result{Err: errors.New("duplicate probe seq in flight")}
	}
	f.sendMu.Lock()
	err = unix.SetsockoptInt(f.fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, req.TTL)
	if err == nil {
		w.sent.Store(monoNow())
		err = unix.Sendto(f.fd, pkt, 0, sa)
	}
	f.sendMu.Unlock()
	if err != nil {
		f.pend.take(key)
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			return Result{Err: fmt.Errorf("send: %w (firewall?)", err)}
		}
		return Result{Err: fmt.Errorf("send: %w", err)}
	}
	return f.pend.wait(ctx, key, w, req.Timeout)
}

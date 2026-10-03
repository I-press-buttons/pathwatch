//go:build linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// NewICMPProber creates the Linux ICMP prober. mode is "auto", "raw" or "dgram".
// "auto" prefers raw sockets (root/CAP_NET_RAW, needed on older NAS kernels) and falls
// back to unprivileged datagram sockets. The returned mode string is "raw" or "dgram";
// on failure the error explains why neither worked.
func NewICMPProber(mode string) (Prober, string, error) {
	switch mode {
	case "raw":
		p, err := newRawProber()
		if err != nil {
			return nil, ModeUnavailable, fmt.Errorf("raw ICMP socket: %w (needs root or CAP_NET_RAW)", err)
		}
		return p, ModeRaw, nil
	case "dgram":
		p, err := newDgramProber()
		if err != nil {
			return nil, ModeUnavailable, fmt.Errorf("datagram ICMP socket: %w (check net.ipv4.ping_group_range)", err)
		}
		return p, ModeDgram, nil
	default:
		p, rawErr := newRawProber()
		if rawErr == nil {
			return p, ModeRaw, nil
		}
		d, dgramErr := newDgramProber()
		if dgramErr == nil {
			return d, ModeDgram, nil
		}
		return nil, ModeUnavailable, fmt.Errorf("raw ICMP socket: %v; datagram ICMP socket: %v (run as root with NET_RAW, or set net.ipv4.ping_group_range)", rawErr, dgramErr)
	}
}

func addr4(a netip.Addr) (*unix.SockaddrInet4, bool) {
	a = a.Unmap()
	if !a.Is4() {
		return nil, false
	}
	return &unix.SockaddrInet4{Addr: a.As4()}, true
}

// ---------------------------------------------------------------------------
// raw mode: one shared raw socket, TTL set per probe, replies matched by id/seq.

type rawProber struct {
	fd      int
	sendMu  sync.Mutex // serialises setsockopt(IP_TTL)+sendto so concurrent probes keep their own TTL
	pend    *pendingTable
	closed  atomic.Bool
	done    chan struct{}
	rcvOnce sync.Once
}

func newRawProber() (*rawProber, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	// Only let echo reply (0), destination unreachable (3) and time exceeded (11) through.
	// ICMP_FILTER sets a bit per type to BLOCK. Best effort.
	mask := ^uint32(1<<0 | 1<<3 | 1<<11)
	_ = unix.SetsockoptInt(fd, unix.SOL_RAW, 1, int(int32(mask)))
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	tv := unix.NsecToTimeval(int64(500 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, err
	}
	p := &rawProber{fd: fd, pend: newPendingTable(), done: make(chan struct{})}
	go p.recvLoop()
	return p, nil
}

func (p *rawProber) Mode() string { return ModeRaw }

func (p *rawProber) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	<-p.done
	return unix.Close(p.fd)
}

func (p *rawProber) recvLoop() {
	defer close(p.done)
	buf := make([]byte, 4096)
	for !p.closed.Load() {
		n, _, err := unix.Recvfrom(p.fd, buf, 0)
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
		r, err := ParseIPv4ICMP(buf[:n])
		if err != nil {
			continue
		}
		st, ok := statusForICMPType(r.Type)
		if !ok {
			continue
		}
		p.pend.deliver(pendKey(r.ID, r.Seq), recvAt, st, r.Src, r.Dst)
	}
}

func (p *rawProber) Probe(ctx context.Context, req Request) Result {
	sa, ok := addr4(req.Dst)
	if !ok {
		return Result{Err: errors.New("raw prober supports IPv4 destinations only")}
	}
	if p.closed.Load() {
		return Result{Err: errors.New("prober closed")}
	}
	pkt := BuildEcho(req.Flow, req.Seq, FlowChecksum(req.Flow))
	key := pendKey(req.Flow, req.Seq)
	w := &waiter{ch: make(chan Result, 1), dst: req.Dst.Unmap()}
	if !p.pend.add(key, w) {
		return Result{Err: errors.New("duplicate probe id/seq in flight")}
	}
	p.sendMu.Lock()
	err := unix.SetsockoptInt(p.fd, unix.IPPROTO_IP, unix.IP_TTL, req.TTL)
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
// datagram mode: unprivileged ICMP sockets with IP_RECVERR, one socket per flow.
// The kernel rewrites the identifier to the socket's port, so Paris identity needs a socket
// per flow; the kernel also recomputes the checksum, so we compensate for the port-id.

type dgramProber struct {
	mu     sync.Mutex
	flows  map[uint16]*dgramFlow
	closed bool
}

type dgramFlow struct {
	fd     int
	id     uint16 // kernel-assigned identifier (the socket's port)
	sendMu sync.Mutex
	pend   *pendingTable
	closed atomic.Bool
	done   chan struct{}
}

func newDgramProber() (*dgramProber, error) {
	// Probe that datagram sockets can be created at all.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	unix.Close(fd)
	return &dgramProber{flows: make(map[uint16]*dgramFlow)}, nil
}

func (p *dgramProber) Mode() string { return ModeDgram }

func (p *dgramProber) Close() error {
	p.mu.Lock()
	p.closed = true
	flows := p.flows
	p.flows = map[uint16]*dgramFlow{}
	p.mu.Unlock()
	for _, f := range flows {
		f.close()
	}
	return nil
}

func (p *dgramProber) ReleaseFlow(flow uint16) {
	p.mu.Lock()
	f := p.flows[flow]
	delete(p.flows, flow)
	p.mu.Unlock()
	if f != nil {
		f.close()
	}
}

func (p *dgramProber) flow(key uint16) (*dgramFlow, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, errors.New("prober closed")
	}
	if f := p.flows[key]; f != nil {
		return f, nil
	}
	f, err := newDgramFlow()
	if err != nil {
		return nil, err
	}
	p.flows[key] = f
	return f, nil
}

func newDgramFlow() (*dgramFlow, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*dgramFlow, error) { unix.Close(fd); return nil, err }
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1); err != nil {
		return fail(fmt.Errorf("IP_RECVERR: %w", err))
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{}); err != nil {
		return fail(err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return fail(err)
	}
	in4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		return fail(errors.New("unexpected socket address type"))
	}
	f := &dgramFlow{fd: fd, id: uint16(in4.Port), pend: newPendingTable(), done: make(chan struct{})}
	go f.recvLoop()
	return f, nil
}

func (f *dgramFlow) close() {
	if f.closed.Swap(true) {
		return
	}
	<-f.done
	unix.Close(f.fd)
}

func (f *dgramFlow) recvLoop() {
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
		// Error queue first: Time Exceeded / Unreachable arrive here.
		for {
			n, oobn, _, _, err := unix.Recvmsg(f.fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
			recvAt := time.Now()
			if err != nil {
				break
			}
			f.handleErr(buf[:n], oob[:oobn], recvAt)
		}
		for {
			n, from, err := unix.Recvfrom(f.fd, buf, unix.MSG_DONTWAIT)
			recvAt := time.Now()
			if err != nil {
				break
			}
			r, perr := ParseICMP(buf[:n])
			if perr != nil || r.Type != icmpEchoReply {
				continue
			}
			var src netip.Addr
			if in4, ok := from.(*unix.SockaddrInet4); ok {
				src = netip.AddrFrom4(in4.Addr)
			}
			f.pend.deliver(pendKey(f.id, r.Seq), recvAt, StatusReply, src, netip.Addr{})
		}
		if pfd[0].Revents&(unix.POLLNVAL|unix.POLLHUP) != 0 {
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func (f *dgramFlow) handleErr(data, oob []byte, recvAt time.Time) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, m := range msgs {
		if m.Header.Level != unix.SOL_IP || m.Header.Type != unix.IP_RECVERR {
			continue
		}
		const eeLen = 16 // struct sock_extended_err
		if len(m.Data) < eeLen+8 {
			continue
		}
		origin, typ := m.Data[4], m.Data[5]
		if origin != 2 /* SO_EE_ORIGIN_ICMP */ {
			continue
		}
		st, ok := statusForICMPType(typ)
		if !ok {
			continue
		}
		// struct sockaddr_in follows: family(2) port(2) addr(4)
		off := eeLen
		off4 := m.Data[off+4 : off+8]
		src, _ := netip.AddrFromSlice(off4)
		_, seq, ok := ParseEmbeddedEcho(data)
		if !ok {
			continue
		}
		f.pend.deliver(pendKey(f.id, seq), recvAt, st, src, netip.Addr{})
	}
}

func (p *dgramProber) Probe(ctx context.Context, req Request) Result {
	sa, ok := addr4(req.Dst)
	if !ok {
		return Result{Err: errors.New("datagram prober supports IPv4 destinations only")}
	}
	f, err := p.flow(req.Flow)
	if err != nil {
		return Result{Err: err}
	}
	// Build with the kernel-assigned id; the kernel recomputes the same checksum.
	pkt := BuildEcho(f.id, req.Seq, FlowChecksum(f.id))
	key := pendKey(f.id, req.Seq)
	w := &waiter{ch: make(chan Result, 1), dst: req.Dst.Unmap()}
	if !f.pend.add(key, w) {
		return Result{Err: errors.New("duplicate probe seq in flight")}
	}
	f.sendMu.Lock()
	err = unix.SetsockoptInt(f.fd, unix.IPPROTO_IP, unix.IP_TTL, req.TTL)
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

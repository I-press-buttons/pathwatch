//go:build windows

package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows prober using iphlpapi's IcmpSendEcho (blocking; each in-flight probe runs in its own
// goroutine). It needs no administrator rights and returns the responding hop. The ICMP
// identifier/sequence are not controllable, so Paris-style flow identity is best effort.
// NOTE: written against the documented ABI but not yet exercised on a real Windows host.

var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose    = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho = iphlpapi.NewProc("IcmpSendEcho")

	procIcmp6Create   = iphlpapi.NewProc("Icmp6CreateFile")
	procIcmp6SendEcho = iphlpapi.NewProc("Icmp6SendEcho2")
)

const (
	ipSuccess            = 0
	ipDestNetUnreachable = 11002
	ipDestHostUnreach    = 11003
	ipDestProtUnreach    = 11004
	ipDestPortUnreach    = 11005
	ipReqTimedOut        = 11010
	ipTTLExpiredTransit  = 11013
	ipTTLExpiredReassem  = 11014
)

type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

type winEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

type winProber struct {
	mu      sync.Mutex
	handle  syscall.Handle
	handle6 syscall.Handle // 0 when ICMPv6 is unavailable
}

// NewICMPProber creates the Windows IcmpSendEcho prober. The mode argument is ignored.
func NewICMPProber(mode string) (Prober, string, error) {
	h, _, err := procIcmpCreate.Call()
	if h == 0 || syscall.Handle(h) == syscall.InvalidHandle {
		return nil, ModeUnavailable, fmt.Errorf("IcmpCreateFile: %v", err)
	}
	p := &winProber{handle: syscall.Handle(h)}
	// IPv6 is optional: without it IPv6 destinations fail per probe with a clear error.
	if h6, _, _ := procIcmp6Create.Call(); h6 != 0 && syscall.Handle(h6) != syscall.InvalidHandle {
		p.handle6 = syscall.Handle(h6)
	}
	return p, ModeRaw, nil
}

func (p *winProber) Mode() string { return ModeRaw }

func (p *winProber) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.handle != 0 {
		procIcmpClose.Call(uintptr(p.handle))
		p.handle = 0
	}
	if p.handle6 != 0 {
		procIcmpClose.Call(uintptr(p.handle6))
		p.handle6 = 0
	}
	return nil
}

func (p *winProber) Probe(ctx context.Context, req Request) Result {
	dst := req.Dst.Unmap()
	if dst.Is6() {
		return p.probe6(ctx, req, dst)
	}
	if !dst.Is4() {
		return Result{Err: errors.New("invalid destination address")}
	}
	a4 := dst.As4()
	ipaddr := uint32(a4[0]) | uint32(a4[1])<<8 | uint32(a4[2])<<16 | uint32(a4[3])<<24
	payload := []byte("pathwatch probe!")
	opts := ipOptionInformation{TTL: uint8(req.TTL)}
	replySize := int(unsafe.Sizeof(winEchoReply{})) + len(payload) + 8 + 8
	reply := make([]byte, replySize)
	timeoutMS := uint32(req.Timeout / time.Millisecond)
	if timeoutMS == 0 {
		timeoutMS = 1
	}
	p.mu.Lock()
	h := p.handle
	p.mu.Unlock()
	if h == 0 {
		return Result{Err: errors.New("prober closed")}
	}
	type out struct {
		n   uintptr
		err error
		rtt time.Duration
	}
	ch := make(chan out, 1)
	go func() {
		start := time.Now()
		n, _, err := procIcmpSendEcho.Call(uintptr(h), uintptr(ipaddr),
			uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
			uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeoutMS))
		ch <- out{n: n, err: err, rtt: time.Since(start)}
	}()
	var o out
	select {
	case o = <-ch:
	case <-ctx.Done():
		return Result{Status: StatusTimeout}
	}
	if o.n == 0 {
		return Result{Status: StatusTimeout}
	}
	er := (*winEchoReply)(unsafe.Pointer(&reply[0]))
	addr := netip.AddrFrom4([4]byte{byte(er.Address), byte(er.Address >> 8), byte(er.Address >> 16), byte(er.Address >> 24)})
	switch er.Status {
	case ipSuccess:
		return Result{Status: StatusReply, Addr: addr, RTT: o.rtt}
	case ipTTLExpiredTransit, ipTTLExpiredReassem:
		return Result{Status: StatusTTLExceeded, Addr: addr, RTT: o.rtt}
	case ipDestNetUnreachable, ipDestHostUnreach, ipDestProtUnreach, ipDestPortUnreach:
		return Result{Status: StatusUnreachable, Addr: addr, RTT: o.rtt}
	}
	return Result{Status: StatusTimeout}
}

// ICMPv6 via Icmp6SendEcho2 (synchronous when no event is given). As for IPv4 the Echo
// identifier, sequence and checksum are chosen by the OS, so Paris flow identity is best effort.
// NOTE: written against the documented ABI but not yet exercised on a real Windows host.

const (
	sockaddrIn6Len   = 28
	icmp6ReplyHeader = 34 // ICMPV6_ECHO_REPLY: IPV6_ADDRESS_EX (26, packed) + Status + RoundTripTime
	afInet6          = 23
)

// parseWinReply6 decodes the fixed part of an ICMPV6_ECHO_REPLY. IPV6_ADDRESS_EX is packed:
// port(2) flowinfo(4) addr(16, network order) scope(4), followed by status(4) and rtt(4).
func parseWinReply6(b []byte) (addr netip.Addr, status uint32, ok bool) {
	if len(b) < icmp6ReplyHeader {
		return netip.Addr{}, 0, false
	}
	addr, _ = netip.AddrFromSlice(b[6:22])
	status = uint32(b[26]) | uint32(b[27])<<8 | uint32(b[28])<<16 | uint32(b[29])<<24
	return addr, status, true
}

func (p *winProber) probe6(ctx context.Context, req Request, dst netip.Addr) Result {
	p.mu.Lock()
	h := p.handle6
	p.mu.Unlock()
	if h == 0 {
		return Result{Err: errors.New("IPv6 ICMP is unavailable (Icmp6CreateFile failed)")}
	}
	var src, to [sockaddrIn6Len]byte
	src[0] = afInet6 // unspecified source: let the stack choose
	to[0] = afInet6
	a16 := dst.As16()
	copy(to[8:24], a16[:])
	payload := []byte("pathwatch probe!")
	opts := ipOptionInformation{TTL: uint8(req.TTL)}
	reply := make([]byte, icmp6ReplyHeader+len(payload)+8+64)
	timeoutMS := uint32(req.Timeout / time.Millisecond)
	if timeoutMS == 0 {
		timeoutMS = 1
	}
	type out struct {
		n   uintptr
		rtt time.Duration
	}
	ch := make(chan out, 1)
	go func() {
		start := time.Now()
		n, _, _ := procIcmp6SendEcho.Call(uintptr(h), 0, 0, 0,
			uintptr(unsafe.Pointer(&src[0])), uintptr(unsafe.Pointer(&to[0])),
			uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)),
			uintptr(unsafe.Pointer(&opts)),
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeoutMS))
		ch <- out{n: n, rtt: time.Since(start)}
	}()
	var o out
	select {
	case o = <-ch:
	case <-ctx.Done():
		return Result{Status: StatusTimeout}
	}
	if o.n == 0 {
		return Result{Status: StatusTimeout}
	}
	addr, status, ok := parseWinReply6(reply)
	if !ok {
		return Result{Status: StatusTimeout}
	}
	switch status {
	case ipSuccess:
		if addr != dst.WithZone("") {
			return Result{Status: StatusTimeout} // only the destination may answer an Echo
		}
		return Result{Status: StatusReply, Addr: addr, RTT: o.rtt}
	case ipTTLExpiredTransit, ipTTLExpiredReassem:
		return Result{Status: StatusTTLExceeded, Addr: addr, RTT: o.rtt}
	case ipDestNetUnreachable, ipDestHostUnreach, ipDestProtUnreach, ipDestPortUnreach:
		return Result{Status: StatusUnreachable, Addr: addr, RTT: o.rtt}
	}
	return Result{Status: StatusTimeout}
}

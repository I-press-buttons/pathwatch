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
	mu     sync.Mutex
	handle syscall.Handle
}

// NewICMPProber creates the Windows IcmpSendEcho prober. The mode argument is ignored.
func NewICMPProber(mode string) (Prober, string, error) {
	h, _, err := procIcmpCreate.Call()
	if h == 0 || syscall.Handle(h) == syscall.InvalidHandle {
		return nil, ModeUnavailable, fmt.Errorf("IcmpCreateFile: %v", err)
	}
	return &winProber{handle: syscall.Handle(h)}, ModeRaw, nil
}

func (p *winProber) Mode() string { return ModeRaw }

func (p *winProber) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.handle != 0 {
		procIcmpClose.Call(uintptr(p.handle))
		p.handle = 0
	}
	return nil
}

func (p *winProber) Probe(ctx context.Context, req Request) Result {
	dst := req.Dst.Unmap()
	if !dst.Is4() {
		return Result{Err: errors.New("windows prober supports IPv4 destinations only")}
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

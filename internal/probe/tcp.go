package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// TCPResult is the outcome of one TCP connect probe.
type TCPResult struct {
	Connect time.Duration
	Err     error
	OK      bool
}

// TCPConnect times a TCP three-way handshake to addr:port and closes the connection.
func TCPConnect(ctx context.Context, addr netip.Addr, port int, timeout time.Duration) TCPResult {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
	rtt := time.Since(start)
	if err != nil {
		return TCPResult{Err: simplifyNetErr(err)}
	}
	_ = c.Close()
	return TCPResult{Connect: rtt, OK: true}
}

// simplifyNetErr strips redundant "dial tcp ip:port:" prefixes and normalises timeouts.
func simplifyNetErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return errors.New("timeout")
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return errors.New(oe.Op + ": " + oe.Err.Error())
	}
	return err
}

package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// DNSResult is the outcome of one DNS resolver probe.
type DNSResult struct {
	RTT     time.Duration
	RCode   int
	Answers int
	Err     error // network failure, timeout or non-NOERROR rcode
	OK      bool
}

// DNSQuery asks server (host:port) for name/record directly over UDP, retrying over TCP
// when the answer is truncated, and times the exchange.
func DNSQuery(ctx context.Context, server, name, record string, timeout time.Duration) DNSResult {
	qtype := DNSTypeA
	if strings.EqualFold(record, "AAAA") {
		qtype = DNSTypeAAAA
	}
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	q, err := BuildDNSQuery(id, name, qtype)
	if err != nil {
		return DNSResult{Err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	msg, err := dnsExchangeUDP(ctx, server, q, id)
	if err == nil && msg.Truncated {
		msg, err = dnsExchangeTCP(ctx, server, q, id)
	}
	rtt := time.Since(start)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
			err = errors.New("timeout")
		}
		return DNSResult{Err: err}
	}
	res := DNSResult{RTT: rtt, RCode: msg.RCode, Answers: len(msg.Answers)}
	if msg.RCode != RCodeSuccess {
		res.Err = fmt.Errorf("rcode %s", RCodeName(msg.RCode))
		return res
	}
	res.OK = true
	return res
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func dnsExchangeUDP(ctx context.Context, server string, q []byte, id uint16) (*DNSMessage, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		m, perr := ParseDNSResponse(buf[:n])
		if perr != nil || m.ID != id || !m.Response {
			continue // ignore garbage and mismatched ids until the deadline
		}
		return m, nil
	}
}

func dnsExchangeTCP(ctx context.Context, server string, q []byte, id uint16) (*DNSMessage, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	out := make([]byte, 2, 2+len(q))
	binary.BigEndian.PutUint16(out, uint16(len(q)))
	out = append(out, q...)
	if _, err := c.Write(out); err != nil {
		return nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(c, lb[:]); err != nil {
		return nil, err
	}
	buf := make([]byte, binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	m, err := ParseDNSResponse(buf)
	if err != nil {
		return nil, err
	}
	if m.ID != id {
		return nil, errors.New("dns: mismatched response id")
	}
	return m, nil
}

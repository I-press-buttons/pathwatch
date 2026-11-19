package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"
)

// DNSResult is the outcome of one DNS resolver probe.
type DNSResult struct {
	RTT     time.Duration
	RCode   int
	Answers int
	Addrs   []netip.Addr // the A/AAAA addresses in the answer
	Err     error        // network failure, timeout, non-NOERROR rcode or a failed answer check
	OK      bool
}

// DNSCheck is what a DNS answer must satisfy beyond NOERROR (see config.DNSAnswerChecks).
type DNSCheck struct {
	Expect         []netip.Prefix
	ExpectNXDomain bool
	CompareWith    string // host:port; "" = no comparison
}

// WrongAnswerPrefix starts the error of a probe whose resolver answered, but wrongly.
const WrongAnswerPrefix = "wrong answer: "

func wrongAnswer(f string, a ...any) error {
	return errors.New(WrongAnswerPrefix + fmt.Sprintf(f, a...))
}

// maxListed bounds the addresses quoted in an error message.
const maxListed = 4

func listAddrs(as []netip.Addr) string {
	var parts []string
	for i, a := range as {
		if i == maxListed {
			parts = append(parts, fmt.Sprintf("+%d more", len(as)-maxListed))
			break
		}
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

func listPrefixes(ps []netip.Prefix) string {
	var parts []string
	for _, p := range ps {
		if p.Bits() == p.Addr().BitLen() {
			parts = append(parts, p.Addr().String())
		} else {
			parts = append(parts, p.String())
		}
	}
	return strings.Join(parts, ", ")
}

// CheckDNSAnswer applies the expect and expect_nxdomain checks to a result, returning it with
// OK and Err adjusted. Transport failures (no reply, timeout) are returned unchanged.
func CheckDNSAnswer(res DNSResult, c DNSCheck) DNSResult {
	if res.RTT == 0 && res.Err != nil && res.RCode == 0 {
		return res // no reply at all: nothing to check
	}
	if c.ExpectNXDomain {
		switch {
		case res.RCode == RCodeNXDomain:
			res.OK, res.Err = true, nil
		case res.RCode == RCodeSuccess && len(res.Addrs) > 0:
			res.OK, res.Err = false, wrongAnswer("a name that should not exist resolved to %s (NXDOMAIN rewritten)", listAddrs(res.Addrs))
		case res.RCode == RCodeSuccess:
			res.OK, res.Err = false, wrongAnswer("expected NXDOMAIN, got NOERROR with no address")
		}
		return res
	}
	if !res.OK || len(c.Expect) == 0 {
		return res
	}
	if len(res.Addrs) == 0 {
		res.OK, res.Err = false, wrongAnswer("no address in the answer (expected %s)", listPrefixes(c.Expect))
		return res
	}
	var bad []netip.Addr
	for _, a := range res.Addrs {
		in := false
		for _, p := range c.Expect {
			if p.Contains(a) {
				in = true
				break
			}
		}
		if !in {
			bad = append(bad, a)
		}
	}
	if len(bad) > 0 {
		res.OK, res.Err = false, wrongAnswer("unexpected %s (expected %s)", listAddrs(bad), listPrefixes(c.Expect))
	}
	return res
}

// CompareDNSAnswer fails res when ref (the same question asked of another resolver) returned
// addresses and none of them is in res. A failing or empty reference never fails res.
func CompareDNSAnswer(res, ref DNSResult, refServer string) DNSResult {
	if !res.OK || !ref.OK || len(res.Addrs) == 0 || len(ref.Addrs) == 0 {
		return res
	}
	for _, a := range res.Addrs {
		for _, b := range ref.Addrs {
			if a == b {
				return res
			}
		}
	}
	res.OK, res.Err = false, wrongAnswer("%s differs from %s (%s)", listAddrs(res.Addrs), refServer, listAddrs(ref.Addrs))
	return res
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
	for _, a := range msg.Answers {
		if a.Type == qtype && a.Addr.IsValid() {
			res.Addrs = append(res.Addrs, a.Addr.Unmap())
		}
	}
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

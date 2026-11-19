package probe

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestCheckDNSAnswerExpect(t *testing.T) {
	ok := DNSResult{RTT: time.Millisecond, OK: true, Addrs: addrs("10.0.0.5", "10.0.0.6")}
	if r := CheckDNSAnswer(ok, DNSCheck{Expect: prefixes("10.0.0.0/24")}); !r.OK || r.Err != nil {
		t.Fatalf("inside prefix should pass: %+v", r)
	}
	r := CheckDNSAnswer(ok, DNSCheck{Expect: prefixes("10.0.0.5/32")})
	if r.OK || r.Err == nil || !strings.HasPrefix(r.Err.Error(), WrongAnswerPrefix) || !strings.Contains(r.Err.Error(), "10.0.0.6") {
		t.Fatalf("address outside the expected set must fail: %+v", r)
	}
	empty := DNSResult{RTT: time.Millisecond, OK: true}
	if r := CheckDNSAnswer(empty, DNSCheck{Expect: prefixes("10.0.0.0/24")}); r.OK {
		t.Fatal("an empty answer must fail an expect check")
	}
	// a transport failure is left alone
	down := DNSResult{Err: errors.New("timeout")}
	if r := CheckDNSAnswer(down, DNSCheck{ExpectNXDomain: true}); r.OK || r.Err.Error() != "timeout" {
		t.Fatalf("timeout must stay a timeout: %+v", r)
	}
}

func TestCheckDNSAnswerNXDomain(t *testing.T) {
	nx := DNSResult{RTT: time.Millisecond, RCode: RCodeNXDomain, Err: errors.New("rcode NXDOMAIN")}
	if r := CheckDNSAnswer(nx, DNSCheck{ExpectNXDomain: true}); !r.OK || r.Err != nil {
		t.Fatalf("NXDOMAIN is success when expected: %+v", r)
	}
	hijack := DNSResult{RTT: time.Millisecond, OK: true, Addrs: addrs("198.51.100.7")}
	r := CheckDNSAnswer(hijack, DNSCheck{ExpectNXDomain: true})
	if r.OK || !strings.Contains(r.Err.Error(), "NXDOMAIN rewritten") {
		t.Fatalf("an answer for a missing name must fail: %+v", r)
	}
	sf := DNSResult{RTT: time.Millisecond, RCode: RCodeServFail, Err: errors.New("rcode SERVFAIL")}
	if r := CheckDNSAnswer(sf, DNSCheck{ExpectNXDomain: true}); r.OK || r.Err.Error() != "rcode SERVFAIL" {
		t.Fatalf("SERVFAIL stays a failure: %+v", r)
	}
}

func TestCompareDNSAnswer(t *testing.T) {
	res := DNSResult{OK: true, Addrs: addrs("1.2.3.4", "1.2.3.5")}
	if r := CompareDNSAnswer(res, DNSResult{OK: true, Addrs: addrs("1.2.3.5")}, "1.1.1.1:53"); !r.OK {
		t.Fatal("overlap passes")
	}
	r := CompareDNSAnswer(res, DNSResult{OK: true, Addrs: addrs("9.9.9.9")}, "1.1.1.1:53")
	if r.OK || !strings.Contains(r.Err.Error(), "differs from 1.1.1.1:53") {
		t.Fatalf("disjoint answers fail: %+v", r)
	}
	if r := CompareDNSAnswer(res, DNSResult{Err: errors.New("timeout")}, "1.1.1.1:53"); !r.OK {
		t.Fatal("a failing reference never fails the probe")
	}
}

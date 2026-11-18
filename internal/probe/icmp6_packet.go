package probe

import (
	"encoding/binary"
	"net/netip"
)

// ICMPv6 message types used by the prober (RFC 4443).
const (
	icmp6DestUnreach  = 1
	icmp6TimeExceeded = 3
	icmp6EchoRequest  = 128
	icmp6EchoReply    = 129

	ipv6HeaderBytes = 40
	ipv6NextICMPv6  = 58
)

// pseudoHeader6 returns the ICMPv6 checksum pseudo-header (RFC 8200 section 8.1) for a
// message of length n.
func pseudoHeader6(src, dst netip.Addr, n int) []byte {
	ph := make([]byte, 40)
	s, d := src.As16(), dst.As16()
	copy(ph[0:], s[:])
	copy(ph[16:], d[:])
	binary.BigEndian.PutUint32(ph[32:], uint32(n))
	ph[39] = ipv6NextICMPv6
	return ph
}

// Checksum6 computes the ICMPv6 checksum of msg (whose checksum field must be zero) for the
// given source and destination addresses.
func Checksum6(src, dst netip.Addr, msg []byte) uint16 {
	return ^fold(sum16(pseudoHeader6(src, dst, len(msg))) + sum16(msg))
}

// BuildEcho6 builds an ICMPv6 Echo Request with the given identifier and sequence number
// whose checksum, once computed over the IPv6 pseudo-header for src -> dst, equals want no
// matter what seq is (the Paris-traceroute flow identity, see BuildEcho). The kernel always
// computes the ICMPv6 checksum itself on both raw and datagram ICMPv6 sockets, so the value
// written to the checksum field is overwritten; it is the compensation word in the payload
// that makes the kernel's result constant. src must therefore be the address the kernel will
// use as the packet's source. want must be in 1..0xfffe (see FlowChecksum).
func BuildEcho6(id, seq, want uint16, src, dst netip.Addr) []byte {
	pkt := make([]byte, echoHeaderLen+echoPayloadLen)
	pkt[0] = icmp6EchoRequest
	binary.BigEndian.PutUint16(pkt[4:], id)
	binary.BigEndian.PutUint16(pkt[6:], seq)
	copy(pkt[echoHeaderLen+2:], "pathwatch path monitor probe....")
	s := fold(sum16(pseudoHeader6(src, dst, len(pkt))) + sum16(pkt))
	w := fold(uint32(^want) + uint32(^s))
	binary.BigEndian.PutUint16(pkt[echoHeaderLen:], w)
	binary.BigEndian.PutUint16(pkt[2:], want)
	return pkt
}

// ParseICMPv6 parses an ICMPv6 message (no IPv6 header; raw ICMPv6 sockets do not deliver
// it). For Time Exceeded and Destination Unreachable it extracts the identifier, sequence and
// destination of the embedded original Echo Request. Src is left for the caller to fill from
// the datagram's source address. Every offset is bounds-checked: the input is untrusted.
func ParseICMPv6(m []byte) (Reply, error) {
	if len(m) < echoHeaderLen {
		return Reply{}, errNotRelevant
	}
	r := Reply{Type: m[0], Code: m[1]}
	switch m[0] {
	case icmp6EchoReply:
		r.ID = binary.BigEndian.Uint16(m[4:])
		r.Seq = binary.BigEndian.Uint16(m[6:])
		return r, nil
	case icmp6TimeExceeded, icmp6DestUnreach:
		orig := m[echoHeaderLen:]
		// The quoted original packet is ours: a bare IPv6 header (we send no extension
		// headers) followed by the Echo Request header.
		if len(orig) < ipv6HeaderBytes+echoHeaderLen || orig[0]>>4 != 6 || orig[6] != ipv6NextICMPv6 {
			return r, errNotRelevant
		}
		if orig[ipv6HeaderBytes] != icmp6EchoRequest {
			return r, errNotRelevant
		}
		r.Dst, _ = netip.AddrFromSlice(orig[24:40])
		r.ID = binary.BigEndian.Uint16(orig[ipv6HeaderBytes+4:])
		r.Seq = binary.BigEndian.Uint16(orig[ipv6HeaderBytes+6:])
		return r, nil
	}
	return r, errNotRelevant
}

// ParseEmbeddedEcho6 parses the quoted original packet found in the IPV6_RECVERR error queue
// payload of datagram ICMPv6 sockets. Depending on the kernel it begins either at the original
// Echo Request header or at its IPv6 header; both are accepted.
func ParseEmbeddedEcho6(m []byte) (id, seq uint16, ok bool) {
	if len(m) >= ipv6HeaderBytes+echoHeaderLen && m[0]>>4 == 6 && m[6] == ipv6NextICMPv6 {
		m = m[ipv6HeaderBytes:]
	}
	if len(m) < echoHeaderLen || m[0] != icmp6EchoRequest {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(m[4:]), binary.BigEndian.Uint16(m[6:]), true
}

func statusForICMPv6Type(t uint8) (Status, bool) {
	switch t {
	case icmp6EchoReply:
		return StatusReply, true
	case icmp6TimeExceeded:
		return StatusTTLExceeded, true
	case icmp6DestUnreach:
		return StatusUnreachable, true
	}
	return StatusTimeout, false
}

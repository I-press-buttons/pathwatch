package probe

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// ICMPv4 message types used by the prober.
const (
	icmpEchoReply      = 0
	icmpDestUnreach    = 3
	icmpEchoRequest    = 8
	icmpTimeExceeded   = 11
	echoHeaderLen      = 8
	echoPayloadLen     = 32
	flowChecksumMin    = 1
	flowChecksumSpan   = 0xfffd
	ipv4MinHeaderBytes = 20
)

// Checksum computes the RFC 1071 Internet checksum of b.
func Checksum(b []byte) uint16 {
	return ^fold(sum16(b))
}

func sum16(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

func fold(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return uint16(s)
}

// FlowChecksum returns the constant ICMP checksum used for every probe of a flow.
// It is never 0 or 0xffff (both are special in one's complement arithmetic).
func FlowChecksum(flow uint16) uint16 {
	return uint16(flowChecksumMin + (uint32(flow)*40503+12345)%flowChecksumSpan)
}

// BuildEcho builds an ICMPv4 Echo Request with the given identifier and sequence
// number whose checksum field equals want, no matter what seq is. ECMP routers hash
// on the ICMP checksum as well as the identifier, so keeping both constant makes every
// probe of a flow follow the same path (Paris traceroute). The first two payload bytes
// are adjusted to compensate for the varying sequence number.
// want must be in 1..0xfffe (see FlowChecksum).
func BuildEcho(id, seq uint16, want uint16) []byte {
	pkt := make([]byte, echoHeaderLen+echoPayloadLen)
	pkt[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(pkt[4:], id)
	binary.BigEndian.PutUint16(pkt[6:], seq)
	// Payload: 2 compensation bytes, then a fixed pattern.
	copy(pkt[echoHeaderLen+2:], "pathwatch path monitor probe....")
	// Sum without the compensation word and without the checksum field.
	s := fold(sum16(pkt))
	// Need s + w = ^want (one's complement)  =>  w = ^want - s = ^want + ^s.
	w := fold(uint32(^want) + uint32(^s))
	binary.BigEndian.PutUint16(pkt[echoHeaderLen:], w)
	binary.BigEndian.PutUint16(pkt[2:], want)
	return pkt
}

// Reply is a parsed ICMP message relevant to the prober.
type Reply struct {
	Type    uint8
	Code    uint8
	Src     netip.Addr // IP source address (zero for datagram sockets where it is supplied separately)
	ID, Seq uint16     // of the original Echo Request
	Dst     netip.Addr // original destination (errors only)
}

var errNotRelevant = errors.New("not a relevant ICMP message")

// ParseIPv4ICMP parses a raw-socket packet: an IPv4 header followed by an ICMP message.
func ParseIPv4ICMP(b []byte) (Reply, error) {
	if len(b) < ipv4MinHeaderBytes || b[0]>>4 != 4 {
		return Reply{}, errNotRelevant
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < ipv4MinHeaderBytes || len(b) < ihl+echoHeaderLen || b[9] != 1 {
		return Reply{}, errNotRelevant
	}
	src, _ := netip.AddrFromSlice(b[12:16])
	r, err := ParseICMP(b[ihl:])
	r.Src = src
	return r, err
}

// ParseICMP parses an ICMP message (no IP header). For Time Exceeded and Destination
// Unreachable it extracts the identifier and sequence of the embedded original Echo Request.
func ParseICMP(m []byte) (Reply, error) {
	if len(m) < echoHeaderLen {
		return Reply{}, errNotRelevant
	}
	r := Reply{Type: m[0], Code: m[1]}
	switch m[0] {
	case icmpEchoReply:
		r.ID = binary.BigEndian.Uint16(m[4:])
		r.Seq = binary.BigEndian.Uint16(m[6:])
		return r, nil
	case icmpTimeExceeded, icmpDestUnreach:
		orig := m[echoHeaderLen:]
		if len(orig) < ipv4MinHeaderBytes || orig[0]>>4 != 4 || orig[9] != 1 {
			return r, errNotRelevant
		}
		ihl := int(orig[0]&0x0f) * 4
		if ihl < ipv4MinHeaderBytes || len(orig) < ihl+echoHeaderLen || orig[ihl] != icmpEchoRequest {
			return r, errNotRelevant
		}
		r.Dst, _ = netip.AddrFromSlice(orig[16:20])
		r.ID = binary.BigEndian.Uint16(orig[ihl+4:])
		r.Seq = binary.BigEndian.Uint16(orig[ihl+6:])
		return r, nil
	}
	return r, errNotRelevant
}

// ParseEmbeddedEcho parses an original Echo Request header (no IP header), as found in
// the IP_RECVERR error queue payload of datagram ICMP sockets.
func ParseEmbeddedEcho(m []byte) (id, seq uint16, ok bool) {
	if len(m) < echoHeaderLen || m[0] != icmpEchoRequest {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(m[4:]), binary.BigEndian.Uint16(m[6:]), true
}

func statusForICMPType(t uint8) (Status, bool) {
	switch t {
	case icmpEchoReply:
		return StatusReply, true
	case icmpTimeExceeded:
		return StatusTTLExceeded, true
	case icmpDestUnreach:
		return StatusUnreachable, true
	}
	return StatusTimeout, false
}

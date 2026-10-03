package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// DNS record types and classes supported by the minimal codec.
const (
	DNSTypeA     uint16 = 1
	DNSTypeAAAA  uint16 = 28
	dnsClassIN   uint16 = 1
	dnsFlagRD           = 0x0100
	dnsFlagTC           = 0x0200
	dnsFlagQR           = 0x8000
	dnsHeaderLen        = 12
)

// DNS response codes.
const (
	RCodeSuccess  = 0
	RCodeFormErr  = 1
	RCodeServFail = 2
	RCodeNXDomain = 3
	RCodeNotImp   = 4
	RCodeRefused  = 5
)

// RCodeName returns the mnemonic for an rcode.
func RCodeName(rc int) string {
	switch rc {
	case RCodeSuccess:
		return "NOERROR"
	case RCodeFormErr:
		return "FORMERR"
	case RCodeServFail:
		return "SERVFAIL"
	case RCodeNXDomain:
		return "NXDOMAIN"
	case RCodeNotImp:
		return "NOTIMP"
	case RCodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", rc)
}

// DNSAnswer is one A/AAAA answer record.
type DNSAnswer struct {
	Name string
	Type uint16
	TTL  uint32
	Addr netip.Addr
}

// DNSMessage is a decoded DNS response.
type DNSMessage struct {
	ID        uint16
	Response  bool
	Truncated bool
	RCode     int
	Questions int
	Answers   []DNSAnswer // only A and AAAA records are decoded; others are skipped
	AnswerRRs int         // total answer RRs on the wire
}

// BuildDNSQuery encodes a standard recursive query for one name and type (A or AAAA).
func BuildDNSQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return nil, errors.New("dns: invalid name length")
	}
	b := make([]byte, dnsHeaderLen, dnsHeaderLen+len(name)+6)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], dnsFlagRD)
	binary.BigEndian.PutUint16(b[4:], 1) // QDCOUNT
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("dns: invalid label %q", label)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, dnsClassIN)
	return b, nil
}

// ParseDNSResponse decodes a DNS message, following name compression pointers safely.
func ParseDNSResponse(b []byte) (*DNSMessage, error) {
	if len(b) < dnsHeaderLen {
		return nil, errors.New("dns: short message")
	}
	flags := binary.BigEndian.Uint16(b[2:])
	m := &DNSMessage{
		ID:        binary.BigEndian.Uint16(b[0:]),
		Response:  flags&dnsFlagQR != 0,
		Truncated: flags&dnsFlagTC != 0,
		RCode:     int(flags & 0x000f),
		Questions: int(binary.BigEndian.Uint16(b[4:])),
	}
	an := int(binary.BigEndian.Uint16(b[6:]))
	m.AnswerRRs = an
	off := dnsHeaderLen
	for i := 0; i < m.Questions; i++ {
		_, n, err := dnsName(b, off)
		if err != nil {
			return nil, err
		}
		off = n + 4
		if off > len(b) {
			return nil, errors.New("dns: truncated question")
		}
	}
	for i := 0; i < an; i++ {
		name, n, err := dnsName(b, off)
		if err != nil {
			return nil, err
		}
		off = n
		if off+10 > len(b) {
			return nil, errors.New("dns: truncated record header")
		}
		typ := binary.BigEndian.Uint16(b[off:])
		class := binary.BigEndian.Uint16(b[off+2:])
		ttl := binary.BigEndian.Uint32(b[off+4:])
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if off+rdlen > len(b) {
			return nil, errors.New("dns: truncated rdata")
		}
		rd := b[off : off+rdlen]
		off += rdlen
		if class != dnsClassIN {
			continue
		}
		switch {
		case typ == DNSTypeA && rdlen == 4:
			m.Answers = append(m.Answers, DNSAnswer{Name: name, Type: typ, TTL: ttl, Addr: netip.AddrFrom4([4]byte(rd))})
		case typ == DNSTypeAAAA && rdlen == 16:
			m.Answers = append(m.Answers, DNSAnswer{Name: name, Type: typ, TTL: ttl, Addr: netip.AddrFrom16([16]byte(rd))})
		}
	}
	return m, nil
}

// dnsName decodes a possibly compressed name starting at off and returns the name and the
// offset just after the name's first encoding (not after any pointer target).
func dnsName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	next := -1
	hops := 0
	for {
		if off >= len(b) {
			return "", 0, errors.New("dns: name out of bounds")
		}
		c := int(b[off])
		switch c & 0xc0 {
		case 0x00:
			if c == 0 {
				if next < 0 {
					next = off + 1
				}
				return sb.String(), next, nil
			}
			if off+1+c > len(b) {
				return "", 0, errors.New("dns: label out of bounds")
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.Write(b[off+1 : off+1+c])
			if sb.Len() > 255 {
				return "", 0, errors.New("dns: name too long")
			}
			off += 1 + c
		case 0xc0:
			if off+1 >= len(b) {
				return "", 0, errors.New("dns: truncated pointer")
			}
			ptr := (c&0x3f)<<8 | int(b[off+1])
			if next < 0 {
				next = off + 2
			}
			hops++
			if hops > 10 || ptr >= len(b) {
				return "", 0, errors.New("dns: bad compression pointer")
			}
			off = ptr
		default:
			return "", 0, errors.New("dns: unsupported label type")
		}
	}
}

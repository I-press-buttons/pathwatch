package selfmon

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// ntpEpochOffset is the seconds between 1900-01-01 (NTP) and 1970-01-01 (Unix).
const ntpEpochOffset = 2208988800

func ntpTime(b []byte) time.Time {
	sec := binary.BigEndian.Uint32(b[0:4])
	frac := binary.BigEndian.Uint32(b[4:8])
	ns := (int64(frac) * 1e9) >> 32
	return time.Unix(int64(sec)-ntpEpochOffset, ns)
}

func putNTPTime(b []byte, t time.Time) {
	sec := uint32(t.Unix() + ntpEpochOffset)
	frac := uint32((int64(t.Nanosecond()) << 32) / 1e9)
	binary.BigEndian.PutUint32(b[0:4], sec)
	binary.BigEndian.PutUint32(b[4:8], frac)
}

// clockOffset asks an NTP server (SNTPv4, RFC 4330) for the time and returns how far this
// machine's clock is from it (positive = this clock is behind) and the round trip.
func clockOffset(ctx context.Context, server string) (offset, rtt time.Duration, err error) {
	if _, _, e := net.SplitHostPort(server); e != nil {
		server = net.JoinHostPort(server, "123")
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	req := make([]byte, 48)
	req[0] = 0x23 // LI 0, version 4, mode 3 (client)
	t1 := time.Now()
	putNTPTime(req[40:48], t1) // transmit timestamp: the server echoes it as the originate timestamp
	if _, err := c.Write(req); err != nil {
		return 0, 0, err
	}
	resp := make([]byte, 48)
	for {
		n, err := c.Read(resp)
		if err != nil {
			return 0, 0, err
		}
		t4 := time.Now()
		if n < 48 || resp[0]&0x07 != 4 || string(resp[24:32]) != string(req[40:48]) {
			continue // not a server reply to this request
		}
		if resp[1] == 0 || resp[1] > 15 {
			return 0, 0, errors.New("the NTP server is not synchronized")
		}
		t2, t3 := ntpTime(resp[32:40]), ntpTime(resp[40:48])
		offset = (t2.Sub(t1) + t3.Sub(t4)) / 2
		rtt = t4.Sub(t1) - t3.Sub(t2)
		return offset, rtt, nil
	}
}

package selfmon

import (
	"context"
	"net"
	"testing"
	"time"
)

// a fake NTP server whose clock runs 3 seconds ahead
func TestClockOffsetSNTP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback UDP:", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 48 {
				continue
			}
			resp := make([]byte, 48)
			resp[0] = 0x24 // version 4, mode 4 (server)
			resp[1] = 2    // stratum
			copy(resp[24:32], buf[40:48])
			now := time.Now().Add(3 * time.Second)
			putNTPTime(resp[32:40], now)
			putNTPTime(resp[40:48], now)
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	off, rtt, err := clockOffset(ctx, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if off < 2900*time.Millisecond || off > 3100*time.Millisecond {
		t.Fatalf("offset %v, want about 3s", off)
	}
	if rtt < 0 || rtt > time.Second {
		t.Fatalf("rtt %v", rtt)
	}
}

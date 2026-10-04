package store

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"path/filepath"
	"testing"
	"time"
)

func benchStore(b *testing.B, now time.Time) *Store {
	b.Helper()
	s, err := Open(filepath.Join(b.TempDir(), "b.db"), Options{
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		NoBackground:  true,
		FlushInterval: 20 * time.Millisecond,
		Now:           func() time.Time { return now },
	})
	if err != nil {
		b.Fatal(err)
	}
	return s
}

// BenchmarkRecordRound measures queueing one 15-hop round and committing it (a Sync every
// 2000 rounds keeps the queue from dropping writes).
func BenchmarkRecordRound(b *testing.B) {
	t0 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s := benchStore(b, t0)
	defer s.Close()
	hops := make([]Hop, 15)
	for i := range hops {
		hops[i] = Hop{TTL: i + 1, Status: 2, RTT: time.Duration(i+1) * time.Millisecond, Resp: 1}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.RecordRound(Round{TargetID: int64(i%10 + 1), TS: t0.Add(time.Duration(i) * time.Second), PathID: 1, Hops: hops})
		if i%2000 == 1999 {
			if err := s.Sync(); err != nil {
				b.Fatal(err)
			}
		}
	}
	if err := s.Sync(); err != nil {
		b.Fatal(err)
	}
	b.StopTimer()
	if s.Dropped() != 0 {
		b.Fatalf("dropped %d writes", s.Dropped())
	}
}

// BenchmarkBackfill measures rebuilding the rollups of 10 targets x 15 hops (plus an HTTP and
// a TCP probe each) from 3 h of raw data, as after a long outage of the rollups.
func BenchmarkBackfill(b *testing.B) {
	t0 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	s := benchStore(b, t0.Add(3*time.Hour+30*time.Second))
	defer s.Close()
	const targets, hours = 10, 3
	hops := make([]Hop, 15)
	rng := rand.New(rand.NewSource(2))
	for tg := 0; tg < targets; tg++ {
		tr, err := s.SyncConfigTarget(fmt.Sprintf("t%d", tg), "h")
		if err != nil {
			b.Fatal(err)
		}
		pid, _ := s.NewPath(tr.ID, "1.1.1.1", len(hops), t0)
		hid, _ := s.EnsureProbe(tr.ID, "http", "http:x", "x")
		tid, _ := s.EnsureProbe(tr.ID, "tcp", "tcp:x", "x")
		for i := 0; i < hours*1800; i++ {
			ts := t0.Add(time.Duration(i) * 2 * time.Second)
			for h := range hops {
				hops[h] = Hop{TTL: h + 1, Status: 2, RTT: time.Duration(float64(h+1) * (0.85 + 0.3*rng.Float64()) * float64(time.Millisecond)), Resp: 1}
			}
			s.RecordRound(Round{TargetID: tr.ID, TS: ts, PathID: pid, Hops: hops})
			if i%15 == 0 {
				s.RecordHTTP(HTTPSample{ProbeID: hid, TS: ts, Status: 200, Total: 90 * time.Millisecond, TTFB: 40 * time.Millisecond})
				s.RecordTCP(TCPSample{ProbeID: tid, TS: ts, Connect: 20 * time.Millisecond})
			}
			if i%1000 == 999 {
				if err := s.Sync(); err != nil {
					b.Fatal(err)
				}
			}
		}
		if err := s.Sync(); err != nil {
			b.Fatal(err)
		}
	}
	if s.Dropped() != 0 {
		b.Fatalf("dropped %d writes", s.Dropped())
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s.agg = NewAggregator()
		for _, tbl := range []string{"icmp_rollup_1m", "icmp_rollup_1h", "probe_rollup_1m", "probe_rollup_1h"} {
			if _, err := s.wdb.Exec(`DELETE FROM ` + tbl); err != nil {
				b.Fatal(err)
			}
		}
		s.hacc.reset() // the deletes above bypass the writer
		b.StartTimer()
		if err := s.Backfill(context.Background()); err != nil {
			b.Fatal(err)
		}
		if err := s.Sync(); err != nil {
			b.Fatal(err)
		}
	}
}

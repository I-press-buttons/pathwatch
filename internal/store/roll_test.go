package store

import (
	"math"
	"math/rand"
	"testing"
)

// ---------------------------------------------------------------------------
// merging stored rows without allocating

func randHist(rng *rand.Rand, n int) *Hist {
	h := &Hist{}
	for i := 0; i < n; i++ {
		h.Add(math.Exp(rng.NormFloat64()*1.5 + 2))
	}
	return h
}

func TestHistMergeEncoded(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	dst, want := randHist(rng, 50), &Hist{}
	want.Merge(dst)
	for i := 0; i < 200; i++ {
		src := randHist(rng, rng.Intn(80)) // includes empty histograms (nil blob)
		blob := src.Encode()
		if err := dst.MergeEncoded(blob); err != nil {
			t.Fatal(err)
		}
		dec, err := DecodeHist(blob)
		if err != nil {
			t.Fatal(err)
		}
		want.Merge(dec)
		if *dst != *want {
			t.Fatalf("round %d: MergeEncoded differs from DecodeHist+Merge", i)
		}
	}
}

func TestHistMergeEncodedBadBlobs(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	good := randHist(rng, 40).Encode()
	bad := map[string][]byte{
		"header only continuation": {0xff, 0xff, 0xff},
		"too many buckets":         {0xc9, 0x01}, // 201 non-zero buckets
		"truncated count":          good[:len(good)-1],
		"truncated delta":          good[:2],
		"index out of range":       {1, 0xc8, 0x01, 1}, // delta 200
		"later index out of range": {2, 5, 1, 0xc8, 0x01, 1},
	}
	for name, blob := range bad {
		t.Run(name, func(t *testing.T) {
			h := randHist(rng, 20)
			before := *h
			err := h.MergeEncoded(blob)
			if err == nil {
				t.Fatal("no error for a malformed blob")
			}
			if _, derr := DecodeHist(blob); derr == nil {
				t.Fatal("DecodeHist accepts what MergeEncoded rejects")
			}
			if *h != before {
				t.Fatal("a rejected blob changed the histogram")
			}
		})
	}
	// an empty blob adds nothing and is not an error
	h := randHist(rng, 20)
	before := *h
	if err := h.MergeEncoded(nil); err != nil || *h != before {
		t.Fatalf("empty blob: %v", err)
	}
}

func TestHistMergeEncodedDoesNotAllocate(t *testing.T) {
	blob := randHist(rand.New(rand.NewSource(3)), 100).Encode()
	h := &Hist{}
	if n := testing.AllocsPerRun(100, func() { _ = h.MergeEncoded(blob) }); n != 0 {
		t.Fatalf("MergeEncoded allocates %v times", n)
	}
}

// sameRollExact compares every field of two rolls, treating a missing histogram as empty.
func sameRollExact(a, b *Roll) bool {
	if a.N != b.N || a.Lost != b.Lost || a.Min != b.Min || a.Max != b.Max || a.Sum != b.Sum || a.JitSum != b.JitSum || a.JitN != b.JitN {
		return false
	}
	return histOf(a.Hist) == histOf(b.Hist)
}

func histOf(h *Hist) Hist {
	if h == nil {
		return Hist{}
	}
	return *h
}

// TestRollMergeRowMatchesMerge checks the allocation-free row merge against the way rows were
// merged before: r.Merge(rollFromRow(...)).
func TestRollMergeRowMatchesMerge(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	for seq := 0; seq < 300; seq++ {
		var old, got Roll
		for i := 0; i < 1+rng.Intn(12); i++ {
			n := int64(rng.Intn(40))
			lost := int64(0)
			if n > 0 {
				lost = int64(rng.Intn(int(n) + 1))
			}
			if rng.Intn(6) == 0 {
				lost = n // every probe lost: NULL aggregates stored as 0
			}
			mn, avg, mx, jit := 0.0, 0.0, 0.0, 0.0
			var blob []byte
			if n-lost > 0 {
				mn = rng.Float64() * 20
				avg = mn + rng.Float64()*20
				mx = avg + rng.Float64()*20
				jit = rng.Float64() * 3
				blob = randHist(rng, int(n-lost)).Encode()
			}
			switch rng.Intn(10) {
			case 0:
				blob = []byte{0xff, 0xff, 0xff} // malformed
			case 1:
				blob = nil
			}
			old.Merge(rollFromRow(n, lost, mn, avg, mx, jit, blob))
			got.mergeRow(n, lost, mn, avg, mx, jit, blob)
			if !sameRollExact(&old, &got) {
				t.Fatalf("seq %d row %d: mergeRow %+v differs from Merge(rollFromRow) %+v", seq, i, got, old)
			}
		}
	}
	// no hist: the same statistics, quantiles unknown
	var withHist, noHist Roll
	blob := randHist(rng, 30).Encode()
	withHist.mergeRow(30, 0, 1, 2, 9, 0.5, blob)
	noHist.mergeRow(30, 0, 1, 2, 9, 0.5, nil)
	if withHist.N != noHist.N || withHist.Sum != noHist.Sum || withHist.JitSum != noHist.JitSum {
		t.Fatal("hist changes the statistics")
	}
	if _, ok := noHist.Quantile(0.95); ok {
		t.Fatal("quantile without a histogram")
	}
	if n := testing.AllocsPerRun(100, func() { withHist.mergeRow(30, 1, 1, 2, 9, 0.5, blob) }); n != 0 {
		t.Fatalf("mergeRow allocates %v times", n)
	}
}

func TestProbeRollMergeRowMatchesMerge(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	same := func(a, b *ProbeRoll) bool {
		x, y := *a, *b
		x.Hist, y.Hist = nil, nil
		return x == y && histOf(a.Hist) == histOf(b.Hist)
	}
	for seq := 0; seq < 300; seq++ {
		var old, got ProbeRoll
		for i := 0; i < 1+rng.Intn(12); i++ {
			n := int64(rng.Intn(40))
			errs := int64(0)
			if n > 0 {
				errs = int64(rng.Intn(int(n) + 1))
			}
			var dns, conn, tls, ttfb, tr, tmin, tavg, tmax float64
			var blob []byte
			if n-errs > 0 {
				dns, conn, tls, ttfb, tr = rng.Float64(), rng.Float64()*5, rng.Float64()*9, rng.Float64()*20, rng.Float64()
				tmin = rng.Float64() * 30
				tavg, tmax = tmin+rng.Float64()*30, tmin+60
				blob = randHist(rng, int(n-errs)).Encode()
			}
			cert := int64(0)
			if rng.Intn(3) == 0 {
				cert = int64(rng.Intn(1e9)) + 1
			}
			if rng.Intn(10) == 0 {
				blob = []byte{0xff}
			}
			old.Merge(probeRollFromRow(n, errs, dns, conn, tls, ttfb, tr, tmin, tavg, tmax, blob, cert))
			got.mergeRow(n, errs, dns, conn, tls, ttfb, tr, tmin, tavg, tmax, blob, cert)
			if !same(&old, &got) {
				t.Fatalf("seq %d row %d: mergeRow %+v differs from Merge(probeRollFromRow) %+v", seq, i, got, old)
			}
		}
	}
}

func TestAddStatsMatchesAddReply(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	var a, b Roll
	var pa, pb ProbeRoll
	prev, have := 0.0, false
	for i := 0; i < 500; i++ {
		if rng.Intn(5) == 0 {
			a.AddLoss()
			b.AddLoss()
			pa.AddError()
			pb.AddError()
			continue
		}
		v := rng.Float64() * 50
		a.AddReply(v, prev, have)
		b.addStats(v, prev, have)
		pa.AddOK(1, 2, 3, 4, 5, v)
		pb.addOKStats(1, 2, 3, 4, 5, v)
		prev, have = v, true
	}
	if a.Hist == nil || b.Hist != nil || pb.Hist != nil {
		t.Fatal("addStats must not build histograms")
	}
	a.Hist, pa.Hist = nil, nil
	if a != b || pa != pb {
		t.Fatalf("statistics differ: %+v vs %+v", a, b)
	}
}

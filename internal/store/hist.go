package store

import (
	"encoding/binary"
	"errors"
	"math"
)

// Histogram parameters: fixed log-scale buckets from HistMinMS growing by HistGrowth per bucket.
// With growth 1.08 the relative error of a reported quantile is at most ~4%.
const (
	HistBuckets = 200
	HistMinMS   = 0.01
	HistGrowth  = 1.08
)

var logGrowth = math.Log(HistGrowth)

// Hist is a fixed log-scale latency histogram. Histograms with identical parameters merge by
// adding counts, so percentiles stay correct across rollups (never average percentiles).
type Hist struct {
	C [HistBuckets]uint32
	N uint32
}

func histIndex(ms float64) int {
	if ms <= HistMinMS {
		return 0
	}
	i := int(math.Log(ms/HistMinMS) / logGrowth)
	if i >= HistBuckets {
		return HistBuckets - 1
	}
	return i
}

// histLower is the lower bound (ms) of bucket i.
func histLower(i int) float64 { return HistMinMS * math.Pow(HistGrowth, float64(i)) }

// Add records one latency in milliseconds.
func (h *Hist) Add(ms float64) {
	h.C[histIndex(ms)]++
	h.N++
}

// Merge adds o's counts into h.
func (h *Hist) Merge(o *Hist) {
	if o == nil {
		return
	}
	for i, c := range o.C {
		h.C[i] += c
	}
	h.N += o.N
}

// Quantile returns the q-quantile (0..1) in milliseconds, using the geometric middle of the
// containing bucket clamped to [min, max] (the exact extremes tracked alongside). ok is false
// for an empty histogram.
func (h *Hist) Quantile(q, min, max float64) (float64, bool) {
	if h == nil || h.N == 0 {
		return 0, false
	}
	if q < 0 {
		q = 0
	}
	if q > 1 {
		q = 1
	}
	target := uint32(math.Ceil(q * float64(h.N)))
	if target == 0 {
		target = 1
	}
	var cum uint32
	for i, c := range h.C {
		cum += c
		if c > 0 && cum >= target {
			v := math.Sqrt(histLower(i) * histLower(i+1))
			if min > 0 && v < min {
				v = min
			}
			if max > 0 && v > max {
				v = max
			}
			return v, true
		}
	}
	return max, true
}

// Encode serialises the histogram sparsely: uvarint(nonzero buckets) then
// (uvarint index delta, uvarint count) pairs.
func (h *Hist) Encode() []byte {
	if h == nil || h.N == 0 {
		return nil
	}
	nz := 0
	for _, c := range h.C {
		if c != 0 {
			nz++
		}
	}
	b := make([]byte, 0, 1+nz*3)
	b = binary.AppendUvarint(b, uint64(nz))
	prev := 0
	for i, c := range h.C {
		if c == 0 {
			continue
		}
		b = binary.AppendUvarint(b, uint64(i-prev))
		b = binary.AppendUvarint(b, uint64(c))
		prev = i
	}
	return b
}

var (
	errHistHeader    = errors.New("hist: bad header")
	errHistTruncated = errors.New("hist: truncated")
	errHistRange     = errors.New("hist: index out of range")
)

// walkEncoded validates an Encode blob and calls add (when not nil) with the index and count
// of every stored bucket. An empty blob has no buckets.
func walkEncoded(b []byte, add func(i int, c uint32)) error {
	if len(b) == 0 {
		return nil
	}
	nz, n := binary.Uvarint(b)
	if n <= 0 || nz > HistBuckets {
		return errHistHeader
	}
	b = b[n:]
	idx := 0
	for i := uint64(0); i < nz; i++ {
		d, n1 := binary.Uvarint(b)
		if n1 <= 0 {
			return errHistTruncated
		}
		b = b[n1:]
		c, n2 := binary.Uvarint(b)
		if n2 <= 0 {
			return errHistTruncated
		}
		b = b[n2:]
		idx += int(d)
		if idx < 0 || idx >= HistBuckets {
			return errHistRange
		}
		if add != nil {
			add(idx, uint32(c))
		}
	}
	return nil
}

// MergeEncoded adds the counts of an Encode blob into h without building an intermediate
// histogram. A malformed blob is rejected as DecodeHist rejects it and leaves h unchanged.
func (h *Hist) MergeEncoded(b []byte) error {
	if err := walkEncoded(b, nil); err != nil {
		return err
	}
	return walkEncoded(b, func(i int, c uint32) {
		h.C[i] += c
		h.N += c
	})
}

// DecodeHist parses Encode output. An empty blob yields an empty histogram.
func DecodeHist(b []byte) (*Hist, error) {
	h := &Hist{}
	if err := h.MergeEncoded(b); err != nil {
		return nil, err
	}
	return h, nil
}

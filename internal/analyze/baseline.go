package analyze

import (
	"math"
	"sort"
	"sync"
)

// BandTracker keeps a rolling median and MAD of per-minute latency averages per key and derives
// the upper edge of the "normal" latency band. It stays silent (no band) until it holds
// MinSamples minutes (cold start). Callers freeze a baseline simply by not observing minutes in
// which the metric was degraded.
type BandTracker struct {
	Window     int     // number of minutes kept (default 1440 = 24h)
	MinSamples int     // minutes required before a band is produced (default 30)
	MADK       float64 // band width in robust sigmas (default 4)
	MinDelta   float64 // absolute floor above the median, ms (default 10)
	MinRatio   float64 // relative floor above the median (default 0.5 = +50%)

	mu sync.Mutex
	m  map[string][]float64
}

// NewBandTracker returns a tracker with default parameters.
func NewBandTracker() *BandTracker {
	return &BandTracker{Window: 1440, MinSamples: 30, MADK: 4, MinDelta: 10, MinRatio: 0.5, m: map[string][]float64{}}
}

// Observe records one per-minute average (ms) for key.
func (b *BandTracker) Observe(key string, avgMs float64) {
	if math.IsNaN(avgMs) || avgMs < 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := append(b.m[key], avgMs)
	if w := b.Window; w > 0 && len(s) > w {
		s = s[len(s)-w:]
	}
	b.m[key] = s
}

// Band returns the median and the upper band edge for key. ok is false during cold start.
func (b *BandTracker) Band(key string) (median, upper float64, ok bool) {
	b.mu.Lock()
	s := append([]float64(nil), b.m[key]...)
	b.mu.Unlock()
	if len(s) < b.MinSamples || len(s) == 0 {
		return 0, 0, false
	}
	median = medianOf(s)
	dev := make([]float64, len(s))
	for i, v := range s {
		dev[i] = math.Abs(v - median)
	}
	mad := medianOf(dev)
	width := b.MADK * 1.4826 * mad
	if f := b.MinRatio * median; f > width {
		width = f
	}
	if width < b.MinDelta {
		width = b.MinDelta
	}
	return median, median + width, true
}

// Len returns the number of samples held for key.
func (b *BandTracker) Len(key string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.m[key])
}

func medianOf(s []float64) float64 {
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

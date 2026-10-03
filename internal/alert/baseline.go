package alert

import (
	"encoding/json"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/store"
)

// Baseline is a robust summary of a probe metric: the rolling median and the median absolute
// deviation (MAD) of per-minute averages over the baseline window. It is not Ready until it
// holds at least min_baseline of data (cold start: latency rules stay inactive).
type Baseline struct {
	Median  float64
	MAD     float64
	Samples int           // minutes (or hours, for very long windows) of data it is based on
	Covers  time.Duration // data span it is based on
	Ready   bool
}

// baselineRefresh is how often a cached baseline is recomputed from the rollups.
const baselineRefresh = 5 * time.Minute

// maxMinuteWindow is the longest baseline window read from the 1-minute rollups; longer windows
// use the hourly rollups.
const maxMinuteWindow = 7 * 24 * time.Hour

type baseKey struct {
	probe  int64
	metric string
	window time.Duration
	minAge time.Duration
}

type baseEntry struct {
	b        Baseline
	computed time.Time
	loading  bool
}

// baselines keeps cached medians/MADs per (probe, metric). They are recomputed from the store's
// rollups every few minutes rather than per minute, and never while the rule that uses them is
// pending or firing (the baseline is frozen, so a long incident cannot become the new normal).
type baselines struct {
	st    *store.Store
	now   func() time.Time
	async bool

	mu sync.Mutex
	m  map[baseKey]*baseEntry
}

func newBaselines(st *store.Store, now func() time.Time, async bool) *baselines {
	return &baselines{st: st, now: now, async: async, m: map[baseKey]*baseEntry{}}
}

// get returns the cached baseline of a probe metric. frozen = the dependent rule is pending or
// firing: the cached value is returned unchanged. lag keeps the most recent minutes (those the
// rule is judging right now) out of the baseline.
func (c *baselines) get(probe int64, metric string, window, minBaseline, lag time.Duration, frozen bool) Baseline {
	k := baseKey{probe, metric, window, minBaseline}
	c.mu.Lock()
	e := c.m[k]
	now := c.now()
	stale := e == nil || now.Sub(e.computed) >= baselineRefresh
	if e == nil {
		e = &baseEntry{}
		c.m[k] = e
	}
	if frozen && e.b.Ready {
		b := e.b
		c.mu.Unlock()
		return b
	}
	if !stale || e.loading {
		b := e.b
		c.mu.Unlock()
		return b
	}
	if c.async {
		e.loading = true
		c.mu.Unlock()
		go func() {
			b := c.compute(probe, metric, window, minBaseline, lag, now)
			c.mu.Lock()
			e.b, e.computed, e.loading = b, now, false
			c.mu.Unlock()
		}()
		c.mu.Lock()
		b := e.b
		c.mu.Unlock()
		return b
	}
	c.mu.Unlock()
	b := c.compute(probe, metric, window, minBaseline, lag, now)
	c.mu.Lock()
	e.b, e.computed = b, now
	c.mu.Unlock()
	return b
}

// forget drops cached baselines of a probe (it was removed).
func (c *baselines) forget(probe int64) {
	c.mu.Lock()
	for k := range c.m {
		if k.probe == probe {
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}

type interval struct{ from, to time.Time }

func (c *baselines) compute(probe int64, metric string, window, minBaseline, lag time.Duration, now time.Time) Baseline {
	tier, step := store.Tier1m, time.Minute
	if window > maxMinuteWindow {
		tier, step = store.Tier1h, time.Hour
	}
	to := now.Add(-lag).Truncate(step)
	from := to.Add(-window)
	rows, err := c.st.ProbeAverages(probe, from, to, tier)
	if err != nil || len(rows) == 0 {
		return Baseline{}
	}
	// periods spent in an alert on this probe's latency never feed the baseline
	var skip []interval
	if as, err := c.st.AlertsOverlappingTypes(from, "http_latency", "dns_latency"); err == nil {
		for _, a := range as {
			var d struct {
				ProbeID int64  `json:"probe_id"`
				Metric  string `json:"metric"`
			}
			if json.Unmarshal([]byte(a.DetailsJSON), &d) != nil || d.ProbeID != probe || (d.Metric != "" && d.Metric != metric) {
				continue
			}
			end := now.Add(time.Hour)
			if a.EndedAt != nil {
				end = *a.EndedAt
			}
			skip = append(skip, interval{a.StartedAt, end})
		}
	}
	vals := make([]float64, 0, len(rows))
	for _, r := range rows {
		if !r.HaveAvg() {
			continue
		}
		in := false
		for _, s := range skip {
			if r.Bucket.Add(step).After(s.from) && r.Bucket.Before(s.to) {
				in = true
				break
			}
		}
		if in {
			continue
		}
		v := r.TotalMS
		if metric == "ttfb" {
			v = r.TTFBMS
		}
		if math.IsNaN(v) || v < 0 {
			continue
		}
		vals = append(vals, v)
	}
	covers := time.Duration(len(vals)) * step
	if len(vals) == 0 {
		return Baseline{}
	}
	med, mad := medianMAD(vals)
	return Baseline{Median: med, MAD: mad, Samples: len(vals), Covers: covers, Ready: covers >= minBaseline}
}

// medianMAD returns the median and the median absolute deviation of vals (which it sorts).
func medianMAD(vals []float64) (median, mad float64) {
	if len(vals) == 0 {
		return 0, 0
	}
	sort.Float64s(vals)
	median = midpoint(vals)
	dev := make([]float64, len(vals))
	for i, v := range vals {
		dev[i] = math.Abs(v - median)
	}
	sort.Float64s(dev)
	return median, midpoint(dev)
}

func midpoint(sorted []float64) float64 {
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

package alert

import (
	"strings"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/store"
)

const latencyYAML = `
alerts:
  cooldown: 30m
  clear_ratio: 0.5
  rules:
    - name: http-slow
      type: http_latency
      baseline_window: 24h
      min_baseline: 2h
      multiplier: 3
      min_delta: 50ms
      sustain: 3m
    - name: dns-slow
      type: dns_latency
      baseline_window: 24h
      min_baseline: 2h
      multiplier: 3
      min_delta: 20ms
      sustain: 3m
`

// seed writes `minutes` one-minute rollups for an HTTP probe, starting at from, each averaging
// totalMS (two samples per minute).
func (h *harness) seed(probe int64, typ string, from time.Time, minutes int, totalMS float64) {
	h.t.Helper()
	d := time.Duration(totalMS * float64(time.Millisecond))
	for i := 0; i < minutes; i++ {
		for k := 0; k < 2; k++ {
			ts := from.Add(time.Duration(i)*time.Minute + time.Duration(k)*20*time.Second)
			switch typ {
			case "dns":
				h.st.Aggregator().AddDNS(store.DNSSample{ProbeID: probe, TS: ts, RTT: d})
			default:
				h.st.Aggregator().AddHTTP(store.HTTPSample{ProbeID: probe, TS: ts, Total: d, TTFB: d / 2})
			}
		}
	}
	h.st.FlushDue(from.Add(time.Duration(minutes)*time.Minute + time.Hour))
	if err := h.st.Sync(); err != nil {
		h.t.Fatal(err)
	}
}

func TestBaselineColdStartInactive(t *testing.T) {
	h := newHarness(t, latencyYAML)
	h.seed(5, "http", at(-60), 60, 100) // one hour of data: below min_baseline (2h)
	for i := 0; i < 8; i++ {
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 5, 2000))
	}
	want(t, len(h.alerts()) == 0, "latency rule must stay inactive while the baseline is learning: %+v", h.alerts())

	// the baseline fills up: the rule becomes active and fires
	h.seed(5, "http", at(-180), 120, 100)
	h.eng.base = newBaselines(h.st, h.clk.Now, false)
	for i := 8; i < 14; i++ {
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 5, 2000))
	}
	want(t, len(h.alerts()) == 1, "fires once the baseline is ready: %+v", h.alerts())
}

func TestLatencyFiresWithMessageAndBaseline(t *testing.T) {
	h := newHarness(t, latencyYAML)
	h.seed(5, "http", at(-180), 180, 100)
	for i := 0; i < 2; i++ {
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 5, 400))
	}
	want(t, len(h.alerts()) == 0, "sustain 3m not elapsed")
	h.minute(at(2), LocalState{}, httpMinute(1, "cf", 5, 420))
	al := h.alerts()
	want(t, len(al) == 1 && al[0].State == "firing", "alert %+v", al)
	a := al[0]
	want(t, a.Message == "HTTP total 420ms vs baseline 100ms", "message %q", a.Message)
	want(t, a.Baseline != nil && *a.Baseline == 100, "baseline %v", a.Baseline)
	want(t, a.Value != nil && *a.Value == 420 && a.PeakValue != nil && *a.PeakValue == 420, "value/peak")
	want(t, a.StartedAt.Equal(at(0)), "started_at %v", a.StartedAt)
	// peak follows the worst minute
	h.minute(at(3), LocalState{}, httpMinute(1, "cf", 5, 900))
	h.minute(at(4), LocalState{}, httpMinute(1, "cf", 5, 500))
	a = h.alerts()[0]
	want(t, a.PeakValue != nil && *a.PeakValue == 900, "peak %v", a.PeakValue)
	// resolves with hysteresis: clear below 0.5 x 300 = 150
	for i := 5; i < 7; i++ {
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 5, 200)) // between 150 and 300: stays firing
	}
	want(t, h.alerts()[0].State == "firing", "hysteresis: 200ms is below the trigger but above the clear level")
	for i := 7; i < 10; i++ {
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 5, 110))
	}
	want(t, h.alerts()[0].State == "resolved", "resolved after sustain below the clear level")
	want(t, h.alerts()[0].EndedAt.Equal(at(7)), "ended_at %v", h.alerts()[0].EndedAt)
}

func TestMinDeltaFloor(t *testing.T) {
	h := newHarness(t, latencyYAML)
	h.seed(5, "http", at(-180), 180, 5) // 5ms baseline: 3x = 15ms
	for i := 0; i < 8; i++ {
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 5, 40)) // 8x the baseline, but only +35ms
	}
	want(t, len(h.alerts()) == 0, "3x of a 5ms baseline must not page without min_delta: %+v", h.alerts())
	for i := 8; i < 12; i++ {
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 5, 80))
	}
	want(t, len(h.alerts()) == 1, "above baseline+min_delta and the multiplier: %+v", h.alerts())
}

func TestBaselineFrozenWhileFiringAndExcludedAfter(t *testing.T) {
	h := newHarness(t, latencyYAML)
	h.seed(5, "http", at(-125), 125, 100)
	h.seed(5, "http", at(0), 160, 400) // the incident, long enough to swamp the baseline if it fed it
	for i := 0; i < 150; i++ {
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 5, 400))
	}
	al := h.alerts()
	want(t, len(al) == 1 && al[0].State == "firing", "a long incident must not become the new normal: %+v", al)
	want(t, al[0].Baseline != nil && *al[0].Baseline == 100, "baseline frozen at 100, got %v", al[0].Baseline)

	// the incident ends; its period is excluded when baselines are recomputed
	for i := 150; i < 154; i++ {
		h.minute(at(i), LocalState{}, httpMinute(1, "cf", 5, 100))
	}
	want(t, h.alerts()[0].State == "resolved", "resolved: %s", h.alerts()[0].State)
	b := h.eng.base.compute(5, "total", 24*time.Hour, 2*time.Hour, 0, at(154))
	want(t, b.Ready && b.Median == 100, "baseline after the incident must exclude the alert period, got median %v (%d samples)", b.Median, b.Samples)
}

func TestBaselineFrozenWhilePending(t *testing.T) {
	h := newHarness(t, latencyYAML)
	h.seed(5, "http", at(-125), 125, 100)
	h.seed(5, "http", at(0), 20, 600)
	h.minute(at(0), LocalState{}, httpMinute(1, "cf", 5, 600))
	st := h.eng.states[stateKey{1, "http-slow", 5}]
	want(t, st != nil && st.pending(), "pending")
	e1 := h.eng.base.m[baseKey{5, "total", 24 * time.Hour, 2 * time.Hour}]
	first := e1.computed
	h.clk.Add(10 * time.Minute)
	b := h.eng.base.get(5, "total", 24*time.Hour, 2*time.Hour, 4*time.Minute, true)
	want(t, b.Median == 100 && e1.computed.Equal(first), "frozen baseline must not be refreshed while pending")
}

func TestMedianMAD(t *testing.T) {
	m, mad := medianMAD([]float64{1, 2, 3, 4, 100})
	want(t, m == 3 && mad == 1, "median %v mad %v", m, mad)
	m, mad = medianMAD([]float64{10, 10, 10, 10})
	want(t, m == 10 && mad == 0, "constant series")
	m, _ = medianMAD(nil)
	want(t, m == 0, "empty")
}

func TestLatencyThresholdUsesMAD(t *testing.T) {
	r := mustConfig(t, latencyYAML).Alerts.Rules[0]
	want(t, latencyThreshold(r, 100, 0) == 300, "multiplier dominates: %v", latencyThreshold(r, 100, 0))
	want(t, latencyThreshold(r, 5, 0) == 55, "min_delta dominates: %v", latencyThreshold(r, 5, 0))
	// a noisy metric (MAD 80ms) needs a bigger excursion: 100 + 4*1.4826*80 = 574
	got := latencyThreshold(r, 100, 80)
	want(t, got > 570 && got < 575, "MAD band %v", got)
	want(t, clearThreshold(300, 100, 0.7) == 210, "clear = ratio x trigger")
	want(t, clearThreshold(120, 100, 0.7) == 110, "midpoint when ratio x trigger is not above the baseline")
}

func TestDNSLatency(t *testing.T) {
	h := newHarness(t, latencyYAML)
	h.seed(9, "dns", at(-180), 180, 10)
	dns := func(avg float64) ProbeMinute {
		return ProbeMinute{ProbeID: 9, Type: "dns", Label: "home-resolver", N: 2, AvgTotalMS: avg, HaveAvg: true}
	}
	for i := 0; i < 4; i++ {
		h.clk.Set(at(i).Add(65 * time.Second))
		h.eng.HandleMinute(Minute{Bucket: at(i), DNS: []ProbeMinute{dns(250)}})
	}
	al := h.alerts()
	want(t, len(al) == 1 && al[0].RuleType == "dns_latency" && al[0].TargetID == nil, "dns alert: %+v", al)
	want(t, strings.HasPrefix(al[0].Message, "DNS lookup 250ms vs baseline 10ms"), "message %q", al[0].Message)
}

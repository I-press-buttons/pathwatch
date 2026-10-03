// Package analyze holds the pure analysis logic: hop classification (rate-limited vs really
// degraded), gap detection, local-outage detection, baselines and the MOS score, plus the
// Analyzer that applies them to every completed minute.
package analyze

// MOS estimates the Mean Opinion Score (1..4.5) with a simplified ITU-T G.107 E-model.
//
//	effective latency = avg + 2*jitter + 10
//	R = 93.2 - latency/40            (latency < 160)
//	R = 93.2 - (latency-120)/10      (latency >= 160)
//	R -= 2.5 * loss%
//	MOS = 1 + 0.035R + 0.000007 R (R-60) (100-R), clamped to 1..4.5
func MOS(avgMs, jitterMs, lossPct float64) float64 {
	lat := avgMs + 2*jitterMs + 10
	var r float64
	if lat < 160 {
		r = 93.2 - lat/40
	} else {
		r = 93.2 - (lat-120)/10
	}
	r -= 2.5 * lossPct
	switch {
	case r < 0:
		return 1
	case r > 100:
		return 4.5
	}
	m := 1 + 0.035*r + 0.000007*r*(r-60)*(100-r)
	if m < 1 {
		return 1
	}
	if m > 4.5 {
		return 4.5
	}
	return m
}

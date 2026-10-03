package store

import "math"

// Roll accumulates latency and loss statistics for one (target, ttl, path, bucket) cell.
// Rolls are mergeable: 1-minute cells merge into 1-hour cells and into display buckets.
// All latencies are milliseconds.
type Roll struct {
	N      int64   // probes sent
	Lost   int64   // probes without a reply
	Min    float64 // over replies
	Max    float64
	Sum    float64 // sum of reply latencies
	JitSum float64 // sum of |rtt[i]-rtt[i-1]| over consecutive replies (RFC 3550 style)
	JitN   int64   // number of consecutive-reply differences
	Hist   *Hist
}

// Replies is the number of probes that got a reply.
func (r *Roll) Replies() int64 { return r.N - r.Lost }

// AddReply records a reply. prev/havePrev give the previous reply's latency for jitter.
func (r *Roll) AddReply(ms, prev float64, havePrev bool) {
	if r.Replies() == 0 || ms < r.Min {
		r.Min = ms
	}
	if r.Replies() == 0 || ms > r.Max {
		r.Max = ms
	}
	r.N++
	r.Sum += ms
	if havePrev {
		r.JitSum += math.Abs(ms - prev)
		r.JitN++
	}
	if r.Hist == nil {
		r.Hist = &Hist{}
	}
	r.Hist.Add(ms)
}

// AddLoss records a lost probe.
func (r *Roll) AddLoss() {
	r.N++
	r.Lost++
}

// Merge adds o into r.
func (r *Roll) Merge(o *Roll) {
	if o == nil || o.N == 0 {
		return
	}
	if o.Replies() > 0 {
		if r.Replies() == 0 || o.Min < r.Min {
			r.Min = o.Min
		}
		if r.Replies() == 0 || o.Max > r.Max {
			r.Max = o.Max
		}
	}
	r.N += o.N
	r.Lost += o.Lost
	r.Sum += o.Sum
	r.JitSum += o.JitSum
	r.JitN += o.JitN
	if o.Hist != nil {
		if r.Hist == nil {
			r.Hist = &Hist{}
		}
		r.Hist.Merge(o.Hist)
	}
}

// Avg returns the mean reply latency; ok is false without replies.
func (r *Roll) Avg() (float64, bool) {
	if r.Replies() <= 0 {
		return 0, false
	}
	return r.Sum / float64(r.Replies()), true
}

// Jitter returns the mean absolute difference of consecutive reply latencies.
func (r *Roll) Jitter() (float64, bool) {
	if r.JitN <= 0 {
		return 0, false
	}
	return r.JitSum / float64(r.JitN), true
}

// LossPct returns loss in percent; ok is false when nothing was sent.
func (r *Roll) LossPct() (float64, bool) {
	if r.N <= 0 {
		return 0, false
	}
	return 100 * float64(r.Lost) / float64(r.N), true
}

// Quantile returns a latency quantile from the merged histogram.
func (r *Roll) Quantile(q float64) (float64, bool) {
	if r.Hist == nil {
		return 0, false
	}
	return r.Hist.Quantile(q, r.Min, r.Max)
}

// rollFromRow rebuilds a mergeable Roll from stored 1m/1h rollup columns.
func rollFromRow(n, lost int64, min, avg, max, jitter float64, hist []byte) *Roll {
	r := &Roll{N: n, Lost: lost, Min: min, Max: max}
	if rep := n - lost; rep > 0 {
		r.Sum = avg * float64(rep)
		if rep > 1 {
			r.JitN = rep - 1
			r.JitSum = jitter * float64(r.JitN)
		}
	}
	if h, err := DecodeHist(hist); err == nil {
		r.Hist = h
	} else {
		r.Hist = &Hist{}
	}
	return r
}

// ProbeRoll accumulates HTTP/TCP/DNS probe statistics for one (probe, bucket) cell.
// Phase averages and the total are over successful samples only. Latencies in milliseconds.
type ProbeRoll struct {
	N      int64 // samples
	Errors int64 // failed samples
	DNS    float64
	// Sums of phases over successful samples.
	Connect, TLS, TTFB, Transfer float64
	TotalMin, TotalMax, TotalSum float64
	Hist                         *Hist
	CertNotAfter                 int64 // µs, last seen (0 = none)
}

// OK is the number of successful samples.
func (p *ProbeRoll) OK() int64 { return p.N - p.Errors }

// AddOK records a successful sample.
func (p *ProbeRoll) AddOK(dns, connect, tls, ttfb, transfer, total float64) {
	if p.OK() == 0 || total < p.TotalMin {
		p.TotalMin = total
	}
	if p.OK() == 0 || total > p.TotalMax {
		p.TotalMax = total
	}
	p.N++
	p.DNS += dns
	p.Connect += connect
	p.TLS += tls
	p.TTFB += ttfb
	p.Transfer += transfer
	p.TotalSum += total
	if p.Hist == nil {
		p.Hist = &Hist{}
	}
	p.Hist.Add(total)
}

// AddError records a failed sample.
func (p *ProbeRoll) AddError() {
	p.N++
	p.Errors++
}

// Merge adds o into p.
func (p *ProbeRoll) Merge(o *ProbeRoll) {
	if o == nil || o.N == 0 {
		return
	}
	if o.OK() > 0 {
		if p.OK() == 0 || o.TotalMin < p.TotalMin {
			p.TotalMin = o.TotalMin
		}
		if p.OK() == 0 || o.TotalMax > p.TotalMax {
			p.TotalMax = o.TotalMax
		}
	}
	p.N += o.N
	p.Errors += o.Errors
	p.DNS += o.DNS
	p.Connect += o.Connect
	p.TLS += o.TLS
	p.TTFB += o.TTFB
	p.Transfer += o.Transfer
	p.TotalSum += o.TotalSum
	if o.CertNotAfter != 0 {
		p.CertNotAfter = o.CertNotAfter
	}
	if o.Hist != nil {
		if p.Hist == nil {
			p.Hist = &Hist{}
		}
		p.Hist.Merge(o.Hist)
	}
}

func (p *ProbeRoll) avg(sum float64) (float64, bool) {
	if p.OK() <= 0 {
		return 0, false
	}
	return sum / float64(p.OK()), true
}

// AvgTotal, AvgDNS ... return per-phase means over successful samples.
func (p *ProbeRoll) AvgTotal() (float64, bool)    { return p.avg(p.TotalSum) }
func (p *ProbeRoll) AvgDNS() (float64, bool)      { return p.avg(p.DNS) }
func (p *ProbeRoll) AvgConnect() (float64, bool)  { return p.avg(p.Connect) }
func (p *ProbeRoll) AvgTLS() (float64, bool)      { return p.avg(p.TLS) }
func (p *ProbeRoll) AvgTTFB() (float64, bool)     { return p.avg(p.TTFB) }
func (p *ProbeRoll) AvgTransfer() (float64, bool) { return p.avg(p.Transfer) }

// FailPct returns the failure rate in percent; ok is false for no samples.
func (p *ProbeRoll) FailPct() (float64, bool) {
	if p.N <= 0 {
		return 0, false
	}
	return 100 * float64(p.Errors) / float64(p.N), true
}

// SuccessPct returns the success rate in percent.
func (p *ProbeRoll) SuccessPct() (float64, bool) {
	f, ok := p.FailPct()
	return 100 - f, ok
}

// Quantile returns a total-latency quantile.
func (p *ProbeRoll) Quantile(q float64) (float64, bool) {
	if p.Hist == nil {
		return 0, false
	}
	return p.Hist.Quantile(q, p.TotalMin, p.TotalMax)
}

func probeRollFromRow(n, errors int64, dns, connect, tls, ttfb, transfer, tmin, tavg, tmax float64, hist []byte, cert int64) *ProbeRoll {
	p := &ProbeRoll{N: n, Errors: errors, TotalMin: tmin, TotalMax: tmax, CertNotAfter: cert}
	if ok := n - errors; ok > 0 {
		f := float64(ok)
		p.DNS, p.Connect, p.TLS, p.TTFB, p.Transfer, p.TotalSum = dns*f, connect*f, tls*f, ttfb*f, transfer*f, tavg*f
	}
	if h, err := DecodeHist(hist); err == nil {
		p.Hist = h
	} else {
		p.Hist = &Hist{}
	}
	return p
}

package web

import (
	"bytes"
	"context"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// metricsWindow is the span the /metrics values are computed over. It is read from the 1-minute
// rollups, never from the raw tables, so a scrape costs a few indexed rollup reads per target.
const metricsWindow = 5 * time.Minute

// metricsContentType is the Prometheus text exposition format, version 0.0.4.
const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

type metricSample struct {
	labels string // rendered `{a="b",...}` or ""
	value  float64
}

type metricFamily struct {
	name, help, typ string
	samples         []metricSample
}

// metricsDoc collects metric families in first-use order and renders them.
type metricsDoc struct {
	fams  []*metricFamily
	byKey map[string]*metricFamily
}

func newMetricsDoc() *metricsDoc { return &metricsDoc{byKey: map[string]*metricFamily{}} }

// declare registers a family so it keeps its place in the output.
func (d *metricsDoc) declare(name, typ, help string) {
	d.byKey[name] = &metricFamily{name: name, help: help, typ: typ}
	d.fams = append(d.fams, d.byKey[name])
}

// add appends a sample; labels are alternating name, value pairs. NaN and infinite values are
// dropped: a missing sample means "no data".
func (d *metricsDoc) add(name string, v float64, labels ...string) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	f := d.byKey[name]
	f.samples = append(f.samples, metricSample{labels: renderLabels(labels), value: v})
}

func (d *metricsDoc) bytes() []byte {
	var b bytes.Buffer
	for _, f := range d.fams {
		if len(f.samples) == 0 {
			continue
		}
		b.WriteString("# HELP " + f.name + " " + escapeHelp(f.help) + "\n")
		b.WriteString("# TYPE " + f.name + " " + f.typ + "\n")
		for _, s := range f.samples {
			b.WriteString(f.name + s.labels + " " + formatMetric(s.value) + "\n")
		}
	}
	return b.Bytes()
}

func formatMetric(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

// escapeHelp escapes backslash and newline in HELP text.
func escapeHelp(s string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`).Replace(s)
}

// escapeLabel escapes backslash, double quote and newline in a label value.
func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(strings.ToValidUTF8(s, "�"))
}

func renderLabels(kv []string) string {
	if len(kv) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(kv[i] + `="` + escapeLabel(kv[i+1]) + `"`)
	}
	b.WriteByte('}')
	return b.String()
}

// probeLabel is a probe's label value: the UI label without any query string or fragment, which
// may carry tokens.
func probeLabel(label string) string {
	if i := strings.IndexAny(label, "?#"); i >= 0 {
		label = label[:i]
	}
	return label
}

func boolf(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.cfg().Metrics.Enabled {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	body, err := s.renderMetrics(r.Context())
	if err != nil {
		s.queryFailed(w, r, err)
		return
	}
	w.Header().Set("Content-Type", metricsContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (s *Server) renderMetrics(ctx context.Context) ([]byte, error) {
	d := newMetricsDoc()
	d.declare("pathwatch_build_info", "gauge", "Build information; the value is always 1.")
	d.declare("pathwatch_target_up", "gauge", "1 if the target's destination answered in the last 5 minutes, 0 if everything was lost. Absent without data.")
	d.declare("pathwatch_target_paused", "gauge", "1 if monitoring of the target is paused.")
	d.declare("pathwatch_target_loss_ratio", "gauge", "Destination loss ratio (0..1) over the last 5 minutes.")
	d.declare("pathwatch_target_rtt_avg_seconds", "gauge", "Mean destination round-trip time over the last 5 minutes.")
	d.declare("pathwatch_target_rtt_min_seconds", "gauge", "Minimum destination round-trip time over the last 5 minutes.")
	d.declare("pathwatch_target_rtt_max_seconds", "gauge", "Maximum destination round-trip time over the last 5 minutes.")
	d.declare("pathwatch_target_rtt_p95_seconds", "gauge", "95th percentile destination round-trip time over the last 5 minutes.")
	d.declare("pathwatch_target_jitter_seconds", "gauge", "Mean absolute difference of consecutive destination replies over the last 5 minutes.")
	d.declare("pathwatch_target_mos", "gauge", "Estimated MOS (1..4.5) from latency, jitter and loss over the last 5 minutes.")
	d.declare("pathwatch_target_hops", "gauge", "Number of hops of the current path.")
	d.declare("pathwatch_hop_loss_ratio", "gauge", "Loss ratio (0..1) of the hop at this TTL over the last 5 minutes.")
	d.declare("pathwatch_hop_rtt_avg_seconds", "gauge", "Mean round-trip time of the hop at this TTL over the last 5 minutes.")
	d.declare("pathwatch_probe_total_seconds", "gauge", "Mean total time of successful probe samples over the last 5 minutes.")
	d.declare("pathwatch_probe_dns_seconds", "gauge", "Mean DNS lookup time of successful HTTP probe samples.")
	d.declare("pathwatch_probe_connect_seconds", "gauge", "Mean connect time of successful probe samples.")
	d.declare("pathwatch_probe_tls_seconds", "gauge", "Mean TLS handshake time of successful HTTP probe samples.")
	d.declare("pathwatch_probe_ttfb_seconds", "gauge", "Mean time to first byte of successful HTTP probe samples.")
	d.declare("pathwatch_probe_transfer_seconds", "gauge", "Mean transfer time of successful HTTP probe samples.")
	d.declare("pathwatch_probe_error_ratio", "gauge", "Ratio (0..1) of failed probe samples over the last 5 minutes.")
	d.declare("pathwatch_probe_http_status", "gauge", "HTTP status code of the newest HTTP probe sample that got a response.")
	d.declare("pathwatch_probe_cert_expiry_timestamp_seconds", "gauge", "Expiry (Unix time) of the newest TLS certificate seen by an HTTP probe.")
	d.declare("pathwatch_alerts_active", "gauge", "Number of firing alerts.")
	d.declare("pathwatch_outbox_pending", "gauge", "Alert notifications queued or waiting for a retry.")

	d.add("pathwatch_build_info", 1, "version", s.d.Version)

	now := s.now()
	plan := store.SinglePlan(now.Add(-metricsWindow), now, store.Tier1m)
	rows, err := s.d.Store.Targets(false)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if err := s.targetMetrics(ctx, d, row, plan); err != nil {
			return nil, err
		}
	}

	_, total, err := s.d.Store.ActiveAlertCounts()
	if err != nil {
		return nil, err
	}
	d.add("pathwatch_alerts_active", float64(total))
	pending, err := s.d.Store.OutboxPending()
	if err != nil {
		return nil, err
	}
	d.add("pathwatch_outbox_pending", float64(pending))
	return d.bytes(), nil
}

type probeRefLite struct {
	id         int64
	typ, label string
}

func (s *Server) targetMetrics(ctx context.Context, d *metricsDoc, row store.TargetRow, plan store.Plan) error {
	v := s.viewOf(row)
	row = v.row
	tl := []string{"target", row.Name, "host", row.Host}
	d.add("pathwatch_target_paused", boolf(row.Paused), tl...)

	e, err := s.e2e(ctx, v, plan, true)
	if err != nil {
		return err
	}
	if len(e.points) > 0 && e.points[0].n > 0 {
		p := e.points[0]
		// The last responding hop stands in for a destination that drops ICMP; its loss is often
		// router rate limiting, so it says nothing about reachability.
		if p.haveLoss && e.source != "last_hop" {
			d.add("pathwatch_target_loss_ratio", p.loss/100, tl...)
			d.add("pathwatch_target_up", boolf(p.loss < 100), tl...)
		}
		if p.haveAvg {
			d.add("pathwatch_target_rtt_avg_seconds", p.avg/1000, tl...)
			d.add("pathwatch_target_rtt_min_seconds", p.min/1000, tl...)
			d.add("pathwatch_target_rtt_max_seconds", p.max/1000, tl...)
			d.add("pathwatch_target_rtt_p95_seconds", p.p95/1000, tl...)
		}
		if p.haveJit {
			d.add("pathwatch_target_jitter_seconds", p.jitter/1000, tl...)
		}
		if p.haveLoss {
			switch {
			case p.haveAvg:
				d.add("pathwatch_target_mos", analyze.MOS(p.avg, p.jitter, p.loss), tl...)
			case p.loss >= 100:
				d.add("pathwatch_target_mos", 1, tl...)
			}
		}
	}
	hops := s.hopCount(v, e)
	if hops > 0 {
		d.add("pathwatch_target_hops", float64(hops), tl...)
	}

	if !(v.hasSt && v.state.Spec.ICMP == nil) {
		cells, err := s.d.Store.ICMPCells(ctx, row.ID, plan, store.CellOpts{NoHist: true, LastResp: true})
		if err != nil {
			return err
		}
		end := cells.LastRespTTL()
		if hops > end {
			end = hops
		}
		for ttl := 1; ttl <= end; ttl++ {
			tot := cells.Total(ttl)
			if tot == nil || tot.N == 0 {
				continue
			}
			hl := []string{"target", row.Name, "ttl", strconv.Itoa(ttl)}
			if loss, ok := tot.LossPct(); ok {
				d.add("pathwatch_hop_loss_ratio", loss/100, hl...)
			}
			if avg, ok := tot.Avg(); ok {
				d.add("pathwatch_hop_rtt_avg_seconds", avg/1000, hl...)
			}
		}
	}

	var probes []probeRefLite
	for _, p := range v.probes {
		if p.Type == config.ProbeHTTP || p.Type == config.ProbeTCP {
			probes = append(probes, probeRefLite{p.ID, p.Type, p.Label})
		}
	}
	sort.SliceStable(probes, func(i, j int) bool { return probes[i].id < probes[j].id })
	for _, p := range probes {
		pl := []string{"target", row.Name, "probe", probeLabel(p.label), "type", p.typ}
		pc, err := s.d.Store.ProbeCells(ctx, p.id, p.typ, plan, store.CellOpts{NoHist: true})
		if err != nil {
			return err
		}
		t := pc.Total()
		if t.N > 0 {
			if f, ok := t.FailPct(); ok {
				d.add("pathwatch_probe_error_ratio", f/100, pl...)
			}
			if avg, ok := t.AvgTotal(); ok {
				d.add("pathwatch_probe_total_seconds", avg/1000, pl...)
			}
			if avg, ok := t.AvgConnect(); ok {
				d.add("pathwatch_probe_connect_seconds", avg/1000, pl...)
			}
			if p.typ == config.ProbeHTTP {
				if avg, ok := t.AvgDNS(); ok {
					d.add("pathwatch_probe_dns_seconds", avg/1000, pl...)
				}
				if avg, ok := t.AvgTLS(); ok {
					d.add("pathwatch_probe_tls_seconds", avg/1000, pl...)
				}
				if avg, ok := t.AvgTTFB(); ok {
					d.add("pathwatch_probe_ttfb_seconds", avg/1000, pl...)
				}
				if avg, ok := t.AvgTransfer(); ok {
					d.add("pathwatch_probe_transfer_seconds", avg/1000, pl...)
				}
			}
		}
		if p.typ == config.ProbeHTTP {
			if code, ok := s.d.Store.LastHTTPStatus(p.id); ok {
				d.add("pathwatch_probe_http_status", float64(code), pl...)
			}
			if c, ok := s.d.Store.LatestCert(p.id); ok {
				d.add("pathwatch_probe_cert_expiry_timestamp_seconds", float64(c.Unix()), pl...)
			}
		}
	}
	return nil
}

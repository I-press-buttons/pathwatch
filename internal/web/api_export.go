package web

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// Export limits. maxExportRows bounds one download (and so the memory of the cells it loads);
// above exportHistRows the latency histograms are left out and the p95 columns stay empty.
const (
	maxExportRows  = 250000
	exportHistRows = 60000
)

// csvSafe guards a text cell against spreadsheet formula injection: hostnames come from reverse
// DNS and are controlled by whoever owns the address block, and probe labels by the config, so a
// cell that a spreadsheet would read as a formula gets a leading single quote.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// exportCell renders one value for CSV. Only strings are text; numbers cannot start a formula.
func exportCell(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return csvSafe(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case *int:
		if x == nil {
			return ""
		}
		return strconv.Itoa(*x)
	case *float64:
		if x == nil {
			return ""
		}
		return strconv.FormatFloat(*x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// exportSink receives the rows of an export in column order.
type exportSink interface {
	row(vals []any) error
	end() error
}

type csvSink struct {
	w *csv.Writer
	n int
}

func newCSVSink(w *bufio.Writer, cols []string) (*csvSink, error) {
	s := &csvSink{w: csv.NewWriter(w)}
	return s, s.w.Write(cols)
}

func (s *csvSink) row(vals []any) error {
	rec := make([]string, len(vals))
	for i, v := range vals {
		rec[i] = exportCell(v)
	}
	if s.n++; s.n%2000 == 0 {
		s.w.Flush()
	}
	return s.w.Write(rec)
}

func (s *csvSink) end() error {
	s.w.Flush()
	return s.w.Error()
}

type jsonSink struct {
	w     *bufio.Writer
	cols  [][]byte // pre-encoded "name": prefixes
	first bool
}

func newJSONSink(w *bufio.Writer, meta map[string]any, cols []string) (*jsonSink, error) {
	s := &jsonSink{w: w, first: true}
	for _, c := range cols {
		k, _ := json.Marshal(c)
		s.cols = append(s.cols, append(k, ':'))
	}
	head, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	// reopen the meta object to append the rows array
	_, err = w.Write(append(head[:len(head)-1], []byte(`,"rows":[`+"\n")...))
	return s, err
}

func (s *jsonSink) row(vals []any) error {
	if !s.first {
		s.w.WriteByte(',')
	}
	s.first = false
	s.w.WriteByte('{')
	for i, v := range vals {
		if i > 0 {
			s.w.WriteByte(',')
		}
		s.w.Write(s.cols[i])
		var out = v
		if p, ok := v.(*float64); ok && p == nil {
			out = nil
		}
		if p, ok := v.(*int); ok && p == nil {
			out = nil
		}
		b, err := json.Marshal(out)
		if err != nil {
			return err
		}
		s.w.Write(b)
	}
	_, err := s.w.WriteString("}\n")
	return err
}

func (s *jsonSink) end() error {
	_, err := s.w.WriteString("]}\n")
	if err != nil {
		return err
	}
	return s.w.Flush()
}

var hopExportCols = []string{"bucket_start", "bucket_start_ms", "ttl", "address", "hostname", "asn", "as_name",
	"sent", "lost", "loss_pct", "rtt_min_ms", "rtt_avg_ms", "rtt_max_ms", "jitter_ms", "rtt_p95_ms"}

var probeExportCols = []string{"bucket_start", "bucket_start_ms", "probe_id", "probe", "type", "samples", "errors",
	"error_pct", "dns_avg_ms", "connect_avg_ms", "tls_avg_ms", "ttfb_avg_ms", "transfer_avg_ms",
	"total_min_ms", "total_avg_ms", "total_max_ms", "total_p95_ms"}

// exportPlan lays out the buckets of an export: one per minute (raw rounds are folded into
// minutes) up to 7 days, one per hour beyond, unless res asks for one or the other.
func exportPlan(from, to time.Time, res string) store.Plan {
	tier := store.TierFor(from, to)
	step := time.Minute
	switch {
	case res == "1h", res == "" && tier == store.Tier1h:
		step, tier = time.Hour, store.Tier1h
	case to.Sub(from) <= store.RawMaxRange:
		tier = store.TierRaw
	default:
		tier = store.Tier1m
	}
	ms := step.Milliseconds()
	origin := time.UnixMilli(from.UnixMilli() / ms * ms).UTC()
	n := int((to.Sub(origin) + step - 1) / step)
	if n < 1 {
		n = 1
	}
	return store.Plan{Tier: tier, From: origin, To: to, Step: step, N: n}
}

func exportFilename(name, kind string, from, to time.Time, ext string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		case r > 0x20 && r < 0x7f, r == ' ':
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		b.WriteString("target")
	}
	f := "20060102T1504Z"
	return fmt.Sprintf("pathwatch-%s-%s-%s-%s.%s", b.String(), kind, from.UTC().Format(f), to.UTC().Format(f), ext)
}

type probeInfo struct {
	id    int64
	label string
	typ   string
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	row, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	from, to, err := s.parseRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		writeError(w, http.StatusBadRequest, "invalid format: expected csv or json")
		return
	}
	kind := q.Get("kind")
	if kind == "" {
		kind = "hops"
	}
	if kind != "hops" && kind != "probes" {
		writeError(w, http.StatusBadRequest, "invalid kind: expected hops or probes")
		return
	}
	res := q.Get("res")
	if res != "" && res != "1m" && res != "1h" {
		writeError(w, http.StatusBadRequest, "invalid res: expected 1m or 1h")
		return
	}
	plan := exportPlan(from, to, res)

	// Everything that can fail or exceed the cap happens before the first byte is written, so
	// an error is still a clean JSON 400/500; the rows are then streamed out.
	var cols []string
	var emit func(sink exportSink) error
	var count int
	tooMany := func(n int) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("export too large: about %d rows, the limit is %d; choose a shorter range or a coarser res", n, maxExportRows))
	}
	switch kind {
	case "hops":
		cols = hopExportCols
		maxTTL, err := s.d.Store.MaxHopTTL(row.ID)
		if err != nil {
			s.queryFailed(w, r, err)
			return
		}
		if maxTTL < 1 {
			maxTTL = 1
		}
		est := plan.N * maxTTL
		if est > maxExportRows {
			tooMany(est)
			return
		}
		cells, err := s.d.Store.ICMPCells(r.Context(), row.ID, plan, store.CellOpts{NoHist: est > exportHistRows})
		if err != nil {
			s.queryFailed(w, r, err)
			return
		}
		pc, err := s.loadPathCtx(row, plan)
		if err != nil {
			s.queryFailed(w, r, err)
			return
		}
		end := cells.MaxTTL()
		series := make([][]*store.Roll, end+1)
		for ttl := 1; ttl <= end; ttl++ {
			series[ttl] = cells.Series(ttl)
			for _, c := range series[ttl] {
				if c != nil && c.N > 0 {
					count++
				}
			}
		}
		if count > maxExportRows {
			tooMany(count)
			return
		}
		emit = func(sink exportSink) error {
			for ttl := 1; ttl <= end; ttl++ {
				id := s.identity(pc, ttl)
				var asName string
				if id.asName != nil {
					asName = *id.asName
				}
				for b, c := range series[ttl] {
					if c == nil || c.N == 0 {
						continue
					}
					ts := plan.BucketStart(b)
					avg, haveAvg := c.Avg()
					jit, haveJit := c.Jitter()
					p95, haveP95 := c.Quantile(0.95)
					loss, haveLoss := c.LossPct()
					rep := c.Replies() > 0
					v := []any{ts.Format(time.RFC3339), ts.UnixMilli(), ttl, id.addr, id.hostname, id.asn, asName,
						c.N, c.Lost, fp(loss, haveLoss), fp(c.Min, rep), fp(avg, haveAvg), fp(c.Max, rep), fp(jit, haveJit), fp(p95, haveP95 && rep)}
					if err := sink.row(v); err != nil {
						return err
					}
				}
			}
			return nil
		}
	default:
		cols = probeExportCols
		type probeSeries struct {
			p     probeInfo
			rolls []*store.ProbeRoll
		}
		var sets []probeSeries
		v := s.viewOf(row)
		est := 0
		for _, p := range v.probes {
			if p.Type == config.ProbeHTTP || p.Type == config.ProbeTCP {
				est += plan.N
			}
		}
		if est > maxExportRows {
			tooMany(est)
			return
		}
		for _, p := range v.probes {
			if p.Type != config.ProbeHTTP && p.Type != config.ProbeTCP {
				continue
			}
			pcs, err := s.d.Store.ProbeCells(r.Context(), p.ID, p.Type, plan, store.CellOpts{NoHist: est > exportHistRows})
			if err != nil {
				s.queryFailed(w, r, err)
				return
			}
			sets = append(sets, probeSeries{probeInfo{p.ID, p.Label, p.Type}, pcs.Rolls})
			for _, c := range pcs.Rolls {
				if c != nil && c.N > 0 {
					count++
				}
			}
		}
		emit = func(sink exportSink) error {
			for _, ps := range sets {
				for b, c := range ps.rolls {
					if c == nil || c.N == 0 {
						continue
					}
					ts := plan.BucketStart(b)
					dns, a := c.AvgDNS()
					conn, b2 := c.AvgConnect()
					tls, c2 := c.AvgTLS()
					ttfb, d := c.AvgTTFB()
					tr, e := c.AvgTransfer()
					tot, f := c.AvgTotal()
					p95, g := c.Quantile(0.95)
					fail, h := c.FailPct()
					ok := c.OK() > 0
					vals := []any{ts.Format(time.RFC3339), ts.UnixMilli(), ps.p.id, ps.p.label, ps.p.typ, c.N, c.Errors,
						fp(fail, h), fp(dns, a), fp(conn, b2), fp(tls, c2), fp(ttfb, d), fp(tr, e),
						fp(c.TotalMin, ok), fp(tot, f), fp(c.TotalMax, ok), fp(p95, g && ok)}
					if err := sink.row(vals); err != nil {
						return err
					}
				}
			}
			return nil
		}
	}

	h := w.Header()
	if format == "csv" {
		h.Set("Content-Type", "text/csv; charset=utf-8")
	} else {
		h.Set("Content-Type", "application/json; charset=utf-8")
	}
	h.Set("Content-Disposition", `attachment; filename="`+exportFilename(row.Name, kind, from, to, format)+`"`)
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriterSize(w, 32<<10)
	var sink exportSink
	if format == "csv" {
		sink, err = newCSVSink(bw, cols)
	} else {
		meta := map[string]any{"target_id": row.ID, "target": row.Name, "kind": kind, "resolution": plan.Step.String(),
			"from": from.UnixMilli(), "to": to.UnixMilli(), "row_count": count}
		sink, err = newJSONSink(bw, meta, cols)
	}
	// from here on the status is sent: a failure can only cut the stream short
	if err == nil {
		err = emit(sink)
	}
	if err == nil {
		err = sink.end()
	}
	if err == nil {
		err = bw.Flush()
	}
	if err != nil && r.Context().Err() == nil {
		s.log.Warn("export aborted", "path", r.URL.Path, "err", err)
	}
}

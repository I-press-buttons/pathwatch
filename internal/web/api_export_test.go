package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/enrich"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

const evilHostname = "=HYPERLINK(\"http://evil.example\",\"x\")"

type stubPersist map[netip.Addr]enrich.Info

func (p stubPersist) Load() (map[netip.Addr]enrich.Info, error) { return p, nil }
func (p stubPersist) Put(netip.Addr, enrich.Info)               {}

// reportFixture is two hours of one target: a three-hop path whose last two hops stop answering
// between minutes 60 and 70 (together with the TCP probe), a monitor gap at minutes 30-35 and a
// route change at minute 90. The responder of hop 2 has a hostile reverse-DNS name.
type reportFixture struct {
	st      *store.Store
	srv     *Server
	h       http.Handler
	t0, now time.Time
	row     store.TargetRow
	sent    int64 // rounds
	lost    int64 // rounds in which the destination did not answer
}

func newReportFixture(t *testing.T) *reportFixture {
	t.Helper()
	f := &reportFixture{t0: time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)}
	f.now = f.t0.Add(2 * time.Hour)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"), store.Options{Logger: log, NoBackground: true, FlushInterval: 20 * time.Millisecond, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f.st = st
	row, err := st.SyncConfigTarget("isp-edge", "edge.example")
	if err != nil {
		t.Fatal(err)
	}
	f.row = row
	mkPath := func(at time.Duration) int64 {
		id, err := st.NewPath(row.ID, "192.0.2.1", 3, f.t0.Add(at))
		if err != nil {
			t.Fatal(err)
		}
		for ttl := 1; ttl <= 3; ttl++ {
			st.AddPathHop(id, ttl, 0, fmt.Sprintf("10.9.0.%d", ttl))
		}
		return id
	}
	pa, pb := mkPath(0), mkPath(90*time.Minute)
	tcp, err := st.EnsureProbe(row.ID, "tcp", "tcp|edge", "tcp 443")
	if err != nil {
		t.Fatal(err)
	}
	httpP, err := st.EnsureProbe(row.ID, "http", "http|edge", "https://edge.example/")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1440; i++ {
		at := time.Duration(i) * 5 * time.Second
		min := int(at / time.Minute)
		ts := f.t0.Add(at)
		if min >= 30 && min < 35 {
			continue // the monitor was not running
		}
		down := min >= 60 && min < 70
		hops := []store.Hop{{TTL: 1, Status: 2, RTT: time.Millisecond, Resp: 1}, {TTL: 2}, {TTL: 3}}
		if !down {
			hops[1] = store.Hop{TTL: 2, Status: 2, RTT: 2 * time.Millisecond, Resp: 1}
			hops[2] = store.Hop{TTL: 3, Status: 1, RTT: 3 * time.Millisecond, Resp: 1}
		}
		path := pa
		if min >= 90 {
			path = pb
		}
		st.RecordRound(store.Round{TargetID: row.ID, TS: ts, PathID: path, Hops: hops})
		f.sent++
		if down {
			f.lost++
		}
		if i%2 == 0 {
			smp := store.TCPSample{ProbeID: tcp, TS: ts, Connect: 20 * time.Millisecond}
			if down {
				smp.Error = "timeout"
			}
			st.RecordTCP(smp)
		}
		if i%6 == 0 {
			h := store.HTTPSample{ProbeID: httpP, TS: ts, Status: 200, DNS: time.Millisecond, Connect: 5 * time.Millisecond, TLS: 10 * time.Millisecond, TTFB: 30 * time.Millisecond, Transfer: time.Millisecond, Total: 47 * time.Millisecond}
			if down {
				h = store.HTTPSample{ProbeID: httpP, TS: ts, Error: "timeout"}
			}
			st.RecordHTTP(h)
		}
	}
	st.RecordGap(row.ID, f.t0.Add(30*time.Minute), f.t0.Add(35*time.Minute), "stalled")
	tid := row.ID
	ttl := 2
	end := f.t0.Add(70 * time.Minute)
	if _, err := st.InsertEvent(store.Event{TargetID: &tid, Kind: store.EventDegraded, TTL: &ttl, From: f.t0.Add(60 * time.Minute), To: &end}); err != nil {
		t.Fatal(err)
	}
	det, _ := json.Marshal(map[string]any{"from_path": pa, "to_path": pb, "resolved_ip": "192.0.2.1"})
	if _, err := st.InsertEvent(store.Event{TargetID: &tid, Kind: store.EventRouteChange, From: f.t0.Add(90 * time.Minute), Details: det}); err != nil {
		t.Fatal(err)
	}
	aend := f.t0.Add(69 * time.Minute)
	val := 100.0
	if err := st.SaveAlert(&store.Alert{TargetID: &tid, Rule: "dest-loss", RuleType: "final_hop_loss", State: "resolved",
		StartedAt: f.t0.Add(61 * time.Minute), EndedAt: &aend, Value: &val, Message: "destination loss 100%"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Sync(); err != nil {
		t.Fatal(err)
	}
	st.FlushDue(f.now)
	if err := st.Sync(); err != nil {
		t.Fatal(err)
	}
	en := enrich.New(enrich.Options{Logger: log, Workers: 1,
		Persist:    stubPersist{netip.MustParseAddr("10.9.0.2"): {Hostname: evilHostname, ASN: 64500, ASName: "Evil, Inc", UpdatedAt: time.Now()}},
		LookupAddr: func(context.Context, string) ([]string, error) { return nil, errors.New("no rdns") }})
	t.Cleanup(en.Close)
	f.srv = New(Deps{Store: st, Enrich: en, Logger: log, Now: func() time.Time { return f.now },
		Static: fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}}})
	f.h = f.srv.Handler()
	return f
}

func (f *reportFixture) get(path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, loopbackReq("GET", path))
	return w
}

func (f *reportFixture) url(kind, q string) string {
	return fmt.Sprintf("/api/targets/%d/%s?%s", f.row.ID, kind, q)
}

func (f *reportFixture) rangeQ() string {
	return fmt.Sprintf("from=%d&to=%d", f.t0.UnixMilli(), f.now.UnixMilli())
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "",
		"router.example":   "router.example",
		"=1+1":             "'=1+1",
		"+cmd":             "'+cmd",
		"-2":               "'-2",
		"@SUM(A1)":         "'@SUM(A1)",
		"\tx":              "'\tx",
		"\rx":              "'\rx",
		"a=b":              "a=b",
		"'=already quoted": "'=already quoted",
	} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
	// numbers are never prefixed, strings always go through the guard, and the csv writer
	// still quotes what needs it
	zero := 0.0
	if got := exportCell(&zero); got != "0" {
		t.Errorf("number cell %q", got)
	}
	neg := -1.5
	if got := exportCell(&neg); got != "-1.5" {
		t.Errorf("negative number cell %q", got)
	}
	var nilf *float64
	if exportCell(nilf) != "" || exportCell(nil) != "" {
		t.Error("nil cells must be empty")
	}
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	sink, _ := newCSVSink(bw, []string{"a", "b"})
	if err := sink.row([]any{"=SUM(1,2)", "x,\"y\"\n"}); err != nil {
		t.Fatal(err)
	}
	sink.end()
	bw.Flush()
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(recs) != 2 || recs[1][0] != "'=SUM(1,2)" || recs[1][1] != "x,\"y\"\n" {
		t.Fatalf("csv round trip: %v %q", err, recs)
	}
}

func TestExportFilename(t *testing.T) {
	f := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	got := exportFilename("a b/\"c\";\r\nd é", "hops", f, f.Add(time.Hour), "csv")
	if strings.ContainsAny(got, "\"/;\r\n é ") || !strings.HasSuffix(got, ".csv") || !strings.HasPrefix(got, "pathwatch-a_b__c__d_-hops-") {
		t.Errorf("filename %q", got)
	}
	if got := exportFilename("é", "probes", f, f, "json"); !strings.HasPrefix(got, "pathwatch-target-probes-") {
		t.Errorf("filename %q", got)
	}
}

func TestExportHopsCSV(t *testing.T) {
	f := newReportFixture(t)
	w := f.get(f.url("export", f.rangeQ()+"&format=csv&kind=hops"))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content type %q", ct)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="pathwatch-isp-edge-hops-`) || !strings.HasSuffix(cd, `.csv"`) {
		t.Errorf("content disposition %q", cd)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("export lost the security headers")
	}
	recs, err := csv.NewReader(w.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	col := map[string]int{}
	for i, c := range recs[0] {
		col[c] = i
	}
	for _, c := range hopExportCols {
		if _, ok := col[c]; !ok {
			t.Errorf("missing column %s", c)
		}
	}
	// minute buckets: 120 minutes minus the 5 without rounds, three TTLs
	if want := 115 * 3; len(recs)-1 != want {
		t.Errorf("%d rows, want %d", len(recs)-1, want)
	}
	var sawEvil, sawLoss bool
	for _, r := range recs[1:] {
		if r[col["ttl"]] == "2" {
			if r[col["address"]] != "10.9.0.2" || r[col["asn"]] != "64500" || r[col["as_name"]] != "Evil, Inc" {
				t.Fatalf("hop 2 identity: %q", r)
			}
			if r[col["hostname"]] == "'"+evilHostname {
				sawEvil = true
			}
			if strings.HasPrefix(r[col["hostname"]], "=") {
				t.Fatalf("formula in a cell: %q", r[col["hostname"]])
			}
		}
		if r[col["ttl"]] == "3" && r[col["bucket_start"]] == f.t0.Add(65*time.Minute).Format(time.RFC3339) {
			if r[col["sent"]] != "12" || r[col["lost"]] != "12" || r[col["loss_pct"]] != "100" || r[col["rtt_avg_ms"]] != "" {
				t.Fatalf("lossy bucket: %q", r)
			}
			sawLoss = true
		}
		if r[col["ttl"]] == "3" && r[col["bucket_start"]] == f.t0.Add(10*time.Minute).Format(time.RFC3339) {
			if r[col["lost"]] != "0" || r[col["rtt_avg_ms"]] != "3" || r[col["rtt_min_ms"]] != "3" || r[col["rtt_max_ms"]] != "3" || r[col["jitter_ms"]] != "0" || r[col["rtt_p95_ms"]] == "" {
				t.Fatalf("clean bucket: %q", r)
			}
		}
	}
	if !sawEvil || !sawLoss {
		t.Errorf("evil hostname guarded %v, lossy bucket seen %v", sawEvil, sawLoss)
	}
}

func TestExportHopsJSON(t *testing.T) {
	f := newReportFixture(t)
	w := f.get(f.url("export", f.rangeQ()+"&format=json"))
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment;") || !strings.HasSuffix(cd, `.json"`) {
		t.Errorf("content disposition %q", cd)
	}
	var doc struct {
		TargetID   int64            `json:"target_id"`
		Target     string           `json:"target"`
		Kind       string           `json:"kind"`
		Resolution string           `json:"resolution"`
		From       int64            `json:"from"`
		To         int64            `json:"to"`
		RowCount   int              `json:"row_count"`
		Rows       []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("%v\n%.300s", err, w.Body.String())
	}
	if doc.TargetID != f.row.ID || doc.Target != "isp-edge" || doc.Kind != "hops" || doc.Resolution != "1m0s" || doc.From != f.t0.UnixMilli() || doc.To != f.now.UnixMilli() {
		t.Errorf("meta %+v", doc)
	}
	if doc.RowCount != len(doc.Rows) || len(doc.Rows) != 115*3 {
		t.Errorf("row_count %d, rows %d", doc.RowCount, len(doc.Rows))
	}
	for _, r := range doc.Rows {
		if len(r) != len(hopExportCols) {
			t.Fatalf("row has %d keys: %v", len(r), r)
		}
		if r["ttl"] == float64(2) {
			// JSON is not a spreadsheet: the hostname is exported as it is
			if r["hostname"] != evilHostname || r["asn"] != float64(64500) {
				t.Fatalf("hop 2: %v", r)
			}
		}
		if r["ttl"] == float64(1) && r["asn"] != nil {
			t.Fatalf("a hop without ASN must export null: %v", r)
		}
	}
}

func TestExportProbes(t *testing.T) {
	f := newReportFixture(t)
	w := f.get(f.url("export", f.rangeQ()+"&kind=probes&format=csv"))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	recs, err := csv.NewReader(w.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	col := map[string]int{}
	for i, c := range recs[0] {
		col[c] = i
	}
	var sawHTTP, sawDown bool
	for _, r := range recs[1:] {
		if r[col["type"]] == "http" && r[col["bucket_start"]] == f.t0.Add(10*time.Minute).Format(time.RFC3339) {
			sawHTTP = true
			if r[col["errors"]] != "0" || r[col["dns_avg_ms"]] != "1" || r[col["connect_avg_ms"]] != "5" || r[col["tls_avg_ms"]] != "10" ||
				r[col["ttfb_avg_ms"]] != "30" || r[col["transfer_avg_ms"]] != "1" || r[col["total_avg_ms"]] != "47" || r[col["total_min_ms"]] != "47" {
				t.Errorf("http bucket: %q", r)
			}
		}
		if r[col["type"]] == "tcp" && r[col["bucket_start"]] == f.t0.Add(65*time.Minute).Format(time.RFC3339) {
			sawDown = true
			if r[col["samples"]] != r[col["errors"]] || r[col["error_pct"]] != "100" || r[col["total_avg_ms"]] != "" {
				t.Errorf("tcp outage bucket: %q", r)
			}
		}
	}
	if !sawHTTP || !sawDown {
		t.Errorf("http %v, tcp outage %v", sawHTTP, sawDown)
	}
	j := f.get(f.url("export", f.rangeQ()+"&kind=probes&format=json"))
	var doc struct {
		Kind string           `json:"kind"`
		Rows []map[string]any `json:"rows"`
	}
	if err := json.Unmarshal(j.Body.Bytes(), &doc); err != nil || doc.Kind != "probes" || len(doc.Rows) != len(recs)-1 || len(doc.Rows[0]) != len(probeExportCols) {
		t.Fatalf("probes json: %v kind %q rows %d", err, doc.Kind, len(doc.Rows))
	}
}

func TestExportResolution(t *testing.T) {
	f := newReportFixture(t)
	// res=1h over the two hours: three TTLs, buckets for hour 10:00 and 11:00
	w := f.get(f.url("export", f.rangeQ()+"&format=csv&res=1h"))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	recs, _ := csv.NewReader(w.Body).ReadAll()
	if len(recs) < 2 || len(recs) > 1+3*3 {
		t.Errorf("hourly export has %d rows", len(recs)-1)
	}
	// automatic choice: a range beyond 7 days is hourly
	p := exportPlan(f.now.Add(-8*24*time.Hour), f.now, "")
	if p.Step != time.Hour || p.Tier != store.Tier1h {
		t.Errorf("8d plan %+v", p)
	}
	if p := exportPlan(f.now.Add(-2*time.Hour), f.now, ""); p.Step != time.Minute || p.Tier != store.TierRaw {
		t.Errorf("2h plan %+v", p)
	}
	if p := exportPlan(f.now.Add(-2*24*time.Hour), f.now, ""); p.Step != time.Minute || p.Tier != store.Tier1m {
		t.Errorf("2d plan %+v", p)
	}
	if p := exportPlan(f.now.Add(-30*24*time.Hour), f.now, "1m"); p.Step != time.Minute || p.Tier != store.Tier1m {
		t.Errorf("30d res=1m plan %+v", p)
	}
}

func TestExportValidation(t *testing.T) {
	f := newReportFixture(t)
	id := f.row.ID
	cases := map[string]struct {
		url  string
		code int
		msg  string
	}{
		"format":      {f.url("export", "format=xml"), 400, "invalid format"},
		"kind":        {f.url("export", "kind=dns"), 400, "invalid kind"},
		"res":         {f.url("export", "res=5m"), 400, "invalid res"},
		"from":        {f.url("export", "from=yesterday"), 400, "invalid from"},
		"to":          {f.url("export", "to=x"), 400, "invalid to"},
		"order":       {f.url("export", fmt.Sprintf("from=%d&to=%d", f.now.UnixMilli(), f.t0.UnixMilli())), 400, "to must be after from"},
		"range limit": {f.url("export", fmt.Sprintf("from=%d", f.now.Add(-401*24*time.Hour).UnixMilli())), 400, "range too large"},
		"bad id":      {"/api/targets/abc/export", 400, "invalid target id"},
		"no target":   {fmt.Sprintf("/api/targets/%d/export", id+99), 404, "target not found"},
		"report from": {f.url("report", "from=zz"), 400, "invalid from"},
		"report span": {f.url("report", fmt.Sprintf("from=%d", f.now.Add(-401*24*time.Hour).UnixMilli())), 400, "range too large"},
		"report id":   {fmt.Sprintf("/api/targets/%d/report", id+99), 404, "target not found"},
	}
	for name, c := range cases {
		w := f.get(c.url)
		var e struct{ Error string }
		_ = json.Unmarshal(w.Body.Bytes(), &e)
		if w.Code != c.code || !strings.Contains(e.Error, c.msg) {
			t.Errorf("%s: %d %q, want %d containing %q", name, w.Code, w.Body.String(), c.code, c.msg)
		}
		if strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
			t.Errorf("%s: an error must not be sent as a download", name)
		}
	}
	// POST is not routed
	w := httptest.NewRecorder()
	f.h.ServeHTTP(w, loopbackReq("POST", f.url("export", "")))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST export: %d", w.Code)
	}
}

func TestExportRowCap(t *testing.T) {
	f := newReportFixture(t)
	// 100 days of minute buckets over a three-hop path is far beyond the cap, with or without data
	q := fmt.Sprintf("from=%d&to=%d&res=1m", f.now.Add(-100*24*time.Hour).UnixMilli(), f.now.UnixMilli())
	for _, kind := range []string{"hops", "probes"} {
		w := f.get(f.url("export", q+"&kind="+kind))
		if kind == "hops" {
			var e struct{ Error string }
			_ = json.Unmarshal(w.Body.Bytes(), &e)
			if w.Code != 400 || !strings.Contains(e.Error, "export too large") || !strings.Contains(e.Error, fmt.Sprint(maxExportRows)) {
				t.Errorf("hops: %d %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Content-Disposition") != "" {
				t.Error("a refused export carries a Content-Disposition")
			}
		}
	}
	// the same period at hourly resolution fits
	w := f.get(f.url("export", fmt.Sprintf("from=%d&to=%d&res=1h", f.now.Add(-100*24*time.Hour).UnixMilli(), f.now.UnixMilli())))
	if w.Code != 200 {
		t.Errorf("hourly 100 days: %d %s", w.Code, w.Body.String())
	}
}

type reportDoc struct {
	Target struct {
		ID   int64
		Name string
		Host string
	}
	From, To    int64
	Resolution  string
	GeneratedAt int64 `json:"generated_at"`
	Summary     struct {
		Source          string
		Samples         int64
		AvailabilityPct *float64 `json:"availability_pct"`
		LossPct         *float64 `json:"loss_pct"`
		AvgMS           *float64 `json:"avg_ms"`
		P95MS           *float64 `json:"p95_ms"`
		JitterMS        *float64 `json:"jitter_ms"`
		MOS             *float64
		HTTP, TCP       []reportProbe
	}
	Incidents []struct {
		Source     string
		ID         int64
		Kind       string
		Severity   string
		State      string
		StartedAt  int64  `json:"started_at"`
		EndedAt    *int64 `json:"ended_at"`
		Ongoing    bool
		DurationMS int64 `json:"duration_ms"`
		Message    string
		Origin     *struct {
			TTL            int
			Address        *string
			Hostname       *string
			ASN            *int
			ASName         *string `json:"as_name"`
			Reason         string
			LossPct        *float64 `json:"loss_pct"`
			Classification string
		}
		Probes []reportProbe
	}
	Truncated bool
	Gaps      []reportGap
	Changes   []struct {
		At     int64
		FromIP *string `json:"from_ip"`
		ToIP   *string `json:"to_ip"`
	} `json:"path_changes"`
}

func TestReport(t *testing.T) {
	f := newReportFixture(t)
	w := f.get(f.url("report", f.rangeQ()))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"target", "from", "to", "generated_at", "resolution", "summary", "incidents", "truncated", "gaps", "path_changes"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("report lacks %q", k)
		}
	}
	var d reportDoc
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Target.Name != "isp-edge" || d.Target.Host != "edge.example" || d.From != f.t0.UnixMilli() || d.To != f.now.UnixMilli() || d.GeneratedAt != f.now.UnixMilli() {
		t.Errorf("header %+v", d)
	}

	// summary: the destination (hop 3) over the whole range
	s := d.Summary
	wantLoss := 100 * float64(f.lost) / float64(f.sent)
	if s.Source != "icmp" || s.Samples != f.sent {
		t.Errorf("source %q samples %d, want icmp %d", s.Source, s.Samples, f.sent)
	}
	if s.LossPct == nil || !near(*s.LossPct, round3(wantLoss)) || s.AvailabilityPct == nil || !near(*s.AvailabilityPct, round3(100-wantLoss)) {
		t.Errorf("loss %v availability %v, want %v", s.LossPct, s.AvailabilityPct, wantLoss)
	}
	if s.AvgMS == nil || !near(*s.AvgMS, 3) || s.P95MS == nil || !near(*s.P95MS, 3) || s.JitterMS == nil || !near(*s.JitterMS, 0) {
		t.Errorf("latency avg %v p95 %v jitter %v", s.AvgMS, s.P95MS, s.JitterMS)
	}
	if s.MOS == nil || !near(*s.MOS, round3(analyze.MOS(3, 0, wantLoss))) {
		t.Errorf("mos %v, want %v", s.MOS, analyze.MOS(3, 0, wantLoss))
	}
	if len(s.TCP) != 1 || len(s.HTTP) != 1 {
		t.Fatalf("probes: %+v", s)
	}
	for _, p := range []reportProbe{s.TCP[0], s.HTTP[0]} {
		if p.SuccessPct == nil || *p.SuccessPct < 80 || *p.SuccessPct > 95 || p.Errors == 0 || p.AvgMS == nil {
			t.Errorf("probe summary %+v", p)
		}
	}

	// incidents: the alert and the degraded event, oldest first, both traced to hop 2
	if len(d.Incidents) != 2 || d.Truncated {
		t.Fatalf("%d incidents: %s", len(d.Incidents), w.Body.String())
	}
	al, ev := d.Incidents[0], d.Incidents[1]
	if ev.StartedAt > al.StartedAt {
		al, ev = ev, al
	}
	_ = al
	for _, in := range d.Incidents {
		if in.Origin == nil || in.Origin.TTL != 2 || in.Origin.Reason != "loss" || in.Origin.Classification != analyze.ClassDegraded {
			t.Fatalf("incident %s/%s origin: %+v", in.Source, in.Kind, in.Origin)
		}
		o := in.Origin
		if o.Address == nil || *o.Address != "10.9.0.2" || o.Hostname == nil || *o.Hostname != evilHostname || o.ASN == nil || *o.ASN != 64500 || o.ASName == nil || *o.ASName != "Evil, Inc" {
			t.Errorf("origin identity: %+v", o)
		}
		if o.LossPct == nil || *o.LossPct != 100 {
			t.Errorf("origin loss %v", o.LossPct)
		}
		var tcp *reportProbe
		for i := range in.Probes {
			if in.Probes[i].Type == "tcp" {
				tcp = &in.Probes[i]
			}
		}
		if tcp == nil || tcp.SuccessPct == nil || *tcp.SuccessPct != 0 || tcp.Errors == 0 {
			t.Errorf("probe impact: %+v", in.Probes)
		}
	}
	a, e := d.Incidents[0], d.Incidents[1]
	if a.Source != "event" || a.Kind != store.EventDegraded || a.Severity != sevWarning || a.DurationMS != (10*time.Minute).Milliseconds() || a.Ongoing || a.EndedAt == nil {
		t.Errorf("event incident: %+v", a)
	}
	if e.Source != "alert" || e.Kind != "final_hop_loss" || e.Severity != sevCritical || e.State != "resolved" || e.DurationMS != (8*time.Minute).Milliseconds() || e.Message == "" {
		t.Errorf("alert incident: %+v", e)
	}

	// gaps and path changes
	if len(d.Gaps) != 1 || d.Gaps[0].From != f.t0.Add(30*time.Minute).UnixMilli() || d.Gaps[0].DurationMS != (5*time.Minute).Milliseconds() {
		t.Errorf("gaps %+v", d.Gaps)
	}
	if len(d.Changes) != 1 || d.Changes[0].At != f.t0.Add(90*time.Minute).UnixMilli() || d.Changes[0].FromIP == nil || *d.Changes[0].FromIP != "192.0.2.1" {
		t.Errorf("path changes %+v", d.Changes)
	}
}

func TestReportQuietRange(t *testing.T) {
	f := newReportFixture(t)
	// the first half hour: clean, no incident, and no gap or change either
	w := f.get(f.url("report", fmt.Sprintf("from=%d&to=%d", f.t0.UnixMilli(), f.t0.Add(25*time.Minute).UnixMilli())))
	var d reportDoc
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 {
		t.Fatalf("%d %v", w.Code, err)
	}
	if len(d.Incidents) != 0 || len(d.Gaps) != 0 || len(d.Changes) != 0 {
		t.Errorf("quiet range: %+v", d)
	}
	if d.Summary.LossPct == nil || *d.Summary.LossPct != 0 || *d.Summary.AvailabilityPct != 100 {
		t.Errorf("quiet summary %+v", d.Summary)
	}
	if !strings.Contains(w.Body.String(), `"incidents":[]`) || !strings.Contains(w.Body.String(), `"gaps":[]`) {
		t.Errorf("empty lists must be [] not null: %s", w.Body.String())
	}
	// a range without data: nulls, not zeros
	w = f.get(f.url("report", fmt.Sprintf("from=%d&to=%d", f.now.Add(-48*time.Hour).UnixMilli(), f.now.Add(-47*time.Hour).UnixMilli())))
	d = reportDoc{}
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 {
		t.Fatalf("%d %v", w.Code, err)
	}
	if d.Summary.Source != "none" && d.Summary.Samples != 0 || d.Summary.LossPct != nil || d.Summary.MOS != nil {
		t.Errorf("empty summary %+v", d.Summary)
	}
}

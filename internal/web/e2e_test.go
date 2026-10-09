package web

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// refE2E is e2e as it was before the read path loaded only what it needs: every TTL of the
// range, with histograms.
func (f *e2eFixture) refE2E(t *testing.T, v targetView, plan store.Plan) e2eResult {
	t.Helper()
	ctx := context.Background()
	var res e2eResult
	cells, err := f.st.ICMPCells(ctx, v.row.ID, plan, store.CellOpts{})
	if err != nil {
		t.Fatal(err)
	}
	res.lastResp = cells.LastRespTTL()
	unresp := v.hasSt && v.state.ICMPUnresponsive
	latestDest := func() int {
		if p, err := f.st.LatestPath(v.row.ID); err == nil {
			return p.DestTTL
		}
		return 0
	}
	probe := func(typ string) {
		ps := v.probesOfType(typ)
		pc, err := f.st.ProbeCells(ctx, ps[0].ID, typ, plan, store.CellOpts{})
		if err != nil {
			t.Fatal(err)
		}
		res.source = typ
		for _, r := range pc.Rolls {
			res.points = append(res.points, pointFromProbe(r))
		}
	}
	icmp := func(rolls []*store.Roll) {
		for _, r := range rolls {
			res.points = append(res.points, pointFromRoll(r))
		}
	}
	if !unresp {
		if rolls, ok := cells.E2ESeries(false); ok {
			res.source, res.ttl = "icmp", latestDest()
			icmp(rolls)
			return res
		}
	}
	if len(v.probesOfType(config.ProbeTCP)) > 0 {
		probe(config.ProbeTCP)
		return res
	}
	if rolls, ok := cells.E2ESeries(true); ok {
		res.source, res.ttl = "last_hop", res.lastResp
		icmp(rolls)
		return res
	}
	if len(v.probesOfType(config.ProbeHTTP)) > 0 {
		probe(config.ProbeHTTP)
	}
	return res
}

func near(a, b float64) bool { return math.Abs(a-b) <= 1e-9*math.Max(1, math.Abs(a)) }

// diffE2E reports how two end-to-end results differ. The 95th percentile and the last
// responding TTL are only compared when the result was asked for them.
func diffE2E(want, got e2eResult, detail bool) string {
	switch {
	case want.source != got.source || want.ttl != got.ttl:
		return fmt.Sprintf("source %q ttl %d, want %q ttl %d", got.source, got.ttl, want.source, want.ttl)
	case detail && want.lastResp != got.lastResp:
		return fmt.Sprintf("lastResp %d, want %d", got.lastResp, want.lastResp)
	case len(want.points) != len(got.points):
		return fmt.Sprintf("%d points, want %d", len(got.points), len(want.points))
	}
	for i, w := range want.points {
		g := got.points[i]
		if w.n != g.n || w.haveAvg != g.haveAvg || w.haveJit != g.haveJit || w.haveLoss != g.haveLoss {
			return fmt.Sprintf("point %d: %+v, want %+v", i, g, w)
		}
		if !near(w.avg, g.avg) || !near(w.min, g.min) || !near(w.max, g.max) || !near(w.jitter, g.jitter) || !near(w.loss, g.loss) {
			return fmt.Sprintf("point %d: %+v, want %+v", i, g, w)
		}
		if detail && !near(w.p95, g.p95) {
			return fmt.Sprintf("point %d: p95 %v, want %v", i, g.p95, w.p95)
		}
		if !detail && g.p95 != 0 {
			return fmt.Sprintf("point %d: p95 %v without histograms", i, g.p95)
		}
	}
	return ""
}

func TestE2EMatchesFullLoad(t *testing.T) {
	f := newE2EFixture(t, nil)
	ctx := context.Background()
	end := f.t0.Add(3 * time.Hour)
	plans := map[string]store.Plan{
		"summary":      store.SinglePlan(f.now.Add(-5*time.Minute), f.now, store.TierRaw),
		"raw":          store.MakePlan(f.t0.Add(-20*time.Minute), f.now, 20),
		"raw/partial":  store.SinglePlan(f.t0.Add(30*time.Minute), f.t0.Add(150*time.Minute), store.TierRaw),
		"1m":           store.MakePlan(f.now.Add(-30*time.Hour), f.now, 30),
		"1m/partial":   store.SinglePlan(f.t0.Add(17*time.Minute+30*time.Second), end, store.Tier1m),
		"1h":           store.MakePlan(f.now.Add(-9*24*time.Hour), f.now, 30),
		"1h/partial":   store.SinglePlan(f.t0.Add(10*time.Minute), f.t0.Add(140*time.Minute), store.Tier1h),
		"raw/switched": store.MakePlan(f.t0.Add(40*time.Minute), f.t0.Add(100*time.Minute), 7),
	}
	sources := map[string]bool{}
	for pname, plan := range plans {
		for _, name := range f.names {
			for _, unresp := range []bool{false, true} {
				v := f.srv.viewOf(f.rows[name])
				if unresp {
					v.hasSt, v.state = true, scheduler.State{ICMPUnresponsive: true}
				}
				want := f.refE2E(t, v, plan)
				if pname == "raw" || pname == "1m" {
					sources[want.source] = true
				}
				for _, detail := range []bool{false, true} {
					got, err := f.srv.e2e(ctx, v, plan, detail)
					if err != nil {
						t.Fatal(err)
					}
					if d := diffE2E(want, got, detail); d != "" {
						t.Errorf("%s/%s unresp=%v detail=%v: %s", pname, name, unresp, detail, d)
					}
				}
			}
		}
	}
	// the fixture has to reach every way of resolving the series, or the test proves little
	for _, src := range []string{"icmp", "tcp", "last_hop", "http", ""} {
		if !sources[src] {
			t.Errorf("no scenario resolves to source %q (saw %v)", src, sources)
		}
	}
}

// TestHopCountNeedsLastResp checks the hop count of a target whose destination never answered:
// the 5-minute summary asks e2e for the last responding TTL.
func TestHopCountNeedsLastResp(t *testing.T) {
	f := newE2EFixture(t, nil)
	v := f.srv.viewOf(f.rows["silent"])
	plan := store.SinglePlan(f.now.Add(-5*time.Minute), f.now, store.TierRaw)
	res, err := f.srv.e2e(context.Background(), v, plan, true)
	if err != nil {
		t.Fatal(err)
	}
	if res.lastResp != 2 || f.srv.hopCount(v, res) != 2 {
		t.Fatalf("lastResp %d, hop count %d, want 2 (the last responding hop of the newest path)", res.lastResp, f.srv.hopCount(v, res))
	}
	var sum summaryJSON
	tj, err := f.srv.buildTarget(context.Background(), v, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sum = tj.Summary
	if sum.HopCount == nil || *sum.HopCount != 2 {
		t.Fatalf("summary hop count %v, want 2", sum.HopCount)
	}
	if sum.E2EP95 == nil {
		t.Fatal("the summary lost its 95th percentile")
	}
}

// A client that disconnects mid-query is neither answered nor logged as a server error; real
// failures still are.
func TestCanceledRequest(t *testing.T) {
	var logs bytes.Buffer
	f := newE2EFixture(t, slog.New(slog.NewTextHandler(&logs, nil)))
	logs.Reset()
	h := f.srv.Handler()
	id := f.rows["change"].ID
	urls := []string{
		"/api/overview?range=1h", "/api/overview?range=24h", "/api/targets",
		fmt.Sprintf("/api/targets/%d/hops?range=1h", id), fmt.Sprintf("/api/targets/%d/timeline?range=24h", id),
		fmt.Sprintf("/api/targets/%d/series?range=1h", id), fmt.Sprintf("/api/targets/%d/series?range=24h&ttl=2", id),
		fmt.Sprintf("/api/targets/%d/probes?range=1h", id), fmt.Sprintf("/api/targets/%d/probes?range=24h", id),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, u := range urls {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, loopbackReq("GET", u).WithContext(ctx))
		if w.Code == http.StatusInternalServerError || strings.Contains(w.Body.String(), "internal error") {
			t.Errorf("GET %s answered a gone client with %d %s", u, w.Code, w.Body.String())
		}
	}
	if logs.Len() != 0 {
		t.Errorf("a disconnected client was logged:\n%s", logs.String())
	}

	// a store that fails for another reason is still a 500, logged
	f.st.Close()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, loopbackReq("GET", "/api/overview?range=1h"))
	if w.Code != http.StatusInternalServerError || !strings.Contains(logs.String(), "request failed") {
		t.Errorf("closed store: %d %s, log %q", w.Code, w.Body.String(), logs.String())
	}
}

// loopbackReq is an in-process request addressed to a loopback Host (httptest defaults to
// example.com, which the Host check of an unauthenticated server refuses).
func loopbackReq(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "127.0.0.1:8095"
	return r
}

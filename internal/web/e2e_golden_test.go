package web

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"testing/fstest"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/store"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/e2e_golden.json from the current handlers")

const (
	e2eRounds = 5400 // three hours of 2 s rounds
	e2eStep   = 2 * time.Second
)

// hopSpec describes how a path answers: hops probed, TTLs up to respond answer, and whether the
// last hop is the destination.
type hopSpec struct {
	hops, respond int
	dest          bool
}

// e2eFixture is a store with six targets that exercise every way the end-to-end series is
// resolved (ICMP destination across a route change, last responding hop, TCP, HTTP, nothing),
// holding the same three hours as raw rounds, 1m rollups and 1h rollups.
type e2eFixture struct {
	st      *store.Store
	srv     *Server
	t0, now time.Time
	names   []string
	rows    map[string]store.TargetRow
	rng     *rand.Rand
}

func newE2EFixture(t *testing.T, logger *slog.Logger) *e2eFixture {
	t.Helper()
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	f := &e2eFixture{t0: time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC), rows: map[string]store.TargetRow{}, rng: rand.New(rand.NewSource(21))}
	f.now = f.t0.Add(3*time.Hour + 10*time.Second)
	st, err := store.Open(filepath.Join(t.TempDir(), "e2e.db"), store.Options{Logger: logger, NoBackground: true, FlushInterval: 20 * time.Millisecond, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f.st = st
	sync := func() {
		if err := st.Sync(); err != nil {
			t.Fatal(err)
		}
	}
	target := func(name string) store.TargetRow {
		tr, err := st.SyncConfigTarget(name, name+".example")
		if err != nil {
			t.Fatal(err)
		}
		f.names = append(f.names, name)
		f.rows[name] = tr
		return tr
	}
	path := func(tr store.TargetRow, dest, hops, at int) int64 {
		id, err := st.NewPath(tr.ID, "192.0.2.1", dest, f.t0.Add(time.Duration(at)*e2eStep))
		if err != nil {
			t.Fatal(err)
		}
		for ttl := 1; ttl <= hops; ttl++ {
			st.AddPathHop(id, ttl, 0, fmt.Sprintf("10.%d.%d.%d", tr.ID, id, ttl))
		}
		return id
	}
	round := func(tr store.TargetRow, path int64, i int, sp hopSpec) {
		hops := make([]store.Hop, sp.hops)
		blackout := i >= 1200 && i < 1230 // a minute with nothing answered
		for k := range hops {
			ttl := k + 1
			hops[k] = store.Hop{TTL: ttl}
			if ttl > sp.respond || blackout || f.rng.Intn(12) == 0 {
				continue
			}
			hops[k].Status = 2
			if sp.dest && ttl == sp.hops {
				hops[k].Status = 1
			}
			hops[k].RTT = time.Duration(float64(ttl)*2000*(0.7+0.6*f.rng.Float64())) * time.Microsecond
			hops[k].Resp = 1
		}
		st.RecordRound(store.Round{TargetID: tr.ID, TS: f.t0.Add(time.Duration(i) * e2eStep), PathID: path, Hops: hops})
		if i%2000 == 1999 {
			sync()
		}
	}
	probes := func(tr store.TargetRow, kinds ...string) {
		for _, kind := range kinds {
			id, err := st.EnsureProbe(tr.ID, kind, kind+"|"+tr.Name, kind)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "http":
				for i := 0; i < e2eRounds/15; i++ {
					smp := store.HTTPSample{ProbeID: id, TS: f.t0.Add(time.Duration(i) * 30 * time.Second), Status: 200, DNS: time.Millisecond, Connect: 10 * time.Millisecond,
						TLS: 20 * time.Millisecond, TTFB: time.Duration(40+f.rng.Intn(60)) * time.Millisecond, Transfer: 5 * time.Millisecond, CertNotAfter: f.t0.Add(90 * 24 * time.Hour)}
					smp.Total = smp.DNS + smp.Connect + smp.TLS + smp.TTFB + smp.Transfer
					if i%9 == 4 {
						smp.Error = "timeout"
					}
					st.RecordHTTP(smp)
				}
			case "tcp":
				for i := 0; i < e2eRounds/5; i++ {
					smp := store.TCPSample{ProbeID: id, TS: f.t0.Add(time.Duration(i) * 10 * time.Second), Connect: time.Duration(15+f.rng.Intn(10)) * time.Millisecond}
					if i%7 == 0 {
						smp.Error = "refused"
					}
					st.RecordTCP(smp)
				}
			}
		}
		sync()
	}

	// change: the destination moves from TTL 3 to TTL 4; rounds alternate between the two
	// path versions for a while. Has HTTP and TCP probes, which ICMP outranks.
	tr := target("change")
	a, b := path(tr, 3, 3, 0), path(tr, 4, 4, 2400)
	for i := 0; i < e2eRounds; i++ {
		if i < 2400 || (i < 2550 && i%2 == 0) {
			round(tr, a, i, hopSpec{3, 3, true})
		} else {
			round(tr, b, i, hopSpec{4, 4, true})
		}
	}
	probes(tr, "http", "tcp")
	// silent: the destination never answers ICMP (last responding hop: TTL 3, then 2); HTTP only,
	// so the series is the last hop.
	tr = target("silent")
	a, b = path(tr, 0, 5, 0), path(tr, 0, 4, 3000)
	for i := 0; i < e2eRounds; i++ {
		if i < 3000 {
			round(tr, a, i, hopSpec{5, 3, false})
		} else {
			round(tr, b, i, hopSpec{4, 2, false})
		}
	}
	probes(tr, "http")
	// silent-tcp: the same, with a TCP probe that takes over.
	tr = target("silent-tcp")
	a = path(tr, 0, 5, 0)
	for i := 0; i < e2eRounds; i++ {
		round(tr, a, i, hopSpec{5, 3, false})
	}
	probes(tr, "tcp")
	// late: the destination starts answering after a route change.
	tr = target("late")
	a, b = path(tr, 0, 4, 0), path(tr, 3, 3, 2700)
	for i := 0; i < e2eRounds; i++ {
		if i < 2700 {
			round(tr, a, i, hopSpec{4, 2, false})
		} else {
			round(tr, b, i, hopSpec{3, 3, true})
		}
	}
	// dark: the destination (TTL 4) went dark while TTL 3 still answers.
	tr = target("dark")
	a = path(tr, 4, 4, 0)
	for i := 0; i < e2eRounds; i++ {
		round(tr, a, i, hopSpec{4, 3, true})
	}
	// dark-change: the same, then a route change to a path whose destination never answers.
	tr = target("dark-change")
	a, b = path(tr, 4, 4, 0), path(tr, 0, 4, 2700)
	for i := 0; i < e2eRounds; i++ {
		if i < 2700 {
			round(tr, a, i, hopSpec{4, 3, true})
		} else {
			round(tr, b, i, hopSpec{4, 2, false})
		}
	}
	// http-only: no ICMP at all.
	tr = target("http-only")
	probes(tr, "http")
	// empty: a target without data.
	target("empty")

	sync()
	st.FlushDue(f.now)
	sync()
	f.srv = New(Deps{Store: st, Logger: logger, Now: func() time.Time { return f.now },
		Static: fstest.MapFS{"index.html": {Data: []byte("<!doctype html>")}}})
	return f
}

// goldenURLs lists the history requests the golden file covers: every endpoint for every target
// over ranges that read the raw, 1m and 1h tiers.
func (f *e2eFixture) goldenURLs() []string {
	urls := []string{"/api/targets"}
	for _, rg := range []string{"1h", "6h", "24h", "8d"} {
		urls = append(urls, "/api/overview?buckets=12&range="+rg)
		for _, name := range f.names {
			base := fmt.Sprintf("/api/targets/%d/", f.rows[name].ID)
			q := "?buckets=12&range=" + rg
			urls = append(urls, base+"hops"+q, base+"timeline"+q, base+"series"+q, base+"series"+q+"&ttl=2", base+"series"+q+"&ttl=4", base+"probes"+q)
		}
	}
	return urls
}

func e2eGet(t testing.TB, h http.Handler, url string) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, loopbackReq("GET", url))
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", url, w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

// TestE2EGolden pins the history endpoints byte for byte (as JSON). The golden file was written
// by the handlers as they were before the read path loaded only what it needs.
func TestE2EGolden(t *testing.T) {
	f := newE2EFixture(t, nil)
	h := f.srv.Handler()
	got := map[string]json.RawMessage{}
	for _, u := range f.goldenURLs() {
		var buf bytes.Buffer
		if err := json.Compact(&buf, e2eGet(t, h, u)); err != nil {
			t.Fatal(err)
		}
		got[u] = buf.Bytes()
	}
	file := filepath.Join("testdata", "e2e_golden.json")
	if *updateGolden {
		b, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]json.RawMessage
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	var urls []string
	for u := range want {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	if len(want) != len(got) {
		t.Fatalf("golden file has %d responses, handlers produced %d (run with -update after changing the fixture)", len(want), len(got))
	}
	for _, u := range urls {
		var w, g any
		if err := json.Unmarshal(want[u], &w); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(got[u], &g); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if !reflect.DeepEqual(w, g) {
			t.Errorf("GET %s differs from the golden file\n got: %.600s\nwant: %.600s", u, got[u], want[u])
		}
	}
}

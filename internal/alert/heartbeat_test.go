package alert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func TestHeartbeatOnlyWhileHealthy(t *testing.T) {
	var hits atomic.Int32
	status := atomic.Int32{}
	status.Store(200)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		hits.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	defer ts.Close()
	var healthy atomic.Bool
	healthy.Store(true)
	hb := NewHeartbeat(quietLog(), healthy.Load)
	hb.Configure(config.HeartbeatConfig{URL: ts.URL + "/ping/secret", Interval: config.Duration(time.Minute)})
	want(t, hb.Beat(context.Background()) && hits.Load() == 1, "healthy: one GET")
	healthy.Store(false)
	want(t, !hb.Beat(context.Background()) && hits.Load() == 1, "unhealthy: heartbeat withheld (that is the point of a dead-man's switch)")
	healthy.Store(true)
	status.Store(500)
	want(t, !hb.Beat(context.Background()), "non-2xx is a failed beat")
	hb2 := NewHeartbeat(quietLog(), nil)
	hb2.Configure(config.HeartbeatConfig{})
	want(t, !hb2.Beat(context.Background()) && hits.Load() == 2, "off without a URL")
}

func TestHeartbeatLoopRespectsInterval(t *testing.T) {
	var hits atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer ts.Close()
	hb := NewHeartbeat(quietLog(), func() bool { return true })
	hb.Configure(config.HeartbeatConfig{URL: ts.URL, Interval: config.Duration(100 * time.Millisecond)})
	hb.Start()
	time.Sleep(450 * time.Millisecond)
	hb.Close()
	n := hits.Load()
	want(t, n >= 3 && n <= 6, "about one beat per interval, got %d", n)
	time.Sleep(200 * time.Millisecond)
	want(t, hits.Load() == n, "no beats after Close")
}

func TestHeartbeatErrorsDoNotLeakURL(t *testing.T) {
	var buf strings.Builder
	log := newBufLogger(&buf)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := ts.URL + "/ping/SECRETUUID"
	ts.Close()
	hb := NewHeartbeat(log, nil)
	hb.Configure(config.HeartbeatConfig{URL: url, Interval: config.Duration(time.Minute)})
	hb.Beat(context.Background())
	want(t, buf.Len() > 0 && !strings.Contains(buf.String(), "SECRETUUID"), "log %q", buf.String())
}

package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestHTTPProbeHeaderEnvAndRedirectStrip(t *testing.T) {
	t.Setenv("PATHWATCH_PROBE_KEY", "from-env")
	t.Setenv("PATHWATCH_PASSWORD", "hunter2")
	var gotA, gotB http.Header
	var hitsB atomic.Int32
	l2, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 not available:", err)
	}
	srvB := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsB.Add(1)
		gotB = r.Header.Clone()
	}))
	srvB.Listener = l2
	srvB.Start()
	defer srvB.Close()
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, srvB.URL+"/", http.StatusFound)
			return
		}
		gotA = r.Header.Clone()
	}))
	defer srvA.Close()

	hdr := map[string]string{"X-Api-Key": "${PATHWATCH_PROBE_KEY}", "X-Other": "${PATHWATCH_PASSWORD}", "X-Lit": "a$$b"}
	p := httpProbeCfg(srvA.URL + "/plain")
	p.Headers = hdr
	if res := HTTPProbe(context.Background(), p, HTTPOptions{}); !res.OK {
		t.Fatalf("%+v", res)
	}
	if gotA.Get("X-Api-Key") != "from-env" || gotA.Get("X-Other") != "" || gotA.Get("X-Lit") != "a$b" {
		t.Errorf("expansion: %v", gotA)
	}
	if hdr["X-Api-Key"] != "${PATHWATCH_PROBE_KEY}" {
		t.Error("probe definition was modified")
	}

	// cross-host redirect, unpinned: configured headers are dropped
	p = httpProbeCfg(srvA.URL + "/redir")
	p.FollowRedirects, p.PinIP, p.Headers = true, false, map[string]string{"X-Api-Key": "s", "Authorization": "Bearer t"}
	res := HTTPProbe(context.Background(), p, HTTPOptions{})
	if !res.OK || res.Redirects != 1 || hitsB.Load() != 1 {
		t.Fatalf("redirect: %+v hits=%d", res, hitsB.Load())
	}
	if gotB.Get("X-Api-Key") != "" || gotB.Get("Authorization") != "" {
		t.Errorf("headers leaked to the redirect target: %v", gotB)
	}

	// pinned: the redirect goes back to the pinned address, never to the other host
	hitsB.Store(0)
	p.PinIP = true
	HTTPProbe(context.Background(), p, HTTPOptions{Pin: netip.MustParseAddr("127.0.0.1")})
	if hitsB.Load() != 0 {
		t.Error("pinned probe reached the redirect target")
	}

	// same-origin redirects keep the headers
	var seen string
	srvC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redir" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		seen = r.Header.Get("X-Api-Key")
	}))
	defer srvC.Close()
	p = httpProbeCfg(srvC.URL + "/redir")
	p.FollowRedirects, p.Headers = true, map[string]string{"X-Api-Key": "s"}
	HTTPProbe(context.Background(), p, HTTPOptions{})
	if seen != "s" {
		t.Errorf("same-origin redirect dropped the header: %q", seen)
	}
}

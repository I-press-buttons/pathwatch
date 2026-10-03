package enrich

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memPersist struct {
	mu sync.Mutex
	m  map[netip.Addr]Info
}

func (p *memPersist) Load() (map[netip.Addr]Info, error) { return p.m, nil }
func (p *memPersist) Put(a netip.Addr, i Info) {
	p.mu.Lock()
	p.m[a] = i
	p.mu.Unlock()
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timeout")
}

func TestAsyncReverseDNSAndCache(t *testing.T) {
	var calls atomic.Int32
	p := &memPersist{m: map[netip.Addr]Info{}}
	e := New(Options{ReverseDNS: true, Persist: p, LookupAddr: func(ctx context.Context, a string) ([]string, error) {
		calls.Add(1)
		if a == "192.168.1.1" {
			return []string{"router.lan."}, nil
		}
		return nil, errors.New("no such host")
	}})
	defer e.Close()
	a := netip.MustParseAddr("192.168.1.1")
	if i := e.Lookup(a); i.Hostname != "" {
		t.Error("first lookup must not block and returns empty")
	}
	waitFor(t, func() bool { return e.Lookup(a).Hostname == "router.lan" })
	n := calls.Load()
	for i := 0; i < 20; i++ {
		e.Lookup(a)
	}
	if calls.Load() != n {
		t.Error("cached address looked up again")
	}
	// negative result is cached too
	b := netip.MustParseAddr("8.8.4.4")
	e.Lookup(b)
	waitFor(t, func() bool { p.mu.Lock(); defer p.mu.Unlock(); _, ok := p.m[b]; return ok })
	n = calls.Load()
	e.Lookup(b)
	e.Lookup(b)
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != n {
		t.Error("negative cache not honoured")
	}
	// persisted entries are loaded on startup
	e2 := New(Options{ReverseDNS: true, Persist: p, LookupAddr: func(context.Context, string) ([]string, error) { return nil, errors.New("x") }})
	defer e2.Close()
	if e2.Lookup(a).Hostname != "router.lan" {
		t.Error("persisted cache not loaded")
	}
	// disabled reverse DNS never calls the resolver
	var c2 atomic.Int32
	e3 := New(Options{ReverseDNS: false, LookupAddr: func(context.Context, string) ([]string, error) { c2.Add(1); return nil, nil }})
	defer e3.Close()
	e3.Lookup(netip.MustParseAddr("1.2.3.4"))
	time.Sleep(50 * time.Millisecond)
	if c2.Load() != 0 {
		t.Error("resolver called with reverse DNS disabled")
	}
	// invalid / unspecified addresses are ignored
	if i := e3.Lookup(netip.Addr{}); i.Hostname != "" {
		t.Error("invalid addr")
	}
}

func TestIsPublic(t *testing.T) {
	for s, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "192.168.0.1": false, "10.1.2.3": false, "172.16.0.1": false,
		"100.64.0.1": false, "100.127.255.1": false, "100.128.0.1": true, "127.0.0.1": false, "169.254.1.1": false,
		"224.0.0.1": false, "2606:4700::1111": true, "fe80::1": false, "fd00::1": false, "::1": false,
	} {
		if IsPublic(netip.MustParseAddr(s)) != want {
			t.Errorf("IsPublic(%s) != %v", s, want)
		}
	}
}

// Package enrich resolves hop addresses to hostnames (reverse DNS) and, optionally, to AS
// numbers using a user-supplied MaxMind GeoLite2 ASN database. Lookups run asynchronously with a
// cache so they never delay probing.
package enrich

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Info is the enrichment of one address.
type Info struct {
	Hostname  string
	ASN       int
	ASName    string
	UpdatedAt time.Time
}

// Persister stores enrichment across restarts (the store implements it via an adapter).
type Persister interface {
	Load() (map[netip.Addr]Info, error)
	Put(addr netip.Addr, i Info)
}

// Options configure an Enricher.
type Options struct {
	ReverseDNS bool
	ASNDBPath  string // empty = no ASN lookups
	Persist    Persister
	Logger     *slog.Logger
	// LookupAddr overrides reverse DNS (tests). Default: the system resolver.
	LookupAddr               func(ctx context.Context, addr string) ([]string, error)
	Workers                  int
	PositiveTTL, NegativeTTL time.Duration
}

// Enricher is safe for concurrent use.
type Enricher struct {
	opts  Options
	log   *slog.Logger
	asn   *maxminddb.Reader
	mu    sync.RWMutex
	cache map[netip.Addr]Info
	infl  map[netip.Addr]bool
	queue chan netip.Addr
	wg    sync.WaitGroup
	quit  chan struct{}
	once  sync.Once
}

// New creates an Enricher and starts its workers. Close stops them.
func New(o Options) *Enricher {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Workers <= 0 {
		o.Workers = 4
	}
	if o.PositiveTTL == 0 {
		o.PositiveTTL = 24 * time.Hour
	}
	if o.NegativeTTL == 0 {
		o.NegativeTTL = time.Hour
	}
	if o.LookupAddr == nil {
		o.LookupAddr = net.DefaultResolver.LookupAddr
	}
	e := &Enricher{opts: o, log: o.Logger, cache: map[netip.Addr]Info{}, infl: map[netip.Addr]bool{}, queue: make(chan netip.Addr, 512), quit: make(chan struct{})}
	if o.ASNDBPath != "" {
		r, err := maxminddb.Open(o.ASNDBPath)
		if err != nil {
			e.log.Warn("cannot open ASN database; ASN enrichment disabled", "path", o.ASNDBPath, "err", err)
		} else {
			e.asn = r
			e.log.Info("ASN database loaded", "path", o.ASNDBPath)
		}
	}
	if o.Persist != nil {
		if m, err := o.Persist.Load(); err == nil {
			for a, i := range m {
				e.cache[a] = i
			}
		} else {
			e.log.Warn("loading cached enrichment failed", "err", err)
		}
	}
	for i := 0; i < o.Workers; i++ {
		e.wg.Add(1)
		go e.worker()
	}
	return e
}

// Close stops the workers.
func (e *Enricher) Close() {
	e.once.Do(func() {
		close(e.quit)
		e.wg.Wait()
		if e.asn != nil {
			e.asn.Close()
		}
	})
}

// IsPublic reports whether addr is a globally routable address (ASN lookups are only done for those).
func IsPublic(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		if b[0] == 100 && b[1]&0xc0 == 64 { // 100.64.0.0/10 CGNAT
			return false
		}
	}
	return true
}

func lookupable(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !a.IsUnspecified() && !a.IsMulticast()
}

// Lookup returns cached enrichment for addr without blocking. When the address is unknown or
// stale a background lookup is scheduled and the (possibly empty) cached value is returned.
func (e *Enricher) Lookup(addr netip.Addr) Info {
	addr = addr.Unmap()
	if !lookupable(addr) {
		return Info{}
	}
	e.mu.RLock()
	i, ok := e.cache[addr]
	e.mu.RUnlock()
	ttl := e.opts.PositiveTTL
	if i.Hostname == "" && i.ASN == 0 {
		ttl = e.opts.NegativeTTL
	}
	if !ok || time.Since(i.UpdatedAt) > ttl {
		e.request(addr)
	}
	return i
}

func (e *Enricher) request(addr netip.Addr) {
	e.mu.Lock()
	if e.infl[addr] {
		e.mu.Unlock()
		return
	}
	e.infl[addr] = true
	e.mu.Unlock()
	select {
	case e.queue <- addr:
	default:
		e.mu.Lock()
		delete(e.infl, addr)
		e.mu.Unlock()
	}
}

func (e *Enricher) worker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.quit:
			return
		case a := <-e.queue:
			info := e.resolve(a)
			e.mu.Lock()
			e.cache[a] = info
			delete(e.infl, a)
			e.mu.Unlock()
			if e.opts.Persist != nil {
				e.opts.Persist.Put(a, info)
			}
		}
	}
}

type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

func (e *Enricher) resolve(a netip.Addr) Info {
	info := Info{UpdatedAt: time.Now()}
	if e.opts.ReverseDNS {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		names, err := e.opts.LookupAddr(ctx, a.String())
		cancel()
		if err == nil && len(names) > 0 {
			info.Hostname = strings.TrimSuffix(names[0], ".")
		}
	}
	if e.asn != nil && IsPublic(a) {
		var rec asnRecord
		if err := e.asn.Lookup(net.IP(a.AsSlice()), &rec); err == nil && rec.Number != 0 {
			info.ASN, info.ASName = int(rec.Number), rec.Org
		}
	}
	return info
}

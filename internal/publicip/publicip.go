// Package publicip watches this network's public IPv4 and IPv6 addresses. Each address is an
// open "public_ip" event in the store (target_id NULL); a change closes it and opens the next one
// with the previous address in its details, which the alert engine turns into a public_ip_change
// alert. A different answer is confirmed by a second check shortly after, so a CGNAT pool that
// answers from several addresses or one odd reply does not count as a change.
package publicip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// Families.
const (
	IPv4 = "ipv4"
	IPv6 = "ipv6"
)

// EventKind is the store event kind of a public address.
const EventKind = "public_ip"

const (
	lookupTimeout = 5 * time.Second
	confirmAfter  = 30 * time.Second
	firstCheck    = 3 * time.Second
	maxBody       = 256
)

// OpenDNS resolvers that answer myip.opendns.com with the address the query came from.
var (
	openDNS4 = []string{"208.67.222.222:53", "208.67.220.220:53"}
	openDNS6 = []string{"[2620:119:35::35]:53", "[2620:119:53::53]:53"}
)

// Details is the JSON stored with a public_ip event.
type Details struct {
	Family   string `json:"family"`
	Addr     string `json:"addr"`
	Previous string `json:"previous,omitempty"`
	ASN      int    `json:"asn,omitempty"`
	ASName   string `json:"as_name,omitempty"`
	PrevASN  int    `json:"prev_asn,omitempty"`
	PrevName string `json:"prev_as_name,omitempty"`
}

// ParseDetails decodes an event's details.
func ParseDetails(b []byte) (Details, bool) {
	var d Details
	if len(b) == 0 || json.Unmarshal(b, &d) != nil || d.Addr == "" {
		return d, false
	}
	return d, true
}

// Info is enrichment of an address (the hop enricher provides it).
type Info struct {
	ASN      int
	ASName   string
	Hostname string
}

// Enricher looks up an address without blocking (it may return nothing the first time).
type Enricher func(netip.Addr) Info

// Lookup finds the public address of one family.
type Lookup func(ctx context.Context, family string) (netip.Addr, error)

// State is one family's current knowledge.
type State struct {
	Family      string
	Addr        string // "" = never seen
	Since       time.Time
	EventID     int64
	LastChecked time.Time
	LastOK      time.Time
	LastErr     string
	Pending     string // a different address waiting for confirmation
}

// Options configure a Monitor.
type Options struct {
	Store  *store.Store
	Log    *slog.Logger
	Enrich Enricher // optional
	Lookup Lookup   // optional: overrides the configured source (tests)
	Now    func() time.Time
	// OnChange is called after a recorded change or first observation (SSE refresh); optional.
	OnChange func()
}

// Monitor runs the checks.
type Monitor struct {
	o   Options
	log *slog.Logger

	mu     sync.Mutex
	cfg    config.PublicIPConfig
	states map[string]*State
	check  sync.Mutex // serializes checks

	reload  chan struct{}
	stop    chan struct{}
	done    chan struct{}
	started bool
}

// New creates a monitor and restores the current addresses from the store.
func New(o Options) *Monitor {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	m := &Monitor{o: o, log: o.Log, states: map[string]*State{}, reload: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	for _, f := range []string{IPv4, IPv6} {
		m.states[f] = &State{Family: f}
	}
	if o.Store != nil {
		evs, err := o.Store.OpenEvents(EventKind)
		if err != nil {
			m.log.Warn("public ip: reading the current addresses failed", "err", err)
		}
		for _, ev := range evs {
			d, ok := ParseDetails(ev.Details)
			st := m.states[d.Family]
			if !ok || st == nil {
				continue
			}
			if st.EventID != 0 && ev.ID < st.EventID {
				o.Store.CloseEvent(ev.ID, ev.From) // a stray duplicate; keep the newest
				continue
			}
			st.Addr, st.Since, st.EventID = d.Addr, ev.From, ev.ID
		}
	}
	return m
}

// Configure applies settings (it may be called while running).
func (m *Monitor) Configure(c config.PublicIPConfig) {
	m.mu.Lock()
	same := m.cfg == c
	m.cfg = c
	m.mu.Unlock()
	if same {
		return // another section was saved: keep the schedule
	}
	select {
	case m.reload <- struct{}{}:
	default:
	}
}

// Config returns the current settings.
func (m *Monitor) Config() config.PublicIPConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// States returns copies of the per-family states (IPv4 first).
func (m *Monitor) States() []State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return []State{*m.states[IPv4], *m.states[IPv6]}
}

// Start launches the check loop.
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	go m.loop()
}

// Close stops the loop.
func (m *Monitor) Close() {
	m.mu.Lock()
	started := m.started
	m.mu.Unlock()
	select {
	case <-m.stop:
		return
	default:
		close(m.stop)
	}
	if started {
		select {
		case <-m.done:
		case <-time.After(2*lookupTimeout + time.Second):
		}
	}
}

func (m *Monitor) loop() {
	defer close(m.done)
	wait := firstCheck
	for {
		t := time.NewTimer(wait)
		select {
		case <-m.stop:
			t.Stop()
			return
		case <-m.reload:
			t.Stop()
			wait = firstCheck // settings changed: check soon (turning it on shows an address quickly)
			continue
		case <-t.C:
		}
		cfg := m.Config()
		if !cfg.Enabled {
			wait = time.Hour
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			select {
			case <-m.stop:
				cancel()
			case <-ctx.Done():
			}
		}()
		pending := m.Check(ctx)
		cancel()
		wait = cfg.Interval.D()
		if pending {
			wait = confirmAfter
		}
	}
}

// Check looks up every enabled family once and records confirmed changes. It reports whether a
// different address is waiting for confirmation.
func (m *Monitor) Check(ctx context.Context) bool {
	m.check.Lock()
	defer m.check.Unlock()
	cfg := m.Config()
	lookup := m.o.Lookup
	if lookup == nil {
		lookup = sourceLookup(cfg.Source)
	}
	families := []string{IPv4}
	if !cfg.SkipIPv6 {
		families = append(families, IPv6)
	}
	pending := false
	for _, f := range families {
		lctx, cancel := context.WithTimeout(ctx, 2*lookupTimeout)
		a, err := lookup(lctx, f)
		cancel()
		if ctx.Err() != nil {
			return false
		}
		if m.observe(f, a, err) {
			pending = true
		}
	}
	return pending
}

// observe records one lookup result; it reports whether a change awaits confirmation.
func (m *Monitor) observe(family string, a netip.Addr, err error) bool {
	now := m.o.Now().UTC()
	m.mu.Lock()
	st := m.states[family]
	st.LastChecked = now
	if err != nil {
		st.LastErr = err.Error()
		st.Pending = ""
		m.mu.Unlock()
		return false
	}
	st.LastErr, st.LastOK = "", now
	addr := a.String()
	switch {
	case addr == st.Addr:
		st.Pending = ""
		m.mu.Unlock()
		return false
	case st.Addr != "" && st.Pending != addr:
		st.Pending = addr // first sighting of a different address: confirm it before recording
		m.mu.Unlock()
		return true
	}
	prev, prevID := st.Addr, st.EventID
	st.Pending = ""
	m.mu.Unlock()

	d := Details{Family: family, Addr: addr, Previous: prev}
	if m.o.Enrich != nil {
		i := m.o.Enrich(a)
		d.ASN, d.ASName = i.ASN, i.ASName
		if p, perr := netip.ParseAddr(prev); perr == nil {
			pi := m.o.Enrich(p)
			d.PrevASN, d.PrevName = pi.ASN, pi.ASName
		}
	}
	b, _ := json.Marshal(d)
	if m.o.Store == nil {
		return false
	}
	if prevID != 0 {
		m.o.Store.CloseEvent(prevID, now)
	}
	id, ierr := m.o.Store.InsertEvent(store.Event{Kind: EventKind, From: now, Details: b})
	if ierr != nil {
		m.log.Error("public ip: recording the address failed", "err", ierr)
		return false
	}
	m.mu.Lock()
	st.Addr, st.Since, st.EventID = addr, now, id
	m.mu.Unlock()
	if prev == "" {
		m.log.Info("public ip address", "family", family, "addr", addr)
	} else {
		m.log.Warn("public ip address changed", "family", family, "from", prev, "to", addr)
	}
	if m.o.OnChange != nil {
		m.o.OnChange()
	}
	return false
}

// sourceLookup returns the lookup for a configured source.
func sourceLookup(source string) Lookup {
	if source == "" || source == config.PublicIPSourceOpenDNS {
		return openDNSLookup
	}
	return httpLookup(source)
}

func openDNSLookup(ctx context.Context, family string) (netip.Addr, error) {
	servers, rec := openDNS4, "A"
	if family == IPv6 {
		servers, rec = openDNS6, "AAAA"
	}
	var lastErr error
	for _, srv := range servers {
		res := probe.DNSQuery(ctx, srv, "myip.opendns.com", rec, lookupTimeout)
		if res.OK && len(res.Addrs) > 0 {
			return res.Addrs[0], nil
		}
		lastErr = res.Err
		if lastErr == nil {
			// OpenDNS always answers this name; an empty answer comes from another resolver
			lastErr = errors.New("OpenDNS gave no address: DNS on this network is probably redirected to another resolver; use an http(s) source instead")
		}
		if ctx.Err() != nil {
			break
		}
	}
	return netip.Addr{}, friendly(family, lastErr)
}

func httpLookup(u string) Lookup {
	return func(ctx context.Context, family string) (netip.Addr, error) {
		network := "tcp4"
		if family == IPv6 {
			network = "tcp6"
		}
		d := &net.Dialer{Timeout: lookupTimeout}
		tr := &http.Transport{
			Proxy:             nil, // measure this network, not a proxy's
			DialContext:       func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) },
			DisableKeepAlives: true,
		}
		defer tr.CloseIdleConnections()
		c := &http.Client{Transport: tr, Timeout: 2 * lookupTimeout}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return netip.Addr{}, errors.New("invalid source URL")
		}
		req.Header.Set("User-Agent", "pathwatch")
		resp, err := c.Do(req)
		if err != nil {
			var ue interface{ Unwrap() error }
			if errors.As(err, &ue) {
				err = ue.Unwrap()
			}
			return netip.Addr{}, friendly(family, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if resp.StatusCode != http.StatusOK {
			return netip.Addr{}, fmt.Errorf("source answered HTTP %d", resp.StatusCode)
		}
		a, err := netip.ParseAddr(strings.TrimSpace(string(body)))
		if err != nil {
			return netip.Addr{}, errors.New("source did not answer with an address")
		}
		a = a.Unmap()
		if (family == IPv6) != a.Is6() {
			return netip.Addr{}, fmt.Errorf("source answered with a %s address over %s", map[bool]string{true: "IPv6", false: "IPv4"}[a.Is6()], family)
		}
		return a, nil
	}
}

// friendly turns "no route" style errors for IPv6 into a plain "no IPv6 connectivity".
func friendly(family string, err error) error {
	if err == nil {
		return errors.New("lookup failed")
	}
	if family == IPv6 {
		l := strings.ToLower(err.Error())
		if strings.Contains(l, "no suitable address") {
			return errors.New("the source has no IPv6 address (use a dual-stack source)")
		}
		if strings.Contains(l, "unreachable") || strings.Contains(l, "no route") || strings.Contains(l, "cannot assign") || strings.Contains(l, "address family") {
			return errors.New("no IPv6 connectivity")
		}
	}
	return err
}

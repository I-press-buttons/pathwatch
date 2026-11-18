// Package scheduler runs the probes: one goroutine group per target (ICMP trace rounds, HTTP and
// TCP probes) and per DNS probe, with per-cycle resolution pinning, path versioning, monitor gap
// detection and live fan-out to the web hub and the alert engine.
package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// Resolver resolves host names (net.DefaultResolver implements it).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// RoundEvent is a completed ICMP round, for live streaming.
type RoundEvent struct {
	TargetID int64
	TS       time.Time
	Hops     []store.Hop
}

// ProbeEvent is a completed HTTP/TCP/DNS probe, for live streaming and the alert engine.
type ProbeEvent struct {
	TargetID int64 // 0 for DNS probes
	ProbeID  int64
	Type     string
	TS       time.Time
	OK       bool
	TotalMS  float64
	Sample   alert.ProbeSample
}

// Observer receives live events. Implementations must not block.
type Observer interface {
	Round(RoundEvent)
	Probe(ProbeEvent)
	// TargetsChanged is called when targets were added, removed, paused or resumed.
	TargetsChanged()
}

type nopObserver struct{}

func (nopObserver) Round(RoundEvent) {}
func (nopObserver) Probe(ProbeEvent) {}
func (nopObserver) TargetsChanged()  {}

// Options configure a Scheduler.
type Options struct {
	Store    *store.Store
	Prober   probe.Prober // nil = ICMP unavailable (HTTP/TCP/DNS probes still run)
	Observer Observer
	Logger   *slog.Logger
	Resolver Resolver
	Defaults config.Defaults
	Version  string
	// Stagger is the delay between consecutive TTL probes of a round (default 3ms).
	Stagger time.Duration
	// Debounce is the number of consecutive different rounds that start a new path version (default 3).
	Debounce int
}

// ProbeRef identifies a probe of a target.
type ProbeRef struct {
	ID    int64
	Type  string
	Key   string
	Label string
}

// State is a snapshot of a target for the API.
type State struct {
	Row              store.TargetRow
	Spec             config.Target
	HasSpec          bool
	Running          bool
	Probes           []ProbeRef
	ResolvedIP       string
	ICMPUnresponsive bool
	LastRound        time.Time
	ICMPEnabled      bool // the target has an icmp-trace probe and a prober is available
	ICMPIntervalMS   int
}

type entry struct {
	row    store.TargetRow
	spec   config.Target
	probes []ProbeRef
	run    *runner
}

type dnsEntry struct {
	spec config.DNSProbe
	ref  ProbeRef
	stop context.CancelFunc
	done chan struct{}
}

// Scheduler owns all probe goroutines.
type Scheduler struct {
	opts Options
	log  *slog.Logger
	obs  Observer

	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
	entries  map[int64]*entry
	dns      map[string]*dnsEntry
	started  time.Time
	flowSeed uint16
	wg       sync.WaitGroup
}

// New creates a scheduler. Call Start before adding targets.
func New(o Options) *Scheduler {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Observer == nil {
		o.Observer = nopObserver{}
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.Stagger == 0 {
		o.Stagger = 3 * time.Millisecond
	}
	if o.Debounce == 0 {
		o.Debounce = 3
	}
	return &Scheduler{
		opts: o, log: o.Logger, obs: o.Observer,
		entries: map[int64]*entry{}, dns: map[string]*dnsEntry{},
		flowSeed: uint16(rand.UintN(60000)) + 1,
	}
}

// Start sets the base context of all goroutines.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.started = time.Now()
}

// Close stops every runner and waits for the goroutines to finish.
func (s *Scheduler) Close() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// ICMPMode returns the active prober mode ("raw", "dgram" or "unavailable").
func (s *Scheduler) ICMPMode() string {
	if s.opts.Prober == nil {
		return probe.ModeUnavailable
	}
	return s.opts.Prober.Mode()
}

func (s *Scheduler) flowFor(id int64) uint16 {
	f := uint16((int64(s.flowSeed) + id*7) % 65534)
	return f + 1
}

// probeRefs registers the probes of a spec in the database.
func (s *Scheduler) probeRefs(targetID int64, spec config.Target) ([]ProbeRef, error) {
	var refs []ProbeRef
	reg := func(typ, key, label string) error {
		id, err := s.opts.Store.EnsureProbe(targetID, typ, key, label)
		if err != nil {
			return err
		}
		refs = append(refs, ProbeRef{ID: id, Type: typ, Key: key, Label: label})
		return nil
	}
	if spec.ICMP != nil {
		if err := reg(config.ProbeICMPTrace, config.ProbeICMPTrace, "ICMP trace"); err != nil {
			return nil, err
		}
	}
	for _, p := range spec.Probes {
		if err := reg(p.Type, p.Key(), p.Label()); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

// register installs (or replaces) the entry for a stored target and starts its runner unless paused.
func (s *Scheduler) register(row store.TargetRow, spec config.Target) error {
	refs, err := s.probeRefs(row.ID, spec)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return errors.New("scheduler not started")
	}
	old := s.entries[row.ID]
	if old != nil && old.run != nil {
		if reflect.DeepEqual(old.spec, spec) && !row.Paused && old.row.Host == row.Host && old.row.Name == row.Name {
			old.row = row
			return nil // unchanged and running
		}
		s.stopRunnerLocked(old)
	}
	e := &entry{row: row, spec: spec, probes: refs}
	s.entries[row.ID] = e
	if !row.Paused && row.Active {
		s.startRunnerLocked(e)
	}
	return nil
}

func (s *Scheduler) startRunnerLocked(e *entry) {
	r := newRunner(s, e.row, e.spec, e.probes)
	e.run = r
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		r.run(s.ctx)
	}()
}

func (s *Scheduler) stopRunnerLocked(e *entry) {
	if e.run == nil {
		return
	}
	r := e.run
	e.run = nil
	r.stop()
}

// SyncConfig reconciles config-file targets and DNS probes with the running state. It is used
// at startup and on SIGHUP. Targets no longer in the config are marked inactive (their data is
// kept) and stopped.
func (s *Scheduler) SyncConfig(targets []config.Target, dns []config.DNSProbe) error {
	names := make([]string, 0, len(targets))
	keep := map[int64]bool{}
	for _, t := range targets {
		row, err := s.opts.Store.SyncConfigTarget(t.Name, t.Host)
		if err != nil {
			return fmt.Errorf("target %s: %w", t.Name, err)
		}
		names = append(names, t.Name)
		keep[row.ID] = true
		if err := s.register(row, t); err != nil {
			return fmt.Errorf("target %s: %w", t.Name, err)
		}
	}
	if err := s.opts.Store.DeactivateConfigTargetsExcept(names); err != nil {
		return err
	}
	s.mu.Lock()
	for id, e := range s.entries {
		if e.row.Source == config.SourceConfig && !keep[id] {
			s.stopRunnerLocked(e)
			delete(s.entries, id)
		}
	}
	s.mu.Unlock()
	if err := s.syncDNS(dns); err != nil {
		return err
	}
	s.obs.TargetsChanged()
	return nil
}

func (s *Scheduler) syncDNS(list []config.DNSProbe) error {
	want := map[string]config.DNSProbe{}
	for _, d := range list {
		want[d.Name] = d
	}
	s.mu.Lock()
	for name, e := range s.dns {
		if w, ok := want[name]; !ok || !reflect.DeepEqual(w, e.spec) {
			e.stop()
			<-e.done
			delete(s.dns, name)
		}
	}
	s.mu.Unlock()
	for name, d := range want {
		s.mu.Lock()
		_, exists := s.dns[name]
		s.mu.Unlock()
		if exists {
			continue
		}
		id, err := s.opts.Store.EnsureProbe(0, config.ProbeDNS, d.Key(), d.Label())
		if err != nil {
			return err
		}
		s.mu.Lock()
		ctx, cancel := context.WithCancel(s.ctx)
		e := &dnsEntry{spec: d, ref: ProbeRef{ID: id, Type: config.ProbeDNS, Key: d.Key(), Label: d.Label()}, stop: cancel, done: make(chan struct{})}
		s.dns[name] = e
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer close(e.done)
			s.dnsLoop(ctx, e)
		}()
		s.mu.Unlock()
	}
	return nil
}

// LoadUITargets starts runners for the UI-managed targets stored in the database. resolve
// turns a stored row (its spec) into the target to run; rows it fails on are logged and skipped.
func (s *Scheduler) LoadUITargets(resolve func(store.TargetRow) (config.Target, error)) error {
	rows, err := s.opts.Store.Targets(false)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Source != config.SourceUI {
			continue
		}
		spec, err := resolve(row)
		if err != nil {
			s.log.Error("ignoring UI target with an invalid definition", "target", row.Name, "err", err)
			continue
		}
		spec.Name, spec.Host, spec.Source = row.Name, row.Host, config.SourceUI
		if err := s.register(row, spec); err != nil {
			s.log.Error("cannot start UI target", "target", row.Name, "err", err)
		}
	}
	s.obs.TargetsChanged()
	return nil
}

// AddUITarget stores and starts a UI-managed target with its stored definition (spec).
// store.ErrDuplicate is returned for an existing name.
func (s *Scheduler) AddUITarget(t config.Target, spec string) (store.TargetRow, error) {
	t.Source = config.SourceUI
	row, err := s.opts.Store.CreateUITarget(t.Name, t.Host, spec)
	if err != nil {
		return row, err
	}
	if err := s.register(row, t); err != nil {
		return row, err
	}
	s.obs.TargetsChanged()
	return row, nil
}

// ApplyTarget runs a stored target with a new resolved definition. The runner restarts only
// when something changed (new probes start with their own history; probes whose identity is
// unchanged keep theirs).
func (s *Scheduler) ApplyTarget(row store.TargetRow, t config.Target) error {
	t.Name, t.Host, t.Source = row.Name, row.Host, row.Source
	if err := s.register(row, t); err != nil {
		return err
	}
	s.obs.TargetsChanged()
	return nil
}

// SetDefaults replaces the defaults (used where a target has no setting of its own).
func (s *Scheduler) SetDefaults(d config.Defaults) {
	s.mu.Lock()
	s.opts.Defaults = d
	s.mu.Unlock()
}

func (s *Scheduler) defaults() config.Defaults {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opts.Defaults
}

// RemoveTarget stops a UI target and deletes it with its data. Config targets cannot be removed.
func (s *Scheduler) RemoveTarget(id int64) error {
	row, err := s.opts.Store.Target(id)
	if err != nil {
		return err
	}
	if row.Source != config.SourceUI {
		return ErrConfigTarget
	}
	s.mu.Lock()
	if e := s.entries[id]; e != nil {
		s.stopRunnerLocked(e)
		delete(s.entries, id)
	}
	s.mu.Unlock()
	if err := s.opts.Store.DeleteTarget(id); err != nil {
		return err
	}
	s.obs.TargetsChanged()
	return nil
}

// ErrConfigTarget is returned when a config-file target is asked to be deleted.
var ErrConfigTarget = errors.New("target is managed by the config file")

// SetPaused pauses or resumes a target (runtime only for config targets: a restart resumes it
// unless it is paused in the database, which it is here too).
func (s *Scheduler) SetPaused(id int64, paused bool) error {
	if err := s.opts.Store.SetTargetPaused(id, paused); err != nil {
		return err
	}
	s.mu.Lock()
	e := s.entries[id]
	if e != nil {
		e.row.Paused = paused
		if paused {
			s.stopRunnerLocked(e)
		} else if e.run == nil && e.row.Active && s.ctx != nil {
			s.startRunnerLocked(e)
		}
	}
	s.mu.Unlock()
	s.obs.TargetsChanged()
	return nil
}

// State returns a snapshot of one target.
func (s *Scheduler) State(id int64) (State, bool) {
	s.mu.Lock()
	e := s.entries[id]
	s.mu.Unlock()
	if e == nil {
		return State{}, false
	}
	return s.snapshot(e), true
}

func (s *Scheduler) snapshot(e *entry) State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := State{Row: e.row, Spec: e.spec, HasSpec: true, Probes: append([]ProbeRef(nil), e.probes...), Running: e.run != nil}
	if e.spec.ICMP != nil {
		st.ICMPIntervalMS = int(e.spec.ICMP.Interval / time.Millisecond)
		st.ICMPEnabled = s.opts.Prober != nil
	}
	if e.run != nil {
		ip, unresp, last := e.run.snapshot()
		st.ResolvedIP, st.ICMPUnresponsive, st.LastRound = ip, unresp, last
	}
	return st
}

// States returns snapshots of every registered target, ordered by id.
func (s *Scheduler) States() []State {
	s.mu.Lock()
	es := make([]*entry, 0, len(s.entries))
	for _, e := range s.entries {
		es = append(es, e)
	}
	s.mu.Unlock()
	sort.Slice(es, func(i, j int) bool { return es[i].row.ID < es[j].row.ID })
	out := make([]State, len(es))
	for i, e := range es {
		out[i] = s.snapshot(e)
	}
	return out
}

// Targets implements analyze.Topology.
func (s *Scheduler) Targets() []analyze.TargetInfo {
	var out []analyze.TargetInfo
	for _, st := range s.States() {
		ti := analyze.TargetInfo{ID: st.Row.ID, Name: st.Row.Name, ICMPUnresponsive: st.ICMPUnresponsive}
		for _, p := range st.Probes {
			ti.Probes = append(ti.Probes, analyze.ProbeInfo{ID: p.ID, Type: p.Type, Label: p.Label})
		}
		out = append(out, ti)
	}
	return out
}

// DNSProbes implements analyze.Topology.
func (s *Scheduler) DNSProbes() []analyze.ProbeInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []analyze.ProbeInfo
	for _, e := range s.dns {
		out = append(out, analyze.ProbeInfo{ID: e.ref.ID, Type: config.ProbeDNS, Label: e.spec.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DNSStates describes the configured DNS probes.
type DNSState struct {
	ProbeID int64
	Spec    config.DNSProbe
}

// DNSStates returns the running DNS probes.
func (s *Scheduler) DNSStates() []DNSState {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []DNSState
	for _, e := range s.dns {
		out = append(out, DNSState{ProbeID: e.ref.ID, Spec: e.spec})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProbeID < out[j].ProbeID })
	return out
}

// Healthy reports whether the scheduler is making progress: some ICMP target completed a round
// recently (or none is expected to).
func (s *Scheduler) Healthy() (bool, string) {
	s.mu.Lock()
	started := s.started
	var newest time.Time
	var maxIv time.Duration
	expect := false
	for _, e := range s.entries {
		if e.run == nil || e.spec.ICMP == nil || s.opts.Prober == nil {
			continue
		}
		expect = true
		if iv := e.spec.ICMP.Interval; iv > maxIv {
			maxIv = iv
		}
		if _, _, last := e.run.snapshot(); last.After(newest) {
			newest = last
		}
	}
	s.mu.Unlock()
	if !expect {
		return true, ""
	}
	limit := 5 * maxIv
	if limit < 15*time.Second {
		limit = 15 * time.Second
	}
	if time.Since(started) < limit+15*time.Second {
		return true, "" // startup grace
	}
	if time.Since(newest) > limit {
		return false, "no ICMP round completed recently"
	}
	return true, ""
}

// Uptime is the time since Start.
func (s *Scheduler) Uptime() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started.IsZero() {
		return 0
	}
	return time.Since(s.started)
}

// pickAddr chooses the destination to pin: keep the current one while the resolver still returns
// it (stable pins for round-robin DNS), otherwise the first IPv4 (kept preferred: it is the most widely reachable family and keeps existing
// pins unchanged; IPv6 is traced when it is the only family or a literal), otherwise the first address.
func pickAddr(addrs []netip.Addr, current netip.Addr) netip.Addr {
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	if current.IsValid() {
		for _, a := range addrs {
			if a == current {
				return a
			}
		}
	}
	for _, a := range addrs {
		if a.Is4() {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return netip.Addr{}
}

func resolveHost(ctx context.Context, r Resolver, host string, current netip.Addr) (netip.Addr, time.Duration, error) {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return a.Unmap(), 0, nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	start := time.Now()
	addrs, err := r.LookupNetIP(rctx, "ip", host)
	d := time.Since(start)
	if err != nil {
		return netip.Addr{}, d, err
	}
	a := pickAddr(addrs, current)
	if !a.IsValid() {
		return netip.Addr{}, d, errors.New("no addresses")
	}
	return a, d, nil
}

func (s *Scheduler) dnsLoop(ctx context.Context, e *dnsEntry) {
	if !sleepCtx(ctx, jitter(e.spec.Interval)) {
		return
	}
	t := time.NewTicker(e.spec.Interval)
	defer t.Stop()
	for {
		start := time.Now().UTC()
		var res probe.DNSResult
		n := retrying(ctx, e.spec.Retries, e.spec.Timeout, e.spec.Interval, start, func() bool {
			res = probe.DNSQuery(ctx, e.spec.Server, e.spec.Query, e.spec.Record, e.spec.Timeout)
			return res.OK
		})
		if ctx.Err() != nil {
			return
		}
		smp := store.DNSSample{ProbeID: e.ref.ID, TS: start, RCode: res.RCode, RTT: res.RTT}
		if res.Err != nil {
			smp.Error = withAttempts(res.Err.Error(), res.OK, n)
		}
		s.opts.Store.RecordDNS(smp)
		pe := ProbeEvent{ProbeID: e.ref.ID, Type: config.ProbeDNS, TS: start, OK: res.OK, TotalMS: float64(res.RTT) / float64(time.Millisecond)}
		pe.Sample = alert.ProbeSample{ProbeID: e.ref.ID, Type: config.ProbeDNS, TS: start, OK: res.OK, Error: smp.Error, TotalMS: pe.TotalMS}
		s.obs.Probe(pe)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(d)))
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

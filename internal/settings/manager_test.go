package settings

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

type fakeProber struct{}

func (fakeProber) Mode() string { return probe.ModeRaw }
func (fakeProber) Close() error { return nil }
func (fakeProber) Probe(ctx context.Context, req probe.Request) probe.Result {
	return probe.Result{Status: probe.StatusReply, Addr: req.Dst, RTT: time.Millisecond}
}

type resolver struct{}

func (resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

type fakeEngine struct {
	reloads atomic.Int64
	last    atomic.Pointer[config.Config]
}

func (e *fakeEngine) Reload(c *config.Config) { e.reloads.Add(1); e.last.Store(c) }

const fileYAML = `
defaults:
  icmp_interval: 2s
targets:
  - name: alpha
    host: alpha.example
    probes:
      - type: icmp-trace
      - type: tcp
        port: 443
alerts:
  rules:
    - name: end-loss
      type: final_hop_loss
      threshold_pct: 5
    - name: tcp-down
      type: tcp_failure
dns_probes:
  - name: resolver
    server: 192.0.2.53
    query: example.com
`

type env struct {
	st    *store.Store
	sched *scheduler.Scheduler
	m     *Manager
	eng   *fakeEngine
	path  string
}

func open(t *testing.T, path, yaml string) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(path, store.Options{Logger: log, FlushInterval: 20 * time.Millisecond, NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	sched := scheduler.New(scheduler.Options{Store: st, Prober: fakeProber{}, Logger: log, Resolver: resolver{}, Stagger: time.Millisecond})
	file, err := config.Parse([]byte(yaml), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(st, sched, file, log)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{st: st, sched: sched, m: m, eng: &fakeEngine{}, path: path}
	m.SetEngine(e.eng)
	sched.Start(context.Background())
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) close() { e.sched.Close(); e.st.Close() }

func newEnv(t *testing.T) *env {
	e := open(t, filepath.Join(t.TempDir(), "m.db"), fileYAML)
	t.Cleanup(e.close)
	return e
}

func (e *env) state(t *testing.T, name string) scheduler.State {
	t.Helper()
	for _, s := range e.sched.States() {
		if s.Row.Name == name {
			return s
		}
	}
	t.Fatalf("no target %q", name)
	return scheduler.State{}
}

func intp(v int) *int { return &v }

func TestDefaultsApplyToRunningTargets(t *testing.T) {
	e := newEnv(t)
	ui, err := e.m.CreateTarget(config.TargetConfig{Name: "ui", Host: "UI.example.", Probes: []config.ProbeConfig{{Type: "icmp-trace"}, {Type: "tcp", Port: 22}}})
	if err != nil {
		t.Fatal(err)
	}
	if ui.Host != "ui.example." {
		t.Errorf("host not normalized: %q", ui.Host)
	}
	d := e.m.Effective().Defaults
	d.ICMPInterval = config.Duration(5 * time.Second)
	d.Retries = 2
	if err := e.m.SetDefaults(&d); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "ui"} {
		st := e.state(t, name)
		if st.Spec.ICMP.Interval != 5*time.Second || st.Spec.Probes[0].Retries != 2 {
			t.Errorf("%s: %+v %+v", name, st.Spec.ICMP, st.Spec.Probes)
		}
	}
	if e.eng.reloads.Load() == 0 {
		t.Error("engine not reloaded")
	}
	if e.m.Overrides().Defaults == nil {
		t.Error("override not recorded")
	}

	bad := d
	bad.ICMPInterval = config.Duration(100 * time.Millisecond)
	if err := e.m.SetDefaults(&bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("want invalid, got %v", err)
	}
	if e.m.Effective().Defaults.ICMPInterval.D() != 5*time.Second {
		t.Error("a rejected change was applied")
	}

	if err := e.m.SetDefaults(nil); err != nil {
		t.Fatal(err)
	}
	if st := e.state(t, "ui"); st.Spec.ICMP.Interval != 2*time.Second || st.Spec.Probes[0].Retries != 0 {
		t.Errorf("revert: %+v", st.Spec.ICMP)
	}
}

func TestEditAndRevertConfigTarget(t *testing.T) {
	e := newEnv(t)
	row := e.state(t, "alpha").Row
	def, err := e.m.Target(row)
	if err != nil || def.Overridden || def.Source != config.SourceConfig || len(def.Target.Probes) != 2 {
		t.Fatalf("def %+v %v", def, err)
	}
	tc := def.Target
	tc.Host = "[2001:db8::1]"
	tc.Probes[1].Retries = intp(3)
	tc.Probes[1].Timeout = config.Duration(time.Second)
	ten := 10.0
	tc.Alerts = config.TargetAlerts{Disable: []string{"tcp-down"}, Override: map[string]config.RuleOverride{"end-loss": {ThresholdPct: &ten}}}
	if _, err := e.m.UpdateTarget(row.ID, tc); err != nil {
		t.Fatal(err)
	}
	st := e.state(t, "alpha")
	if st.Row.Host != "2001:db8::1" || st.Spec.Probes[0].Retries != 3 || st.Spec.Probes[0].Timeout != time.Second {
		t.Fatalf("not applied: %+v %+v", st.Row, st.Spec.Probes)
	}
	eff := e.eng.last.Load()
	if eff == nil || len(eff.Targets[0].Alerts.Disable) != 1 {
		t.Fatalf("engine did not get the per-target alert settings: %+v", eff)
	}

	// survives a restart (and a config reload) and shows as edited
	file, _ := config.Parse([]byte(fileYAML), func(string) string { return "" })
	if err := e.m.ReloadFile(file); err != nil {
		t.Fatal(err)
	}
	if st := e.state(t, "alpha"); st.Row.Host != "2001:db8::1" {
		t.Errorf("reload dropped the edit: %+v", st.Row)
	}
	row2, _ := e.st.Target(row.ID)
	if def, _ := e.m.Target(row2); !def.Overridden || def.Target.Host != "2001:db8::1" {
		t.Errorf("def after edit: %+v", def)
	}

	if _, err := e.m.UpdateTarget(row.ID, config.TargetConfig{Name: "renamed", Host: "x.example"}); !errors.Is(err, ErrRenameCf) {
		t.Errorf("rename of config target: %v", err)
	}
	tc.Alerts.Disable = []string{"no-such-rule"}
	if _, err := e.m.UpdateTarget(row.ID, tc); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "no-such-rule") {
		t.Errorf("unknown rule: %v", err)
	}

	if err := e.m.RevertTarget(row.ID); err != nil {
		t.Fatal(err)
	}
	if st := e.state(t, "alpha"); st.Row.Host != "alpha.example" || st.Spec.Probes[0].Retries != 0 {
		t.Errorf("revert: %+v %+v", st.Row, st.Spec.Probes)
	}
	if err := e.m.RevertTarget(row.ID); !errors.Is(err, ErrNotInUI) {
		t.Errorf("second revert: %v", err)
	}
}

func TestUITargetRenameAndDelete(t *testing.T) {
	e := newEnv(t)
	row, err := e.m.CreateTarget(config.TargetConfig{Name: "one", Host: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.CreateTarget(config.TargetConfig{Name: "ALPHA", Host: "1.1.1.1"}); !errors.Is(err, store.ErrDuplicate) {
		t.Errorf("duplicate of a config target: %v", err)
	}
	if _, err := e.m.CreateTarget(config.TargetConfig{Name: "bad", Host: "https://example.com"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("URL as host: %v", err)
	}
	def, _ := e.m.Target(row)
	def.Target.Name = "two"
	nrow, err := e.m.UpdateTarget(row.ID, def.Target)
	if err != nil || nrow.Name != "two" || nrow.ID != row.ID {
		t.Fatalf("rename: %+v %v", nrow, err)
	}
	if e.state(t, "two").Row.ID != row.ID {
		t.Error("runner not renamed")
	}
	if len(e.m.Effective().UITargets) != 1 || e.m.Effective().UITargets[0].Name != "two" {
		t.Errorf("effective ui targets: %+v", e.m.Effective().UITargets)
	}
	if err := e.m.DeleteTarget(row.ID); err != nil {
		t.Fatal(err)
	}
	if len(e.m.Effective().UITargets) != 0 {
		t.Error("deleted target still in the effective config")
	}
	if err := e.m.DeleteTarget(e.state(t, "alpha").Row.ID); !errors.Is(err, scheduler.ErrConfigTarget) {
		t.Errorf("delete config target: %v", err)
	}
}

func TestAlertsStatusAndDNSSections(t *testing.T) {
	e := newEnv(t)
	a := e.m.Effective().Alerts.Settings()
	a.Rules[0].ThresholdPct = 2
	a.Rules = append(a.Rules, config.RuleConfig{Name: "slow", Type: "http_latency", Multiplier: 4})
	a.Cooldown = config.Duration(10 * time.Minute)
	if err := e.m.SetAlerts(&a); err != nil {
		t.Fatal(err)
	}
	eff := e.eng.last.Load()
	if eff.Alerts.Rules[0].ThresholdPct != 2 || eff.Alerts.Rules[2].Sustain.D() != 5*time.Minute || eff.Alerts.Cooldown.D() != 10*time.Minute {
		t.Errorf("alerts: %+v", eff.Alerts)
	}
	if e.m.File().Alerts.Rules[0].ThresholdPct != 5 {
		t.Error("file config modified")
	}
	bad := a
	bad.Rules = append([]config.RuleConfig(nil), a.Rules...)
	bad.Rules[0].ThresholdPct = 200
	if err := e.m.SetAlerts(&bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("threshold 200: %v", err)
	}
	if err := e.m.SetAlerts(&config.AlertSettings{Rules: []config.RuleConfig{{Type: "tcp_failure"}}, ClearRatio: 0.5}); !errors.Is(err, ErrInvalid) {
		t.Errorf("rule without a name: %v", err)
	}

	if err := e.m.SetStatus(&config.StatusConfig{DegradedLossPct: 1, DegradedHTTPSuccessPct: 99}); err != nil {
		t.Fatal(err)
	}
	if e.m.Effective().Status.DegradedLossPct != 1 {
		t.Error("status not applied")
	}

	list := []config.DNSProbeConfig{{Name: "pihole", Server: "192.0.2.2", Query: "example.org", Retries: intp(1)}}
	if err := e.m.SetDNSProbes(&list); err != nil {
		t.Fatal(err)
	}
	ds := e.sched.DNSStates()
	if len(ds) != 1 || ds[0].Spec.Name != "pihole" || ds[0].Spec.Server != "192.0.2.2:53" || ds[0].Spec.Retries != 1 {
		t.Errorf("dns: %+v", ds)
	}
	empty := []config.DNSProbeConfig{}
	if err := e.m.SetDNSProbes(&empty); err != nil || len(e.sched.DNSStates()) != 0 {
		t.Errorf("empty dns list: %v %+v", err, e.sched.DNSStates())
	}
	if err := e.m.SetDNSProbes(nil); err != nil || len(e.sched.DNSStates()) != 1 || e.sched.DNSStates()[0].Spec.Name != "resolver" {
		t.Errorf("revert dns: %v %+v", err, e.sched.DNSStates())
	}
}

func TestSettingsPersistAndFallBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.db")
	e := open(t, path, fileYAML)
	d := e.m.Effective().Defaults
	d.MaxHops = 12
	if err := e.m.SetDefaults(&d); err != nil {
		t.Fatal(err)
	}
	ui, err := e.m.CreateTarget(config.TargetConfig{Name: "ui", Host: "ui.example", Alerts: config.TargetAlerts{Disable: []string{"tcp-down"}}})
	if err != nil {
		t.Fatal(err)
	}
	a := e.m.Effective().Alerts.Settings()
	if err := e.m.SetAlerts(&a); err != nil {
		t.Fatal(err)
	}
	e.close()

	e2 := open(t, path, fileYAML)
	if e2.m.Effective().Defaults.MaxHops != 12 || e2.state(t, "ui").Spec.ICMP.MaxHops != 12 {
		t.Errorf("not restored: %+v", e2.m.Effective().Defaults)
	}
	e2.close()

	// Removing a rule that a UI target refers to is refused...
	e3 := open(t, path, fileYAML)
	a.Rules = a.Rules[:1] // drop tcp-down
	if err := e3.m.SetAlerts(&a); !errors.Is(err, ErrInvalid) {
		t.Fatalf("dangling reference accepted: %v", err)
	}
	e3.close()
	// ...but if such settings are stored anyway (say the reference came from elsewhere), startup
	// falls back to the file's sections instead of failing.
	b, _ := json.Marshal(a)
	st, _ := store.Open(path, store.Options{NoBackground: true})
	_ = st.SetSetting(KeyAlerts, string(b))
	st.Close()
	e4 := open(t, path, fileYAML)
	defer e4.close()
	if len(e4.m.Effective().Alerts.Rules) != 2 {
		t.Errorf("invalid stored alert rules should fall back to the file: %+v", e4.m.Effective().Alerts.Rules)
	}
	if e4.m.Effective().Defaults.MaxHops != 30 {
		t.Errorf("fallback drops every UI section: %+v", e4.m.Effective().Defaults)
	}
	if _, ok := e4.sched.State(ui.ID); !ok {
		t.Error("UI target not running after fallback")
	}
}

func TestLegacyUITargetSpec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "l.db")
	st, err := store.Open(path, store.Options{NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	file, _ := config.Parse([]byte(fileYAML), func(string) string { return "" })
	legacy, _ := config.NewUITarget(config.UITargetRequest{Name: "old", Host: "old.example", ICMPIntervalMS: 3000, TCPPort: 22}, file.Defaults)
	b, _ := json.Marshal(legacy)
	if _, err := st.CreateUITarget("old", "old.example", string(b)); err != nil {
		t.Fatal(err)
	}
	st.Close()
	e := open(t, path, fileYAML)
	defer e.close()
	s := e.state(t, "old")
	if s.Spec.ICMP == nil || s.Spec.ICMP.Interval != 3*time.Second || len(s.Spec.Probes) != 1 || s.Spec.Probes[0].Port != 22 {
		t.Fatalf("legacy spec: %+v", s.Spec)
	}
	def, err := e.m.Target(s.Row)
	if err != nil || def.Target.Probes[0].Interval.D() != 3*time.Second || def.Target.Probes[1].Interval != 0 {
		t.Fatalf("legacy def: %+v %v", def, err)
	}
	// editing stores the new format
	if _, err := e.m.UpdateTarget(s.Row.ID, def.Target); err != nil {
		t.Fatal(err)
	}
	row, _ := e.st.Target(s.Row.ID)
	if !strings.HasPrefix(row.Spec, `{"v":2`) {
		t.Errorf("spec not upgraded: %s", row.Spec)
	}
}

func tcpProbes(n int) []config.ProbeConfig {
	ps := make([]config.ProbeConfig, n)
	for i := range ps {
		ps[i] = config.ProbeConfig{Type: "tcp", Port: 1000 + i}
	}
	return ps
}

func TestTargetCountLimit(t *testing.T) {
	e := newEnv(t)
	fileN := len(e.m.Effective().Targets)
	for i := fileN; i < config.MaxTargets; i++ {
		if _, err := e.m.CreateTarget(config.TargetConfig{Name: "t" + strconv.Itoa(i), Host: "h.example"}); err != nil {
			t.Fatalf("target %d: %v", i, err)
		}
	}
	_, err := e.m.CreateTarget(config.TargetConfig{Name: "one-too-many", Host: "h.example"})
	var inv InvalidError
	if !errors.As(err, &inv) || !strings.Contains(err.Error(), "too many targets") {
		t.Fatalf("over the cap: %v", err)
	}
	// editing existing targets is still possible at the cap
	if _, err := e.m.UpdateTarget(e.state(t, "t"+strconv.Itoa(fileN)).Row.ID, config.TargetConfig{Name: "renamed", Host: "h.example"}); err != nil {
		t.Errorf("update at the cap: %v", err)
	}
}

func TestOverCapDatabaseStillStarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	e := open(t, path, fileYAML)
	for i := 0; i < config.MaxTargets+5; i++ { // bypass the manager, as an older version would have
		tc := config.TargetConfig{Name: "t" + strconv.Itoa(i), Host: "h.example"}
		tg, err := config.ResolveUITarget(tc, e.m.Effective().Defaults)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 { // and with more probes than allowed
			tc.Probes = tcpProbes(config.MaxProbesPerTarget + 3)
		}
		spec, err := encodeSpec(tc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.sched.AddUITarget(tg, spec); err != nil {
			t.Fatal(err)
		}
	}
	e.close()
	e2 := open(t, path, fileYAML)
	defer e2.close()
	if n := len(e2.m.Effective().UITargets); n != config.MaxTargets+5 {
		t.Errorf("UI targets kept: %d", n)
	}
	if _, err := e2.m.CreateTarget(config.TargetConfig{Name: "more", Host: "h.example"}); err == nil {
		t.Error("create over the cap succeeded")
	}
}

func TestProbesPerTargetLimit(t *testing.T) {
	e := newEnv(t)
	_, err := e.m.CreateTarget(config.TargetConfig{Name: "big", Host: "h.example", Probes: tcpProbes(config.MaxProbesPerTarget + 1)})
	var inv InvalidError
	if !errors.As(err, &inv) || !strings.Contains(err.Error(), "too many probes") {
		t.Fatalf("create: %v", err)
	}
	row, err := e.m.CreateTarget(config.TargetConfig{Name: "ok", Host: "h.example", Probes: tcpProbes(config.MaxProbesPerTarget)})
	if err != nil {
		t.Fatalf("create at the cap: %v", err)
	}
	if _, err := e.m.UpdateTarget(row.ID, config.TargetConfig{Name: "ok", Host: "h.example", Probes: tcpProbes(config.MaxProbesPerTarget + 1)}); !errors.As(err, &inv) {
		t.Errorf("update past the cap: %v", err)
	}
	// a config-file target edited past the cap is refused too
	alpha := e.state(t, "alpha").Row.ID
	if _, err := e.m.UpdateTarget(alpha, config.TargetConfig{Name: "alpha", Host: "alpha.example", Probes: tcpProbes(config.MaxProbesPerTarget + 1)}); !errors.As(err, &inv) {
		t.Errorf("file target update past the cap: %v", err)
	}
}

func TestDNSProbeLimit(t *testing.T) {
	e := newEnv(t)
	mk := func(n int) *[]config.DNSProbeConfig {
		l := make([]config.DNSProbeConfig, n)
		for i := range l {
			l[i] = config.DNSProbeConfig{Name: "p" + strconv.Itoa(i), Server: "192.0.2.53", Query: "example.com"}
		}
		return &l
	}
	if err := e.m.SetDNSProbes(mk(config.MaxDNSProbes)); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	err := e.m.SetDNSProbes(mk(config.MaxDNSProbes + 1))
	var inv InvalidError
	if !errors.As(err, &inv) || !strings.Contains(err.Error(), "too many DNS probes") {
		t.Fatalf("over the cap: %v", err)
	}
	if _, err := config.Parse([]byte("dns_probes:\n"+strings.Repeat("  - {name: a, server: 192.0.2.1, query: x.example}\n", config.MaxDNSProbes+1)), func(string) string { return "" }); err == nil {
		t.Error("file with too many DNS probes accepted")
	}
}

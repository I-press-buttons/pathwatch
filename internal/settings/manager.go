// Package settings manages the settings edited in the web UI. They are stored in the database
// and layered over the config file: probe defaults, status thresholds, alert rules and DNS
// probes replace the file's section when edited; a config-file target edited in the UI is
// replaced by its edited definition; UI-managed targets exist only in the database. The
// manager computes the effective configuration and applies every change to the scheduler and
// the alert engine at once, without a restart.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
	"github.com/i-press-buttons/pathwatch/internal/store"
)

// Keys of the settings table.
const (
	KeyDefaults  = "defaults"
	KeyStatus    = "status"
	KeyAlerts    = "alerts"
	KeyDNSProbes = "dns_probes"
)

// Engine is the alert engine (it re-reads rules, thresholds and per-target settings).
type Engine interface {
	Reload(*config.Config)
}

// Errors returned for requests that cannot be honoured (the API maps them to 4xx).
var (
	ErrInvalid  = errors.New("invalid settings")
	ErrRemoved  = errors.New("target was removed from the config file")
	ErrNotInUI  = errors.New("target is not edited in the UI")
	ErrRenameCf = errors.New("config-file targets are renamed in the config file")
)

// InvalidError wraps a validation failure so callers can show its message.
type InvalidError struct{ Err error }

func (e InvalidError) Error() string { return e.Err.Error() }
func (e InvalidError) Unwrap() error { return ErrInvalid }

func invalid(err error) error { return InvalidError{Err: err} }

// Manager owns the effective configuration.
type Manager struct {
	st    *store.Store
	sched *scheduler.Scheduler
	log   *slog.Logger

	mu   sync.Mutex // serializes changes
	file *config.Config
	ov   config.Overrides
	eng  Engine
	eff  atomic.Pointer[config.Config]
}

// New loads the stored settings and computes the effective configuration. Stored settings that
// are no longer valid with the config file are ignored (and logged), never fatal.
func New(st *store.Store, sched *scheduler.Scheduler, file *config.Config, log *slog.Logger) (*Manager, error) {
	if log == nil {
		log = slog.Default()
	}
	m := &Manager{st: st, sched: sched, log: log, file: file}
	raw, err := st.Settings()
	if err != nil {
		return nil, err
	}
	m.ov = m.decodeOverrides(raw)
	eff, err := m.computeWithFallback()
	if err != nil {
		return nil, err
	}
	m.eff.Store(eff)
	return m, nil
}

// SetEngine attaches the alert engine (created from Effective()).
func (m *Manager) SetEngine(e Engine) {
	m.mu.Lock()
	m.eng = e
	m.mu.Unlock()
}

// Effective returns the current effective configuration. It must not be modified.
func (m *Manager) Effective() *config.Config { return m.eff.Load() }

// File returns the configuration as loaded from the file.
func (m *Manager) File() *config.Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.file
}

// Overrides returns the sections edited in the UI.
func (m *Manager) Overrides() config.Overrides {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ov
}

// Start runs every target (config-file and UI) and the DNS probes with the effective configuration.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.push(m.eff.Load(), false)
}

// ReloadFile replaces the config file (SIGHUP) and applies the result.
func (m *Manager) ReloadFile(file *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.file = file
	eff, err := m.computeWithFallback()
	if err != nil {
		return err
	}
	m.eff.Store(eff)
	return m.push(eff, true)
}

func (m *Manager) decodeOverrides(raw map[string]string) config.Overrides {
	var ov config.Overrides
	dec := func(key string, v any) bool {
		s, ok := raw[key]
		if !ok {
			return false
		}
		if err := json.Unmarshal([]byte(s), v); err != nil {
			m.log.Error("ignoring unreadable UI setting", "key", key, "err", err)
			return false
		}
		return true
	}
	var d config.Defaults
	if dec(KeyDefaults, &d) {
		ov.Defaults = &d
	}
	var s config.StatusConfig
	if dec(KeyStatus, &s) {
		ov.Status = &s
	}
	var a config.AlertSettings
	if dec(KeyAlerts, &a) {
		ov.Alerts = &a
	}
	var dp []config.DNSProbeConfig
	if dec(KeyDNSProbes, &dp) {
		ov.DNSProbes = &dp
	}
	return ov
}

// ---------------------------------------------------------------------------
// stored target definitions

// storedSpec is the format of targets.spec. Specs without a version are the resolved targets
// that UI targets were stored as before they became editable.
type storedSpec struct {
	V      int                 `json:"v"`
	Target config.TargetConfig `json:"target"`
}

const specVersion = 2

func encodeSpec(tc config.TargetConfig) (string, error) {
	b, err := json.Marshal(storedSpec{V: specVersion, Target: tc})
	return string(b), err
}

func decodeSpec(raw string, d config.Defaults) (config.TargetConfig, error) {
	var probe struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return config.TargetConfig{}, err
	}
	if probe.V == 0 {
		var legacy config.Target
		if err := json.Unmarshal([]byte(raw), &legacy); err != nil {
			return config.TargetConfig{}, err
		}
		return config.TargetConfigFromResolved(legacy, d), nil
	}
	if probe.V != specVersion {
		return config.TargetConfig{}, fmt.Errorf("unknown definition version %d", probe.V)
	}
	var s storedSpec
	err := json.Unmarshal([]byte(raw), &s)
	return s.Target, err
}

// ---------------------------------------------------------------------------
// effective configuration

type uiTarget struct {
	row store.TargetRow
	tc  config.TargetConfig
}

// state is everything the effective configuration is computed from, besides the file.
type state struct {
	ov     config.Overrides
	edited map[string]config.TargetConfig // config targets edited in the UI, by lower-case name
	ui     []uiTarget
}

// load reads the target definitions stored in the database.
func (m *Manager) load(defaults config.Defaults) (state, error) {
	s := state{ov: m.ov, edited: map[string]config.TargetConfig{}}
	rows, err := m.st.Targets(false)
	if err != nil {
		return s, err
	}
	for _, row := range rows {
		if row.Spec == "" {
			continue
		}
		tc, err := decodeSpec(row.Spec, defaults)
		if err != nil {
			m.log.Error("ignoring unreadable target definition", "target", row.Name, "err", err)
			continue
		}
		tc.Name, tc.Host = row.Name, row.Host
		switch row.Source {
		case config.SourceUI:
			s.ui = append(s.ui, uiTarget{row: row, tc: tc})
		case config.SourceConfig:
			s.edited[strings.ToLower(row.Name)] = tc
		}
	}
	return s, nil
}

// compute returns the effective configuration for s.
func (m *Manager) compute(s state) (*config.Config, error) {
	ui := make([]config.TargetConfig, len(s.ui))
	for i, u := range s.ui {
		ui[i] = u.tc
	}
	eff, err := m.file.WithOverrides(s.ov, s.edited, ui)
	if err != nil {
		return nil, invalid(err)
	}
	return eff, nil
}

// defaultsFor returns the effective defaults of a set of overrides (needed to read the
// definitions of older UI targets, before the targets themselves are known).
func (m *Manager) defaultsFor(ov config.Overrides) config.Defaults {
	eff, err := m.file.WithOverrides(config.Overrides{Defaults: ov.Defaults}, nil, nil)
	if err != nil {
		return m.file.Defaults
	}
	return eff.Defaults
}

// computeWithFallback computes the effective configuration from the stored state. When the
// stored settings do not fit the config file (it changed underneath them), the UI sections
// are dropped first, then the UI edits of config targets and the UI targets' alert settings,
// so pathwatch always starts.
func (m *Manager) computeWithFallback() (*config.Config, error) {
	s, err := m.load(m.defaultsFor(m.ov))
	if err != nil {
		return nil, err
	}
	eff, err := m.compute(s)
	if err == nil {
		return eff, nil
	}
	m.log.Error("settings edited in the web UI do not fit the config file; using the config file's defaults, status thresholds, alert rules and DNS probes until they are saved again", "err", err)
	s.ov = config.Overrides{}
	if s2, lerr := m.load(m.file.Defaults); lerr == nil {
		s.edited, s.ui = s2.edited, s2.ui
	}
	if eff, err = m.compute(s); err == nil {
		return eff, nil
	}
	m.log.Error("target settings edited in the web UI do not fit the config file; ignoring the edits of config-file targets and the per-target alert settings of UI targets", "err", err)
	s.edited = nil
	for i := range s.ui {
		s.ui[i].tc.Alerts = config.TargetAlerts{}
	}
	return m.compute(s)
}

// resolveUI resolves the UI targets of eff, reporting the first that does not resolve.
func resolveUI(eff *config.Config, ui []uiTarget) (map[int64]config.Target, error) {
	out := make(map[int64]config.Target, len(ui))
	for _, u := range ui {
		t, err := config.ResolveUITarget(u.tc, eff.Defaults)
		if err != nil {
			return nil, err
		}
		out[u.row.ID] = t
	}
	return out, nil
}

// push applies an effective configuration to the scheduler and, when asked, the alert engine.
func (m *Manager) push(eff *config.Config, reloadEngine bool) error {
	m.sched.SetDefaults(eff.Defaults)
	if err := m.sched.SyncConfig(eff.ResolveTargets(), eff.ResolveDNSProbes()); err != nil {
		return err
	}
	s, err := m.load(eff.Defaults)
	if err != nil {
		return err
	}
	for _, u := range s.ui {
		t, err := config.ResolveUITarget(u.tc, eff.Defaults)
		if err != nil {
			m.log.Error("UI target has an invalid definition; it is not running", "target", u.row.Name, "err", err)
			continue
		}
		if err := m.sched.ApplyTarget(u.row, t); err != nil {
			return err
		}
	}
	if reloadEngine && m.eng != nil {
		m.eng.Reload(eff)
	}
	return nil
}

// change validates a new state, stores it with save, then applies it.
func (m *Manager) change(s state, save func() error) error {
	eff, err := m.compute(s)
	if err != nil {
		return err
	}
	if _, err := resolveUI(eff, s.ui); err != nil {
		return invalid(err)
	}
	if err := save(); err != nil {
		return err
	}
	m.ov = s.ov
	m.eff.Store(eff)
	return m.push(eff, true)
}

// ---------------------------------------------------------------------------
// sections

func (m *Manager) setSection(key string, value any, isNil bool, set func(*config.Overrides)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ov := m.ov
	set(&ov)
	s, err := m.load(m.defaultsFor(ov))
	if err != nil {
		return err
	}
	s.ov = ov
	return m.change(s, func() error {
		if isNil {
			return m.st.SetSetting(key, "")
		}
		b, err := json.Marshal(value)
		if err != nil {
			return err
		}
		return m.st.SetSetting(key, string(b))
	})
}

// SetDefaults stores the probe defaults edited in the UI (nil reverts to the config file).
func (m *Manager) SetDefaults(d *config.Defaults) error {
	return m.setSection(KeyDefaults, d, d == nil, func(o *config.Overrides) { o.Defaults = d })
}

// SetStatus stores the status thresholds edited in the UI (nil reverts to the config file).
func (m *Manager) SetStatus(v *config.StatusConfig) error {
	return m.setSection(KeyStatus, v, v == nil, func(o *config.Overrides) { o.Status = v })
}

// SetAlerts stores the alert rules and noise control edited in the UI (nil reverts).
func (m *Manager) SetAlerts(a *config.AlertSettings) error {
	if a != nil {
		for i := range a.Rules {
			a.Rules[i].Name = strings.TrimSpace(a.Rules[i].Name)
			if a.Rules[i].Name == "" {
				return invalid(fmt.Errorf("alert rule %d: name is required", i+1))
			}
		}
	}
	return m.setSection(KeyAlerts, a, a == nil, func(o *config.Overrides) { o.Alerts = a })
}

// SetDNSProbes stores the DNS probes edited in the UI (nil reverts to the config file).
func (m *Manager) SetDNSProbes(list *[]config.DNSProbeConfig) error {
	if list != nil && *list == nil {
		empty := []config.DNSProbeConfig{}
		list = &empty
	}
	return m.setSection(KeyDNSProbes, list, list == nil, func(o *config.Overrides) { o.DNSProbes = list })
}

// ---------------------------------------------------------------------------
// targets

// TargetDef is a target's definition as the UI edits it.
type TargetDef struct {
	Target     config.TargetConfig
	Source     string
	Overridden bool // a config-file target with UI edits
}

// Target returns the definition of a stored target, normalized for editing.
func (m *Manager) Target(row store.TargetRow) (TargetDef, error) {
	eff := m.Effective()
	def := TargetDef{Source: row.Source}
	switch {
	case row.Spec != "":
		tc, err := decodeSpec(row.Spec, eff.Defaults)
		if err != nil {
			return def, err
		}
		def.Target, def.Overridden = tc, row.Source == config.SourceConfig
	case row.Source == config.SourceConfig:
		found := false
		for _, tc := range m.File().Targets {
			if strings.EqualFold(tc.Name, row.Name) {
				def.Target, found = tc, true
				break
			}
		}
		if !found {
			return def, ErrRemoved
		}
	default:
		return def, fmt.Errorf("target %q has no stored definition", row.Name)
	}
	def.Target.Name, def.Target.Host = row.Name, row.Host
	def.Target = config.NormalizeTarget(def.Target, eff.Alerts.Rules)
	return def, nil
}

func (m *Manager) prepare(tc config.TargetConfig) (config.TargetConfig, config.Target, error) {
	tc.Name = strings.TrimSpace(tc.Name)
	t, err := config.ResolveUITarget(tc, m.Effective().Defaults)
	if err != nil {
		return tc, t, invalid(err)
	}
	tc.Host = t.Host // normalized
	return tc, t, nil
}

// CreateTarget adds a UI-managed target. store.ErrDuplicate is returned for a name in use.
func (m *Manager) CreateTarget(tc config.TargetConfig) (store.TargetRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tc, t, err := m.prepare(tc)
	if err != nil {
		return store.TargetRow{}, err
	}
	s, err := m.load(m.Effective().Defaults)
	if err != nil {
		return store.TargetRow{}, err
	}
	s.ui = append(s.ui, uiTarget{tc: tc})
	eff, err := m.compute(s)
	if err != nil {
		return store.TargetRow{}, err
	}
	spec, err := encodeSpec(tc)
	if err != nil {
		return store.TargetRow{}, err
	}
	row, err := m.sched.AddUITarget(t, spec)
	if err != nil {
		return row, err
	}
	m.eff.Store(eff)
	if m.eng != nil {
		m.eng.Reload(eff)
	}
	return row, nil
}

// UpdateTarget replaces the definition of a target. A UI target may be renamed; a config-file
// target keeps its name and its edited definition overrides the file until RevertTarget.
func (m *Manager) UpdateTarget(id int64, tc config.TargetConfig) (store.TargetRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, err := m.st.Target(id)
	if err != nil {
		return row, err
	}
	if !row.Active {
		return row, ErrRemoved
	}
	if row.Source == config.SourceConfig {
		if n := strings.TrimSpace(tc.Name); n != "" && !strings.EqualFold(n, row.Name) {
			return row, ErrRenameCf
		}
		tc.Name = row.Name
	}
	tc, t, err := m.prepare(tc)
	if err != nil {
		return row, err
	}
	s, err := m.load(m.Effective().Defaults)
	if err != nil {
		return row, err
	}
	if row.Source == config.SourceConfig {
		s.edited[strings.ToLower(row.Name)] = tc
	} else {
		for i := range s.ui {
			if s.ui[i].row.ID == id {
				s.ui[i].tc = tc
			}
		}
	}
	eff, err := m.compute(s)
	if err != nil {
		return row, err
	}
	spec, err := encodeSpec(tc)
	if err != nil {
		return row, err
	}
	nrow, err := m.st.UpdateTarget(id, tc.Name, tc.Host, spec)
	if err != nil {
		return row, err
	}
	if err := m.sched.ApplyTarget(nrow, t); err != nil {
		return nrow, err
	}
	m.eff.Store(eff)
	if m.eng != nil {
		m.eng.Reload(eff)
	}
	return nrow, nil
}

// RevertTarget drops the UI edits of a config-file target, so the file applies again.
func (m *Manager) RevertTarget(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, err := m.st.Target(id)
	if err != nil {
		return err
	}
	if row.Source != config.SourceConfig || row.Spec == "" {
		return ErrNotInUI
	}
	s, err := m.load(m.Effective().Defaults)
	if err != nil {
		return err
	}
	delete(s.edited, strings.ToLower(row.Name))
	return m.change(s, func() error {
		_, err := m.st.UpdateTarget(id, row.Name, row.Host, "")
		return err
	})
}

// DeleteTarget removes a UI target and its data.
func (m *Manager) DeleteTarget(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.sched.RemoveTarget(id); err != nil {
		return err
	}
	s, err := m.load(m.Effective().Defaults)
	if err != nil {
		return err
	}
	eff, err := m.compute(s)
	if err != nil {
		// cannot happen (removing a target only removes references); keep the old one
		m.log.Error("recomputing settings after deleting a target failed", "err", err)
		return nil
	}
	m.eff.Store(eff)
	if m.eng != nil {
		m.eng.Reload(eff)
	}
	return nil
}

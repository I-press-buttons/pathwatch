package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Source values for targets.
const (
	SourceConfig = "config"
	SourceUI     = "ui"
)

// Probe type names.
const (
	ProbeICMPTrace = "icmp-trace"
	ProbeHTTP      = "http"
	ProbeTCP       = "tcp"
	ProbeDNS       = "dns"
)

// Target is a fully resolved target: defaults and overrides applied, durations parsed.
type Target struct {
	Name   string        `json:"name"`
	Host   string        `json:"host"`
	Source string        `json:"source"`
	ICMP   *ICMPSettings `json:"icmp,omitempty"` // nil when the target has no icmp-trace probe
	Probes []Probe       `json:"probes"`         // http and tcp probes
	Alerts TargetAlerts  `json:"-"`
}

// ICMPSettings are the resolved icmp-trace settings.
type ICMPSettings struct {
	Interval    time.Duration `json:"interval"`
	Timeout     time.Duration `json:"timeout"`
	Rediscovery time.Duration `json:"rediscovery"`
	MaxHops     int           `json:"max_hops"`
}

// Probe is a resolved http or tcp probe.
type Probe struct {
	Type     string        `json:"type"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`

	URL                string            `json:"url,omitempty"`
	Method             string            `json:"method,omitempty"`
	ExpectStatus       []int             `json:"expect_status,omitempty"`
	FollowRedirects    bool              `json:"follow_redirects,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	UserAgent          string            `json:"user_agent,omitempty"`
	InsecureSkipVerify bool              `json:"insecure_skip_verify,omitempty"`
	MaxBody            int64             `json:"max_body,omitempty"`
	UseEnvProxy        bool              `json:"use_env_proxy,omitempty"`
	PinIP              bool              `json:"pin_ip"`

	Port int `json:"port,omitempty"`
}

// Key is the stable identity of the probe within its target, derived from its config.
func (p Probe) Key() string {
	switch p.Type {
	case ProbeHTTP:
		return "http|" + p.Method + "|" + p.URL
	case ProbeTCP:
		return fmt.Sprintf("tcp|%d", p.Port)
	}
	return p.Type
}

// Label is the human readable probe description shown in the UI.
func (p Probe) Label() string {
	switch p.Type {
	case ProbeHTTP:
		return p.Method + " " + p.URL
	case ProbeTCP:
		return fmt.Sprintf("TCP :%d", p.Port)
	case ProbeICMPTrace:
		return "ICMP trace"
	}
	return p.Type
}

// DNSProbe is a resolved DNS resolver probe.
type DNSProbe struct {
	Name     string
	Server   string // host:port
	Query    string
	Record   string // A | AAAA
	Interval time.Duration
	Timeout  time.Duration
}

// Key is the stable identity of the DNS probe.
func (d DNSProbe) Key() string { return "dns|" + d.Name }

// Label is the human readable description.
func (d DNSProbe) Label() string { return d.Name }

var (
	nameRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,62}$`)
	hostLabel  = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)
	validRecs  = map[string]bool{"A": true, "AAAA": true}
	validNotif = map[string]bool{"webhook": true, "email": true}
)

// ValidName reports whether s is acceptable as a target name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ValidHost reports whether s is an IP literal or a plausible hostname.
func ValidHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	s = strings.TrimSuffix(s, ".")
	for _, l := range strings.Split(s, ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func pick(vals ...Duration) time.Duration {
	for _, v := range vals {
		if v != 0 {
			return time.Duration(v)
		}
	}
	return 0
}

// ResolveTarget applies defaults/overrides to a target config and validates it.
func ResolveTarget(tc TargetConfig, d Defaults) (Target, error) {
	var errs []string
	add := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }

	t := Target{Name: tc.Name, Host: tc.Host, Source: SourceConfig, Alerts: tc.Alerts}
	if !ValidName(tc.Name) {
		add("invalid name %q (letters, digits, space, '.', '_' and '-', max 63 chars)", tc.Name)
	}
	if !ValidHost(tc.Host) {
		add("invalid host %q (a hostname or IP address, no scheme or port)", tc.Host)
	}
	if tc.MaxHops < 0 || tc.MaxHops > 64 {
		add("max_hops must be between 1 and 64")
	}
	probes := tc.Probes
	if len(probes) == 0 {
		probes = []ProbeConfig{{Type: ProbeICMPTrace}}
	}
	seen := map[string]bool{}
	for i, pc := range probes {
		switch pc.Type {
		case ProbeICMPTrace:
			if t.ICMP != nil {
				add("probes[%d]: only one icmp-trace probe per target", i)
				continue
			}
			iv := pick(pc.Interval, tc.ICMPInterval, d.ICMPInterval)
			to := pick(pc.Timeout, tc.ICMPTimeout, d.ICMPTimeout)
			rd := pick(tc.PathRediscovery, d.PathRediscovery)
			mh := tc.MaxHops
			if mh == 0 {
				mh = d.MaxHops
			}
			if iv < 500*time.Millisecond {
				add("probes[%d]: icmp interval %v is too small (minimum 500ms)", i, iv)
			}
			if to <= 0 {
				add("probes[%d]: icmp timeout must be positive", i)
			}
			if to > iv {
				to = iv // never longer than the round interval
			}
			if rd < 10*time.Second {
				add("probes[%d]: path_rediscovery %v is too small (minimum 10s)", i, rd)
			}
			t.ICMP = &ICMPSettings{Interval: iv, Timeout: to, Rediscovery: rd, MaxHops: mh}
		case ProbeHTTP:
			p, err := resolveHTTP(pc, tc, d)
			if err != nil {
				add("probes[%d]: %v", i, err)
				continue
			}
			if seen[p.Key()] {
				add("probes[%d]: duplicate probe %s", i, p.Label())
				continue
			}
			seen[p.Key()] = true
			t.Probes = append(t.Probes, p)
		case ProbeTCP:
			p, err := resolveTCP(pc, tc, d)
			if err != nil {
				add("probes[%d]: %v", i, err)
				continue
			}
			if seen[p.Key()] {
				add("probes[%d]: duplicate probe %s", i, p.Label())
				continue
			}
			seen[p.Key()] = true
			t.Probes = append(t.Probes, p)
		case "":
			add("probes[%d]: missing type (icmp-trace, http or tcp)", i)
		default:
			add("probes[%d]: unknown probe type %q (icmp-trace, http or tcp; DNS probes live under dns_probes)", i, pc.Type)
		}
	}
	if len(errs) > 0 {
		return t, fmt.Errorf("target %q: %s", tc.Name, strings.Join(errs, "; "))
	}
	return t, nil
}

func resolveHTTP(pc ProbeConfig, tc TargetConfig, d Defaults) (Probe, error) {
	p := Probe{
		Type:               ProbeHTTP,
		Interval:           pick(pc.Interval, tc.HTTPInterval, d.HTTPInterval),
		Timeout:            pick(pc.Timeout, d.HTTPTimeout),
		URL:                pc.URL,
		Method:             strings.ToUpper(pc.Method),
		ExpectStatus:       []int(pc.ExpectStatus),
		FollowRedirects:    pc.FollowRedirects,
		Headers:            pc.Headers,
		UserAgent:          pc.UserAgent,
		InsecureSkipVerify: pc.InsecureSkipVerify,
		MaxBody:            pc.MaxBody,
		UseEnvProxy:        pc.UseEnvProxy,
		PinIP:              pc.PinIP == nil || *pc.PinIP,
	}
	if p.Method == "" {
		p.Method = "GET"
	}
	if p.Method != "GET" && p.Method != "HEAD" {
		return p, fmt.Errorf("http method must be GET or HEAD, got %q", pc.Method)
	}
	u, err := url.Parse(p.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return p, fmt.Errorf("invalid url %q (must be http:// or https://)", p.URL)
	}
	for _, s := range p.ExpectStatus {
		if s < 100 || s > 599 {
			return p, fmt.Errorf("expect_status %d out of range", s)
		}
	}
	if p.MaxBody == 0 {
		p.MaxBody = defaultMaxBody
	}
	if p.MaxBody < 0 {
		return p, fmt.Errorf("max_body must be positive")
	}
	if p.Interval < time.Second {
		return p, fmt.Errorf("http interval %v is too small (minimum 1s)", p.Interval)
	}
	if p.Timeout <= 0 {
		return p, fmt.Errorf("timeout must be positive")
	}
	return p, nil
}

func resolveTCP(pc ProbeConfig, tc TargetConfig, d Defaults) (Probe, error) {
	p := Probe{
		Type:     ProbeTCP,
		Interval: pick(pc.Interval, tc.TCPInterval, d.TCPInterval),
		Timeout:  pick(pc.Timeout, d.TCPTimeout),
		Port:     pc.Port,
		PinIP:    true,
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if p.Port < 1 || p.Port > 65535 {
		return p, fmt.Errorf("tcp port %d out of range", p.Port)
	}
	if p.Interval < time.Second {
		return p, fmt.Errorf("tcp interval %v is too small (minimum 1s)", p.Interval)
	}
	if p.Timeout <= 0 {
		return p, fmt.Errorf("timeout must be positive")
	}
	return p, nil
}

// ResolveDNSProbe applies defaults to a DNS probe config and validates it.
func ResolveDNSProbe(dc DNSProbeConfig, d Defaults) (DNSProbe, error) {
	p := DNSProbe{
		Name:     dc.Name,
		Server:   dc.Server,
		Query:    dc.Query,
		Record:   strings.ToUpper(dc.Record),
		Interval: pick(dc.Interval, d.DNSInterval),
		Timeout:  pick(dc.Timeout, d.DNSTimeout),
	}
	if !ValidName(p.Name) {
		return p, fmt.Errorf("dns probe: invalid name %q", dc.Name)
	}
	if p.Record == "" {
		p.Record = "A"
	}
	if !validRecs[p.Record] {
		return p, fmt.Errorf("dns probe %q: record must be A or AAAA", p.Name)
	}
	if p.Server == "" {
		return p, fmt.Errorf("dns probe %q: server is required (host:port)", p.Name)
	}
	if _, _, err := net.SplitHostPort(p.Server); err != nil {
		if ap, perr := netip.ParseAddr(strings.Trim(p.Server, "[]")); perr == nil {
			p.Server = net.JoinHostPort(ap.String(), "53")
		} else if !strings.Contains(p.Server, ":") && ValidHost(p.Server) {
			p.Server = net.JoinHostPort(p.Server, "53")
		} else {
			return p, fmt.Errorf("dns probe %q: invalid server %q", p.Name, dc.Server)
		}
	}
	if !ValidHost(p.Query) {
		return p, fmt.Errorf("dns probe %q: invalid query %q", p.Name, dc.Query)
	}
	if p.Interval < time.Second {
		return p, fmt.Errorf("dns probe %q: interval too small (minimum 1s)", p.Name)
	}
	if p.Timeout <= 0 {
		return p, fmt.Errorf("dns probe %q: timeout must be positive", p.Name)
	}
	return p, nil
}

// UITargetRequest is the payload for creating a UI-managed target.
type UITargetRequest struct {
	Name           string
	Host           string
	ICMPIntervalMS int
	HTTPURL        string
	TCPPort        int
}

// NewUITarget builds and validates a target created from the UI.
func NewUITarget(r UITargetRequest, d Defaults) (Target, error) {
	tc := TargetConfig{Name: strings.TrimSpace(r.Name), Host: strings.TrimSpace(r.Host)}
	if r.ICMPIntervalMS < 0 {
		return Target{}, fmt.Errorf("icmp_interval_ms must be positive")
	}
	if r.ICMPIntervalMS > 0 {
		tc.ICMPInterval = Duration(time.Duration(r.ICMPIntervalMS) * time.Millisecond)
		if tc.ICMPInterval.D() > time.Hour {
			return Target{}, fmt.Errorf("icmp_interval_ms too large")
		}
	}
	tc.Probes = []ProbeConfig{{Type: ProbeICMPTrace}}
	if r.HTTPURL != "" {
		tc.Probes = append(tc.Probes, ProbeConfig{Type: ProbeHTTP, URL: r.HTTPURL})
	}
	if r.TCPPort != 0 {
		tc.Probes = append(tc.Probes, ProbeConfig{Type: ProbeTCP, Port: r.TCPPort})
	}
	t, err := ResolveTarget(tc, d)
	if err != nil {
		return t, err
	}
	t.Source = SourceUI
	return t, nil
}

// ResolveTargets returns the resolved config targets. The config must have been validated.
func (c *Config) ResolveTargets() []Target {
	out := make([]Target, 0, len(c.Targets))
	for _, tc := range c.Targets {
		t, err := ResolveTarget(tc, c.Defaults)
		if err != nil {
			continue
		}
		out = append(out, t)
	}
	return out
}

// ResolveDNSProbes returns the resolved DNS probes. The config must have been validated.
func (c *Config) ResolveDNSProbes() []DNSProbe {
	out := make([]DNSProbe, 0, len(c.DNSProbes))
	for _, dc := range c.DNSProbes {
		p, err := ResolveDNSProbe(dc, c.Defaults)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

// RuleNamesAndTypes returns the set of configured rule names and types.
func (c *Config) ruleKeys() []string {
	set := map[string]bool{}
	for _, t := range RuleTypes {
		set[t] = true
	}
	for _, r := range c.Alerts.Rules {
		set[r.Name] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

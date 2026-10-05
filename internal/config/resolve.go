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
	Retries            int               `json:"retries,omitempty"`

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
	Retries  int
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
	_, err := NormalizeHost(s)
	return err == nil
}

// Host kinds reported by HostKind.
const (
	HostIPv4     = "ipv4"
	HostIPv6     = "ipv6"
	HostHostname = "hostname"
)

// HostKind classifies a valid host: an IPv4 address, an IPv6 address or a hostname (an FQDN
// such as "example.com." or "nas.example.com", or a short name the system resolver completes).
func HostKind(s string) string {
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		if a.Unmap().Is4() {
			return HostIPv4
		}
		return HostIPv6
	}
	return HostHostname
}

// NormalizeHost validates a target host and returns its canonical form. Accepted: IPv4
// addresses, IPv6 addresses (optionally in brackets, with a zone), and hostnames: fully
// qualified (a trailing dot is kept, it stops the resolver's search list) or short. Hostnames
// are lower-cased. Common mistakes (a URL, a port) get an error that says what to change.
func NormalizeHost(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("host is required (a hostname such as example.com, or an IP address)")
	}
	if i := strings.Index(s, "://"); i >= 0 {
		return "", fmt.Errorf("invalid host %q: enter only the host name or IP address, without %q (the URL belongs in an HTTP probe)", s, s[:i+3])
	}
	if strings.ContainsAny(s, "/?#@ \t") {
		return "", fmt.Errorf("invalid host %q: enter only a host name or IP address, without a path or spaces", s)
	}
	inner := s
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner = s[1 : len(s)-1]
	}
	if a, err := netip.ParseAddr(inner); err == nil {
		if a.Is4In6() {
			a = a.Unmap()
		}
		return a.String(), nil
	}
	if strings.HasPrefix(s, "[") {
		return "", fmt.Errorf("invalid IPv6 address %q", s)
	}
	if h, p, err := net.SplitHostPort(s); err == nil && p != "" {
		return "", fmt.Errorf("invalid host %q: remove the port (:%s); use %q and set the port on a TCP probe", s, p, h)
	}
	if strings.Count(s, ":") > 1 {
		return "", fmt.Errorf("invalid IPv6 address %q", s)
	}
	if len(s) > 254 || (len(s) == 254 && !strings.HasSuffix(s, ".")) {
		return "", fmt.Errorf("invalid host %q: longer than 253 characters", s)
	}
	name := strings.TrimSuffix(s, ".")
	if name == "" {
		return "", fmt.Errorf("invalid host %q", s)
	}
	labels := strings.Split(name, ".")
	for _, l := range labels {
		if l == "" {
			return "", fmt.Errorf("invalid host %q: empty label (two dots in a row?)", s)
		}
		if !hostLabel.MatchString(l) {
			return "", fmt.Errorf("invalid host %q: label %q may only contain letters, digits, '-' and '_' (max 63 characters, no leading or trailing '-')", s, l)
		}
	}
	// A top-level domain is never all digits, so "10.0.0" or "300.1.1.1" is a mistyped
	// IPv4 address, not a hostname.
	if isDigits(labels[len(labels)-1]) {
		return "", fmt.Errorf("invalid IPv4 address %q", s)
	}
	return strings.ToLower(s), nil
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// pickRetries returns the first set value of vals, or def.
func pickRetries(def int, vals ...*int) int {
	for _, v := range vals {
		if v != nil {
			return *v
		}
	}
	return def
}

func checkRetries(n int) error {
	if n < 0 || n > MaxRetries {
		return fmt.Errorf("retries must be between 0 and %d", MaxRetries)
	}
	return nil
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
	if h, err := NormalizeHost(tc.Host); err != nil {
		add("%v", err)
	} else {
		t.Host = h
	}
	if tc.MaxHops < 0 || tc.MaxHops > 64 {
		add("max_hops must be between 1 and 64")
	}
	if tc.Retries != nil && (*tc.Retries < 0 || *tc.Retries > MaxRetries) {
		add("retries must be between 0 and %d", MaxRetries)
	}
	if len(tc.Probes) > MaxProbesPerTarget {
		add("too many probes (%d, max %d)", len(tc.Probes), MaxProbesPerTarget)
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
		Retries:            pickRetries(d.Retries, pc.Retries, tc.Retries),
	}
	if err := checkRetries(p.Retries); err != nil {
		return p, err
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
		Retries:  pickRetries(d.Retries, pc.Retries, tc.Retries),
	}
	if err := checkRetries(p.Retries); err != nil {
		return p, err
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
		Retries:  pickRetries(d.Retries, dc.Retries),
	}
	if !ValidName(p.Name) {
		return p, fmt.Errorf("dns probe: invalid name %q", dc.Name)
	}
	if err := checkRetries(p.Retries); err != nil {
		return p, fmt.Errorf("dns probe %q: %v", p.Name, err)
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

// Config converts the simple create request into a target definition.
func (r UITargetRequest) Config() (TargetConfig, error) {
	tc := TargetConfig{Name: strings.TrimSpace(r.Name), Host: strings.TrimSpace(r.Host)}
	if r.ICMPIntervalMS < 0 {
		return tc, fmt.Errorf("icmp_interval_ms must be positive")
	}
	if r.ICMPIntervalMS > 0 {
		tc.ICMPInterval = Duration(time.Duration(r.ICMPIntervalMS) * time.Millisecond)
	}
	tc.Probes = []ProbeConfig{{Type: ProbeICMPTrace}}
	if r.HTTPURL != "" {
		tc.Probes = append(tc.Probes, ProbeConfig{Type: ProbeHTTP, URL: r.HTTPURL})
	}
	if r.TCPPort != 0 {
		tc.Probes = append(tc.Probes, ProbeConfig{Type: ProbeTCP, Port: r.TCPPort})
	}
	return tc, nil
}

// maxUIInterval bounds probe intervals and timeouts entered in the UI.
const maxUIInterval = 24 * time.Hour

// ResolveUITarget validates a target definition edited in the UI and resolves it. On top of
// ResolveTarget it bounds durations (a typo of a few zeros should not stop a probe for years).
func ResolveUITarget(tc TargetConfig, d Defaults) (Target, error) {
	tc.Name = strings.TrimSpace(tc.Name)
	tc.Host = strings.TrimSpace(tc.Host)
	tooLarge := func(v Duration) bool { return v.D() > maxUIInterval }
	if tooLarge(tc.ICMPInterval) || tooLarge(tc.ICMPTimeout) || tooLarge(tc.TCPInterval) || tooLarge(tc.HTTPInterval) || tooLarge(tc.PathRediscovery) {
		return Target{}, fmt.Errorf("target %q: intervals and timeouts must be at most 24h", tc.Name)
	}
	for _, p := range tc.Probes {
		if tooLarge(p.Interval) || tooLarge(p.Timeout) {
			return Target{}, fmt.Errorf("target %q: intervals and timeouts must be at most 24h", tc.Name)
		}
	}
	t, err := ResolveTarget(tc, d)
	if err != nil {
		return t, err
	}
	t.Source = SourceUI
	return t, nil
}

// NewUITarget builds and validates a target created from the UI.
func NewUITarget(r UITargetRequest, d Defaults) (Target, error) {
	tc, err := r.Config()
	if err != nil {
		return Target{}, err
	}
	return ResolveUITarget(tc, d)
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

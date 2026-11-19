package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Environment variable names understood by pathwatch.
const (
	EnvConfig   = "PATHWATCH_CONFIG"
	EnvDB       = "PATHWATCH_DB"
	EnvListen   = "PATHWATCH_LISTEN"
	EnvUser     = "PATHWATCH_USER"
	EnvPassword = "PATHWATCH_PASSWORD"
)

// Defaults for settings that are not configured.
const (
	DefaultListen  = "127.0.0.1:8080"
	DefaultUser    = "admin"
	DefaultDBName  = "pathwatch.db"
	DefaultConfig  = "pathwatch.yaml"
	PasswordFile   = ".pathwatch-password"
	defaultMaxBody = 1 << 20
)

// Limits shared by the config file and the web UI, so a write API cannot make the instance run
// an unbounded number of probes.
const (
	// MaxTargets bounds the targets defined in the config file, and the config-file plus
	// UI-created targets together when a target is created. It is checked on create only for the
	// UI: a database that already holds more still starts (see settings.Manager.CreateTarget).
	MaxTargets = 200
	// MaxProbesPerTarget bounds the probes listed on one target.
	MaxProbesPerTarget = 16
	// MaxDNSProbes bounds the DNS servers (dns_probes entries, file or UI).
	MaxDNSProbes = 50
	// MaxDNSQueries bounds the queries of one DNS server.
	MaxDNSQueries = 32
	// MaxDNSQueriesTotal bounds the queries of all DNS servers together.
	MaxDNSQueriesTotal = 200
)

// Config is the top-level YAML document.
type Config struct {
	Listen    string `yaml:"listen"`
	PublicURL string `yaml:"public_url"`

	Auth    AuthConfig    `yaml:"auth"`
	TLS     TLSConfig     `yaml:"tls"`
	Log     LogConfig     `yaml:"log"`
	Storage StorageConfig `yaml:"storage"`
	Probing ProbingConfig `yaml:"probing"`
	Enrich  EnrichConfig  `yaml:"enrich"`
	Metrics MetricsConfig `yaml:"metrics"`

	PublicIP PublicIPConfig `yaml:"public_ip"`
	System   SystemConfig   `yaml:"system"`
	Digest   DigestConfig   `yaml:"digest"`

	Defaults  Defaults         `yaml:"defaults"`
	Status    StatusConfig     `yaml:"status"`
	Targets   []TargetConfig   `yaml:"targets"`
	DNSProbes []DNSProbeConfig `yaml:"dns_probes"`
	Alerts    AlertsConfig     `yaml:"alerts"`

	// UITargets are the definitions of the targets added in the web UI (stored in the
	// database, never in the file). They are set on effective configurations only, so per-target
	// alert settings apply to them as well.
	UITargets []TargetConfig `yaml:"-"`

	// Path is the file the configuration was loaded from.
	Path string `yaml:"-"`
	// Created is true when the file was missing and a starter config was written.
	Created bool `yaml:"-"`

	dbFromEnv bool
}

// AuthConfig configures HTTP Basic auth. Secrets come from the environment only.
type AuthConfig struct {
	BasicUser        string `yaml:"basic_user"`
	BasicPasswordEnv string `yaml:"basic_password_env"`
}

// TLSConfig enables built-in HTTPS.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// LogConfig configures slog output.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

// StorageConfig configures SQLite and retention. A retention of 0 keeps data forever.
type StorageConfig struct {
	Path              string    `yaml:"path"`
	RawRetention      *Duration `yaml:"raw_retention"`
	Rollup1mRetention *Duration `yaml:"rollup_1m_retention"`
	Rollup1hRetention *Duration `yaml:"rollup_1h_retention"`
}

// RetentionSettings are the retention periods as the web UI edits them; 0 keeps data forever.
type RetentionSettings struct {
	Raw      Duration `json:"raw_retention_ms"`
	Rollup1m Duration `json:"rollup_1m_retention_ms"`
	Rollup1h Duration `json:"rollup_1h_retention_ms"`
}

// RetentionSettings returns the retention periods (the config must have its defaults applied).
func (s StorageConfig) RetentionSettings() RetentionSettings {
	return RetentionSettings{Raw: s.RawRetention.orZero(), Rollup1m: s.Rollup1mRetention.orZero(), Rollup1h: s.Rollup1hRetention.orZero()}
}

func (d *Duration) orZero() Duration {
	if d == nil {
		return 0
	}
	return *d
}

// EnrichSettings is the part of the enrich section the web UI edits.
type EnrichSettings struct {
	ReverseDNS bool `json:"reverse_dns"`
}

// ProbingConfig holds platform prober options.
type ProbingConfig struct {
	ICMPMode string `yaml:"icmp_mode"`
}

// EnrichConfig configures hop enrichment.
type EnrichConfig struct {
	ReverseDNS *bool  `yaml:"reverse_dns"`
	ASNDB      string `yaml:"asn_db"`
}

// MetricsConfig controls the Prometheus /metrics endpoint. It is off by default; when on it is
// served behind the same Basic auth and Host check as the API.
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
}

// PublicIPConfig watches this network's public IPv4 and IPv6 addresses, so an ISP renumbering,
// a dropped PPPoE session or a failover to a backup line shows up. It is off by default: it
// contacts a service you did not configure as a target (OpenDNS by default).
type PublicIPConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Interval between checks (default 5m, minimum 30s).
	Interval Duration `yaml:"interval" json:"interval_ms"`
	// Source is "opendns" (default: an A/AAAA query for myip.opendns.com sent to the OpenDNS
	// resolvers over IPv4 and IPv6) or an http(s) URL that answers with the caller's address as
	// plain text (for example https://api.ipify.org), requested once over each family.
	Source string `yaml:"source" json:"source"`
	// SkipIPv6 checks IPv4 only.
	SkipIPv6 bool `yaml:"skip_ipv6" json:"skip_ipv6"`
}

// DigestConfig sends a periodic summary (availability, latency, incidents, public IP changes and
// monitor health) over the notification channels.
type DigestConfig struct {
	// Schedule is off (default), daily or weekly.
	Schedule string `yaml:"schedule" json:"schedule"`
	// Time of day it is sent, HH:MM (default 08:00).
	Time string `yaml:"time" json:"time"`
	// Weekday of a weekly digest, mon..sun (default mon).
	Weekday string `yaml:"weekday" json:"weekday,omitempty"`
	// Timezone of Time (an IANA name; default the server's local time zone).
	Timezone string `yaml:"timezone" json:"timezone,omitempty"`
	// Notify limits the channels (webhook, email); default every configured channel.
	Notify []string `yaml:"notify" json:"notify,omitempty"`
}

// Digest schedules.
const (
	DigestOff    = "off"
	DigestDaily  = "daily"
	DigestWeekly = "weekly"
)

// PublicIPSourceOpenDNS is the default public IP source.
const PublicIPSourceOpenDNS = "opendns"

// SystemConfig sets when pathwatch reports a problem with itself (the Monitor health card and the
// monitor_health alert rule).
type SystemConfig struct {
	// DiskFreeMinPct: warn when the data folder's file system has less free space than this
	// percentage (default 5).
	DiskFreeMinPct float64 `yaml:"disk_free_min_pct" json:"disk_free_min_pct"`
	// DiskFreeMinBytes: also warn below this many free bytes (default 500 MB).
	DiskFreeMinBytes int64 `yaml:"disk_free_min_bytes" json:"disk_free_min_bytes"`
	// NTPServer is asked for the time to measure this machine's clock offset ("" = off, the
	// default; for example pool.ntp.org). A drifting clock skews every timeline.
	NTPServer string `yaml:"ntp_server" json:"ntp_server"`
	// ClockMaxOffset: warn when the clock is off by more than this (default 2s).
	ClockMaxOffset Duration `yaml:"clock_max_offset" json:"clock_max_offset_ms"`
}

// Defaults are inherited by every target and probe. In JSON (the web API) durations are
// milliseconds and a zero or missing value means "the built-in default".
type Defaults struct {
	ICMPInterval    Duration `yaml:"icmp_interval" json:"icmp_interval_ms"`
	ICMPTimeout     Duration `yaml:"icmp_timeout" json:"icmp_timeout_ms"`
	TCPInterval     Duration `yaml:"tcp_interval" json:"tcp_interval_ms"`
	TCPTimeout      Duration `yaml:"tcp_timeout" json:"tcp_timeout_ms"`
	HTTPInterval    Duration `yaml:"http_interval" json:"http_interval_ms"`
	HTTPTimeout     Duration `yaml:"http_timeout" json:"http_timeout_ms"`
	DNSInterval     Duration `yaml:"dns_interval" json:"dns_interval_ms"`
	DNSTimeout      Duration `yaml:"dns_timeout" json:"dns_timeout_ms"`
	PathRediscovery Duration `yaml:"path_rediscovery" json:"path_rediscovery_ms"`
	MaxHops         int      `yaml:"max_hops" json:"max_hops"`
	// Retries is how many times a failed HTTP, TCP or DNS probe is retried before the
	// failure is recorded. ICMP traces never retry: an unanswered probe is the loss being measured.
	Retries int `yaml:"retries" json:"retries"`
	// DNSQuery is the name every DNS probe without its own query looks up, so all resolvers
	// answer the same question and their times compare fairly.
	DNSQuery string `yaml:"dns_query" json:"dns_query"`
}

// MaxRetries bounds the retries setting.
const MaxRetries = 10

// StatusConfig sets when a target is shown as "degraded" (the yellow status in the UI).
type StatusConfig struct {
	// DegradedLossPct: end-to-end loss over the last 5 minutes above this percentage.
	DegradedLossPct float64 `yaml:"degraded_loss_pct" json:"degraded_loss_pct"`
	// DegradedHTTPSuccessPct: HTTP success rate over the last 5 minutes below this percentage.
	DegradedHTTPSuccessPct float64 `yaml:"degraded_http_success_pct" json:"degraded_http_success_pct"`
}

// TargetConfig is one monitored destination. Zero-valued override fields inherit defaults.
type TargetConfig struct {
	Name string `yaml:"name" json:"name"`
	// Host is a hostname (FQDN or short name), an IPv4 address or an IPv6 address.
	Host string `yaml:"host" json:"host"`

	ICMPInterval    Duration `yaml:"icmp_interval" json:"icmp_interval_ms,omitempty"`
	ICMPTimeout     Duration `yaml:"icmp_timeout" json:"icmp_timeout_ms,omitempty"`
	TCPInterval     Duration `yaml:"tcp_interval" json:"tcp_interval_ms,omitempty"`
	HTTPInterval    Duration `yaml:"http_interval" json:"http_interval_ms,omitempty"`
	PathRediscovery Duration `yaml:"path_rediscovery" json:"path_rediscovery_ms,omitempty"`
	MaxHops         int      `yaml:"max_hops" json:"max_hops,omitempty"`
	Retries         *int     `yaml:"retries" json:"retries,omitempty"` // nil inherits defaults.retries

	Probes []ProbeConfig `yaml:"probes" json:"probes"`
	Alerts TargetAlerts  `yaml:"alerts" json:"alerts"`
}

// ProbeConfig is one probe of a target (icmp-trace, http or tcp).
type ProbeConfig struct {
	Type     string   `yaml:"type" json:"type"`
	Interval Duration `yaml:"interval" json:"interval_ms,omitempty"`
	Timeout  Duration `yaml:"timeout" json:"timeout_ms,omitempty"`
	Retries  *int     `yaml:"retries" json:"retries,omitempty"` // http and tcp; nil inherits

	// http
	URL                string            `yaml:"url" json:"url,omitempty"`
	Method             string            `yaml:"method" json:"method,omitempty"`
	ExpectStatus       IntList           `yaml:"expect_status" json:"expect_status,omitempty"`
	FollowRedirects    bool              `yaml:"follow_redirects" json:"follow_redirects,omitempty"`
	Headers            map[string]string `yaml:"headers" json:"headers,omitempty"`
	UserAgent          string            `yaml:"user_agent" json:"user_agent,omitempty"`
	InsecureSkipVerify bool              `yaml:"insecure_skip_verify" json:"insecure_skip_verify,omitempty"`
	MaxBody            int64             `yaml:"max_body" json:"max_body,omitempty"`
	UseEnvProxy        bool              `yaml:"use_env_proxy" json:"use_env_proxy,omitempty"`
	PinIP              *bool             `yaml:"pin_ip" json:"pin_ip,omitempty"`

	// tcp
	Port int `yaml:"port" json:"port,omitempty"`
}

// DefaultDNSQuery is the built-in defaults.dns_query.
const DefaultDNSQuery = "google.com"

// DNSQueryPresets are popular, widely cached names offered as DNS probe queries in the UI.
var DNSQueryPresets = []string{
	"google.com", "youtube.com", "facebook.com", "reddit.com", "wikipedia.org",
	"amazon.com", "apnews.com", "cloudflare.com", "microsoft.com", "apple.com",
}

// DNSProbeConfig is one DNS server (resolver) queried directly, independent of any target.
// It looks up each of its queries; without any it looks up defaults.dns_query. Record,
// interval, timeout and retries set here apply to every query that does not set its own.
type DNSProbeConfig struct {
	Name     string   `yaml:"name" json:"name"`
	Server   string   `yaml:"server" json:"server"`
	Query    string   `yaml:"query" json:"query,omitempty"` // a single query; use queries for several
	Record   string   `yaml:"record" json:"record,omitempty"`
	Interval Duration `yaml:"interval" json:"interval_ms,omitempty"`
	Timeout  Duration `yaml:"timeout" json:"timeout_ms,omitempty"`
	Retries  *int     `yaml:"retries" json:"retries,omitempty"`

	// Answer checks (see DNSAnswerChecks); queries that set none of their own inherit these.
	DNSAnswerChecks `yaml:",inline"`

	Queries []DNSQueryConfig `yaml:"queries" json:"queries,omitempty"`
}

// DNSAnswerChecks verify what a resolver answers, not only that it answers. A failed check is
// recorded as a failed DNS probe ("wrong answer: ..."), so the dns_failure rule alerts on it.
type DNSAnswerChecks struct {
	// Expect lists addresses or CIDR prefixes; every address in the answer must be in one of them
	// (and the answer must hold at least one address).
	Expect []string `yaml:"expect" json:"expect,omitempty"`
	// ExpectNXDomain is for a name that must not exist: NXDOMAIN is success, an address in the
	// answer means the resolver (or the ISP in between) rewrites unknown names.
	ExpectNXDomain bool `yaml:"expect_nxdomain" json:"expect_nxdomain,omitempty"`
	// CompareWith is a second resolver (host[:port]) asked the same question; the probe fails when
	// both return addresses and they have none in common.
	CompareWith string `yaml:"compare_with" json:"compare_with,omitempty"`
}

// IsZero reports whether no check is set.
func (c DNSAnswerChecks) IsZero() bool {
	return len(c.Expect) == 0 && !c.ExpectNXDomain && c.CompareWith == ""
}

// DNSQueryConfig is one name a DNS server is asked for. Zero fields inherit from the server.
// In YAML a plain string ("- reddit.com") is a query with no overrides.
type DNSQueryConfig struct {
	Query    string   `yaml:"query" json:"query"`
	Record   string   `yaml:"record" json:"record,omitempty"`
	Interval Duration `yaml:"interval" json:"interval_ms,omitempty"`
	Timeout  Duration `yaml:"timeout" json:"timeout_ms,omitempty"`
	Retries  *int     `yaml:"retries" json:"retries,omitempty"`

	DNSAnswerChecks `yaml:",inline"`
}

// UnmarshalYAML accepts a plain host name or a mapping with the fields of DNSQueryConfig.
func (q *DNSQueryConfig) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*q = DNSQueryConfig{Query: n.Value}
		return nil
	}
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: a query is a host name or a mapping with query, record, interval, timeout, retries, expect, expect_nxdomain and compare_with", n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch k := n.Content[i].Value; k {
		case "query", "record", "interval", "timeout", "retries", "expect", "expect_nxdomain", "compare_with":
		default:
			return fmt.Errorf("line %d: field %s not found in dns query", n.Content[i].Line, k)
		}
	}
	type plain DNSQueryConfig
	var v plain
	if err := n.Decode(&v); err != nil {
		return err
	}
	*q = DNSQueryConfig(v)
	return nil
}

// LoadOptions controls Load.
type LoadOptions struct {
	// CreateIfMissing writes a commented starter config when the file does not exist.
	CreateIfMissing bool
	// Getenv overrides os.Getenv (tests).
	Getenv func(string) string
}

// Load reads, strictly decodes, validates and applies env overrides to the config at path.
func Load(path string, opts LoadOptions) (*Config, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	created := false
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && opts.CreateIfMissing {
			if mkErr := os.MkdirAll(filepath.Dir(path), 0o700); mkErr != nil {
				return nil, fmt.Errorf("create config dir: %w", mkErr)
			}
			if wErr := os.WriteFile(path, []byte(StarterConfig), 0o600); wErr != nil {
				return nil, fmt.Errorf("write starter config: %w", wErr)
			}
			data = []byte(StarterConfig)
			created = true
		} else {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}
	cfg, err := Parse(data, getenv)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.Path = path
	cfg.Created = created
	cfg.resolvePaths(filepath.Dir(path), getenv)
	return cfg, nil
}

// Parse decodes YAML (strictly), applies env overrides and validates.
func Parse(data []byte, getenv func(string) string) (*Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	cfg.applyDefaults()
	cfg.applyEnv(getenv)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.Storage.Path == "" {
		c.Storage.Path = DefaultDBName
	}
	d := func(p **Duration, v Duration) {
		if *p == nil {
			x := v
			*p = &x
		}
	}
	d(&c.Storage.RawRetention, Duration(7*24*3600e9))
	d(&c.Storage.Rollup1mRetention, Duration(90*24*3600e9))
	d(&c.Storage.Rollup1hRetention, 0)
	if c.Probing.ICMPMode == "" {
		c.Probing.ICMPMode = "auto"
	}
	df := &c.Defaults
	dur := func(p *Duration, v string) {
		if *p == 0 {
			x, _ := ParseDuration(v)
			*p = Duration(x)
		}
	}
	dur(&df.ICMPInterval, "2s")
	dur(&df.ICMPTimeout, "2s")
	dur(&df.TCPInterval, "10s")
	dur(&df.TCPTimeout, "5s")
	dur(&df.HTTPInterval, "30s")
	dur(&df.HTTPTimeout, "10s")
	dur(&df.DNSInterval, "30s")
	dur(&df.DNSTimeout, "3s")
	if df.DNSQuery = strings.TrimSpace(df.DNSQuery); df.DNSQuery == "" {
		df.DNSQuery = DefaultDNSQuery
	}
	dur(&df.PathRediscovery, "5m")
	if df.MaxHops == 0 {
		df.MaxHops = 30
	}
	c.Status.applyDefaults()
	c.Alerts.applyDefaults()
	c.PublicIP.applyDefaults()
	c.System.applyDefaults()
	c.Digest.applyDefaults()
}

func (p *PublicIPConfig) applyDefaults() {
	if p.Interval == 0 {
		p.Interval = Duration(5 * time.Minute)
	}
	if p.Source = strings.TrimSpace(p.Source); p.Source == "" {
		p.Source = PublicIPSourceOpenDNS
	}
}

func (d *DigestConfig) applyDefaults() {
	d.Schedule = strings.ToLower(strings.TrimSpace(d.Schedule))
	if d.Schedule == "" {
		d.Schedule = DigestOff
	}
	if d.Time = strings.TrimSpace(d.Time); d.Time == "" {
		d.Time = "08:00"
	}
	if d.Weekday = strings.ToLower(strings.TrimSpace(d.Weekday)); d.Weekday == "" {
		d.Weekday = "mon"
	}
	d.Timezone = strings.TrimSpace(d.Timezone)
}

func (s *SystemConfig) applyDefaults() {
	if s.DiskFreeMinPct == 0 {
		s.DiskFreeMinPct = 5
	}
	if s.DiskFreeMinBytes == 0 {
		s.DiskFreeMinBytes = 500 << 20
	}
	if s.ClockMaxOffset == 0 {
		s.ClockMaxOffset = Duration(2 * time.Second)
	}
	s.NTPServer = strings.TrimSpace(s.NTPServer)
}

func (s *StatusConfig) applyDefaults() {
	if s.DegradedLossPct == 0 {
		s.DegradedLossPct = 5
	}
	if s.DegradedHTTPSuccessPct == 0 {
		s.DegradedHTTPSuccessPct = 95
	}
}

func (c *Config) applyEnv(getenv func(string) string) {
	if v := getenv(EnvListen); v != "" {
		c.Listen = v
	}
	if v := getenv(EnvDB); v != "" {
		c.Storage.Path = v
		c.dbFromEnv = true
	}
}

// resolvePaths makes relative paths in the file relative to the config file's directory.
func (c *Config) resolvePaths(dir string, getenv func(string) string) {
	rel := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	if !c.dbFromEnv {
		c.Storage.Path = rel(c.Storage.Path)
	}
	c.TLS.CertFile = rel(c.TLS.CertFile)
	c.TLS.KeyFile = rel(c.TLS.KeyFile)
	c.Log.File = rel(c.Log.File)
	c.Enrich.ASNDB = rel(c.Enrich.ASNDB)
}

// DataDir is the directory that holds the database (and the generated password file).
func (c *Config) DataDir() string {
	d := filepath.Dir(c.Storage.Path)
	if d == "" {
		return "."
	}
	return d
}

// ReverseDNSEnabled reports whether hop reverse DNS lookups are on (default true).
func (c *Config) ReverseDNSEnabled() bool {
	return c.Enrich.ReverseDNS == nil || *c.Enrich.ReverseDNS
}

// IsLoopbackListen reports whether the listen address only binds to loopback.
func IsLoopbackListen(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Auth is the resolved authentication setting.
type Auth struct {
	Enabled   bool
	User      string
	Password  string
	Generated bool // password was generated (and stored in PasswordFile)
	FilePath  string
}

// ResolveAuth determines credentials from env/config and, when the bind is not
// loopback and no password is configured, reads or generates the password file.
func (c *Config) ResolveAuth(getenv func(string) string) (Auth, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	a := Auth{User: DefaultUser}
	if c.Auth.BasicUser != "" {
		a.User = c.Auth.BasicUser
	}
	if v := getenv(EnvUser); v != "" {
		a.User = v
	}
	envName := c.Auth.BasicPasswordEnv
	if envName == "" {
		envName = EnvPassword
	}
	a.Password = getenv(envName)
	if a.Password == "" && envName != EnvPassword {
		a.Password = getenv(EnvPassword)
	}
	if a.Password != "" {
		a.Enabled = true
		return a, nil
	}
	if IsLoopbackListen(c.Listen) {
		return a, nil // auth off on loopback without a password
	}
	a.Enabled = true
	a.FilePath = filepath.Join(c.DataDir(), PasswordFile)
	if b, err := os.ReadFile(a.FilePath); err == nil {
		if pw := strings.TrimSpace(string(b)); pw != "" {
			a.Password = pw
			return a, nil
		}
	}
	pw, err := GeneratePassword()
	if err != nil {
		return a, err
	}
	if err := os.MkdirAll(c.DataDir(), 0o700); err != nil {
		return a, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.WriteFile(a.FilePath, []byte(pw+"\n"), 0o600); err != nil {
		return a, fmt.Errorf("write password file: %w", err)
	}
	a.Password = pw
	a.Generated = true
	return a, nil
}

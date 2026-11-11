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
	// MaxDNSProbes bounds the DNS probes (file or UI).
	MaxDNSProbes = 50
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

// DNSProbeConfig queries a resolver directly, independent of any target.
type DNSProbeConfig struct {
	Name     string   `yaml:"name" json:"name"`
	Server   string   `yaml:"server" json:"server"`
	Query    string   `yaml:"query" json:"query"`
	Record   string   `yaml:"record" json:"record,omitempty"`
	Interval Duration `yaml:"interval" json:"interval_ms,omitempty"`
	Timeout  Duration `yaml:"timeout" json:"timeout_ms,omitempty"`
	Retries  *int     `yaml:"retries" json:"retries,omitempty"`
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
	dur(&df.PathRediscovery, "5m")
	if df.MaxHops == 0 {
		df.MaxHops = 30
	}
	c.Status.applyDefaults()
	c.Alerts.applyDefaults()
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

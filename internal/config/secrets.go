package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// ProbeEnvPrefix is the only environment namespace HTTP probe header values may reference as
// ${NAME}. Targets can be created through the API, so unrestricted expansion would let an API
// caller send PATHWATCH_PASSWORD or the SMTP password to a server of their choosing.
const ProbeEnvPrefix = "PATHWATCH_PROBE_"

// HeaderPlaceholder replaces literal probe header values in API responses. Sending it back
// keeps the stored value (see RestoreHeaders).
const HeaderPlaceholder = "********"

// ExpandProbeHeader expands ${NAME} references in an HTTP probe header value at request time.
// Only names starting with ProbeEnvPrefix are read; any other name expands to the empty string,
// so a reference to a different variable can never leak it. "$$" yields a literal "$".
// getenv defaults to os.Getenv.
func ExpandProbeHeader(v string, getenv func(string) string) string {
	if !strings.Contains(v, "$") {
		return v
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	return os.Expand(v, func(name string) string {
		if name == "$" {
			return "$"
		}
		if strings.HasPrefix(name, ProbeEnvPrefix) {
			return getenv(name)
		}
		return ""
	})
}

var envRef = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)

// headerIsReference reports whether a header value holds no literal secret: at least one ${VAR}
// reference, optionally preceded by an auth scheme word.
func headerIsReference(v string) bool {
	if !envRef.MatchString(v) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(envRef.ReplaceAllString(v, ""))) {
	case "", "bearer", "basic", "token":
		return true
	}
	return false
}

// RedactTarget returns a copy of tc whose literal probe header values are replaced by
// HeaderPlaceholder. Pure ${VAR} references stay visible. tc is not modified.
func RedactTarget(tc TargetConfig) TargetConfig {
	tc.Probes = append([]ProbeConfig(nil), tc.Probes...)
	for i := range tc.Probes {
		h := tc.Probes[i].Headers
		if len(h) == 0 {
			continue
		}
		out := make(map[string]string, len(h))
		for k, v := range h {
			if !headerIsReference(v) {
				v = HeaderPlaceholder
			}
			out[k] = v
		}
		tc.Probes[i].Headers = out
	}
	return tc
}

func probeConfigKey(p ProbeConfig) string {
	m := strings.ToUpper(strings.TrimSpace(p.Method))
	if m == "" {
		m = "GET"
	}
	return m + "|" + strings.TrimSpace(p.URL)
}

// storedHeader finds the value of header name on the HTTP probe of stored that matches p.
func storedHeader(stored TargetConfig, p ProbeConfig, name string) (string, bool) {
	if p.Type != ProbeHTTP {
		return "", false
	}
	for _, sp := range stored.Probes {
		if sp.Type != ProbeHTTP || probeConfigKey(sp) != probeConfigKey(p) {
			continue
		}
		for k, v := range sp.Headers {
			if strings.EqualFold(k, name) {
				return v, true
			}
		}
	}
	return "", false
}

// RestoreHeaders replaces HeaderPlaceholder values in tc with the value stored for the same HTTP
// probe (same method and URL) and header name in stored. It fails when there is nothing to
// restore, for example because the probe's URL changed: the value must be entered again.
// stored may be the zero value (a new target). tc is not modified.
func RestoreHeaders(tc, stored TargetConfig) (TargetConfig, error) {
	var out []ProbeConfig
	for i, p := range tc.Probes {
		for k, v := range p.Headers {
			if v != HeaderPlaceholder {
				continue
			}
			restored, ok := storedHeader(stored, p, k)
			if !ok {
				return tc, fmt.Errorf("probes[%d]: header %q has no stored value for this probe (its URL or method changed, or the probe is new); re-enter the header value", i, k)
			}
			if out == nil {
				out = append([]ProbeConfig(nil), tc.Probes...)
			}
			h := make(map[string]string, len(out[i].Headers))
			for hk, hv := range out[i].Headers {
				h[hk] = hv
			}
			h[k] = restored
			out[i].Headers = h
		}
	}
	if out != nil {
		tc.Probes = out
	}
	return tc, nil
}

// maskUserinfo hides a password embedded in a URL (scheme://user:pass@host) for display.
func maskUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, has := u.User.Password(); has {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	return u.String()
}

package web

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// contentSecurityPolicy is strict on purpose: the UI loads only same-origin files, uses no inline
// script or style (styles are applied through the CSSOM, which CSP does not restrict) and must not
// be framed by any other site.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// securityHeaders is the outermost middleware, so every response carries the headers: UI, assets,
// API, 401/403/421/429 and recovered panics. HSTS is sent only when this process terminates TLS
// itself, and with a short lifetime; behind a TLS reverse proxy the proxy should set it.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	tls := s.d.Config != nil && s.d.Config.TLS.CertFile != ""
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY") // legacy browsers; frame-ancestors is the modern control
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		if tls {
			h.Set("Strict-Transport-Security", "max-age=86400")
		}
		next.ServeHTTP(w, r)
	})
}

// hostCheck defends an unauthenticated instance against DNS rebinding: a page on an attacker's
// domain that re-resolves to this machine sends requests that are same-origin from the browser's
// point of view, but carry the attacker's name in Host. With auth off only loopback names and
// IPs and the public_url host are served. With auth on the check is skipped (browsers do not
// send cached credentials to the rebound origin, and LAN access by IP or NAS name must keep
// working). X-Forwarded-Host is deliberately ignored: page script can set it.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	if s.d.Auth.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			writeError(w, http.StatusMisdirectedRequest, "unexpected Host header")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	if s.d.Config != nil && s.d.Config.PublicURL != "" {
		if pu, err := url.Parse(s.d.Config.PublicURL); err == nil && pu.Hostname() != "" && strings.EqualFold(pu.Hostname(), host) {
			return true
		}
	}
	return false
}

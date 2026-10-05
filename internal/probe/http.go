package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

// HTTPResult is the outcome of one HTTP probe, with per-phase timings.
type HTTPResult struct {
	Status       int
	DNS          time.Duration
	Connect      time.Duration
	TLS          time.Duration
	TTFB         time.Duration
	Transfer     time.Duration
	Total        time.Duration
	Redirects    int
	FinalURL     string
	CertNotAfter time.Time // leaf certificate of the first TLS handshake; zero when not HTTPS
	Err          error
	OK           bool
}

// HTTPOptions parameterise an HTTP probe.
type HTTPOptions struct {
	// Pin is the address every connection goes to (when Probe.PinIP is on); the URL's host is
	// still used for the Host header and TLS SNI. Zero means resolve normally.
	Pin netip.Addr
	// PinDNS is the time the per-cycle resolution took; it is reported as the DNS phase when pinned.
	PinDNS time.Duration
	// Version is used for the default User-Agent.
	Version string
}

// HTTPProbe performs one request on a fresh connection and measures its phases.
// Proxy environment variables are ignored unless the probe sets UseEnvProxy.
func HTTPProbe(ctx context.Context, p config.Probe, o HTTPOptions) HTTPResult {
	var res HTTPResult
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	pinned := p.PinIP && o.Pin.IsValid()
	dialer := &net.Dialer{Timeout: p.Timeout}
	tr := &http.Transport{
		DisableKeepAlives:   true,
		DisableCompression:  true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: p.InsecureSkipVerify}, //nolint:gosec // opt-in for internal targets
		TLSHandshakeTimeout: p.Timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if pinned {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				addr = net.JoinHostPort(o.Pin.String(), port)
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	if p.UseEnvProxy {
		tr.Proxy = http.ProxyFromEnvironment
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !p.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			res.Redirects = len(via)
			// net/http copies custom headers to every hop; do not hand the configured ones
			// (API keys, tokens) to another origin.
			if o := via[0].URL; req.URL.Scheme != o.Scheme || req.URL.Host != o.Host || req.URL.Port() != o.Port() {
				for k := range p.Headers {
					req.Header.Del(k)
				}
			}
			return nil
		},
	}

	var (
		dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, wrote, firstByte time.Time
		start                                                                       = time.Now()
		gotConn                                                                     time.Time
	)
	setOnce := func(t *time.Time) {
		if t.IsZero() {
			*t = time.Now()
		}
	}
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { setOnce(&dnsStart) },
		DNSDone:           func(httptrace.DNSDoneInfo) { setOnce(&dnsDone) },
		ConnectStart:      func(_, _ string) { setOnce(&connStart) },
		ConnectDone:       func(_, _ string, _ error) { setOnce(&connDone) },
		TLSHandshakeStart: func() { setOnce(&tlsStart) },
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if tlsDone.IsZero() {
				tlsDone = time.Now()
				if err == nil && len(cs.PeerCertificates) > 0 {
					res.CertNotAfter = cs.PeerCertificates[0].NotAfter
				}
			}
		},
		GotConn:              func(httptrace.GotConnInfo) { setOnce(&gotConn) },
		WroteRequest:         func(httptrace.WroteRequestInfo) { setOnce(&wrote) },
		GotFirstResponseByte: func() { setOnce(&firstByte) },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), p.Method, p.URL, nil)
	if err != nil {
		res.Err = err
		return res
	}
	ua := p.UserAgent
	if ua == "" {
		ua = "pathwatch/" + o.Version
	}
	req.Header.Set("User-Agent", ua)
	for k, v := range p.Headers {
		v = config.ExpandProbeHeader(v, nil)
		if http.CanonicalHeaderKey(k) == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		res.Total = time.Since(start)
		if pinned {
			res.Total += o.PinDNS
		}
		res.Err = simplifyHTTPErr(err)
		fillPhases(&res, pinned, o.PinDNS, dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, gotConn, firstByte, time.Time{})
		return res
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	res.FinalURL = resp.Request.URL.String()
	var bodyDone time.Time
	if p.Method != http.MethodHead {
		_, cerr := io.Copy(io.Discard, io.LimitReader(resp.Body, p.MaxBody))
		bodyDone = time.Now()
		if cerr != nil {
			res.Err = simplifyHTTPErr(cerr)
		}
	} else {
		bodyDone = time.Now()
	}
	end := time.Now()
	res.Total = end.Sub(start)
	if pinned {
		res.Total += o.PinDNS
	}
	fillPhases(&res, pinned, o.PinDNS, dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, gotConn, firstByte, bodyDone)
	if res.Err == nil && !statusOK(res.Status, p.ExpectStatus) {
		res.Err = fmt.Errorf("unexpected status %d", res.Status)
	}
	res.OK = res.Err == nil
	return res
}

func fillPhases(r *HTTPResult, pinned bool, pinDNS time.Duration, dnsStart, dnsDone, connStart, connDone, tlsStart, tlsDone, gotConn, firstByte, bodyDone time.Time) {
	if pinned {
		r.DNS = pinDNS
	} else if !dnsStart.IsZero() && !dnsDone.IsZero() {
		r.DNS = dnsDone.Sub(dnsStart)
	}
	if !connStart.IsZero() && !connDone.IsZero() {
		r.Connect = connDone.Sub(connStart)
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		r.TLS = tlsDone.Sub(tlsStart)
	}
	ready := gotConn
	if !tlsDone.IsZero() && tlsDone.After(ready) {
		ready = tlsDone
	}
	if !firstByte.IsZero() && !ready.IsZero() && firstByte.After(ready) {
		r.TTFB = firstByte.Sub(ready)
	}
	if !bodyDone.IsZero() && !firstByte.IsZero() && bodyDone.After(firstByte) {
		r.Transfer = bodyDone.Sub(firstByte)
	}
}

func statusOK(code int, expect []int) bool {
	if len(expect) == 0 {
		return code >= 100 && code < 400
	}
	for _, e := range expect {
		if e == code {
			return true
		}
	}
	return false
}

func simplifyHTTPErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return errors.New("timeout")
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return errors.New(oe.Op + ": " + oe.Err.Error())
	}
	return err
}

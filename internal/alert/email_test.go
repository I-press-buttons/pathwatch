package alert

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

type smtpMsg struct {
	from    string
	rcpts   []string
	data    string
	authed  string
	usedTLS bool
}

// fakeSMTP is a tiny SMTP server: EHLO, optional STARTTLS and AUTH PLAIN, MAIL/RCPT/DATA/QUIT.
type fakeSMTP struct {
	ln       net.Listener
	tlsCfg   *tls.Config
	starttls bool // advertise STARTTLS
	implicit bool // the listener speaks TLS from the first byte
	auth     bool
	mu       sync.Mutex
	msgs     []smtpMsg
	fail     bool // reply 554 to DATA
}

func selfSigned(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

func newFakeSMTP(t *testing.T, starttls, implicit, auth bool) *fakeSMTP {
	t.Helper()
	f := &fakeSMTP{starttls: starttls, implicit: implicit, auth: auth}
	if starttls || implicit {
		f.tlsCfg = selfSigned(t)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if implicit {
		ln = tls.NewListener(ln, f.tlsCfg)
	}
	f.ln = ln
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	usedTLS := f.implicit
	r := bufio.NewReader(c)
	w := func(s string) { c.Write([]byte(s + "\r\n")) }
	w("220 fake ESMTP")
	var cur smtpMsg
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			w("250-fake")
			if f.starttls && !usedTLS {
				w("250-STARTTLS")
			}
			if f.auth {
				w("250-AUTH PLAIN")
			}
			w("250 8BITMIME")
		case up == "STARTTLS":
			w("220 ready")
			tc := tls.Server(c, f.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			c = tc
			r = bufio.NewReader(tc)
			w = func(s string) { tc.Write([]byte(s + "\r\n")) }
			usedTLS = true
		case strings.HasPrefix(up, "AUTH PLAIN"):
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
			cur.authed = strings.ReplaceAll(string(raw), "\x00", "|")
			w("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			cur.from = between(line)
			w("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			cur.rcpts = append(cur.rcpts, between(line))
			w("250 ok")
		case up == "DATA":
			w("354 go")
			var sb strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				sb.WriteString(strings.TrimPrefix(l, ".")) // undo dot-stuffing (only leading dots matter)
			}
			if f.fail {
				w("554 rejected")
				continue
			}
			cur.data = sb.String()
			cur.usedTLS = usedTLS
			f.mu.Lock()
			f.msgs = append(f.msgs, cur)
			f.mu.Unlock()
			cur = smtpMsg{authed: cur.authed}
			w("250 queued")
		case up == "QUIT":
			w("221 bye")
			return
		default:
			w("250 ok")
		}
	}
}

func (f *fakeSMTP) messages() []smtpMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]smtpMsg(nil), f.msgs...)
}

func emailCfg(f *fakeSMTP, mode string) config.EmailConfig {
	return config.EmailConfig{
		SMTPHost: "127.0.0.1", SMTPPort: f.port(), TLS: mode, UsernameEnv: "SMTP_USER", PasswordEnv: "SMTP_PASS",
		From: "pathwatch <alerts@nas.local>", To: []string{"me@example.com", "you@example.com"},
	}
}

func emailSender(cfg config.EmailConfig) *EmailSender {
	env := map[string]string{"SMTP_USER": "bob", "SMTP_PASS": "hunter2"}
	s := NewEmailSender(cfg, func(k string) string { return env[k] }, func() time.Time { return t0 })
	s.TLSConfig = &tls.Config{InsecureSkipVerify: true}
	return s
}

func TestEmailMessageFormatting(t *testing.T) {
	s := emailSender(config.EmailConfig{From: "pathwatch <alerts@nas.local>", To: []string{"me@example.com", "you@example.com"}})
	n := noteFor(StateFiring)
	msg := string(s.Message(n))
	head, body, ok := strings.Cut(msg, "\r\n\r\n")
	want(t, ok, "headers and body are separated by a blank line")
	for _, h := range []string{
		"From: pathwatch <alerts@nas.local>", "To: me@example.com, you@example.com",
		"Subject: [pathwatch] FIRING cloudflare: http-slow", "MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8", "Date: Tue, 10 Mar 2026 12:00:00 +0000",
	} {
		want(t, strings.Contains(head, h), "missing header %q in\n%s", h, head)
	}
	for _, b := range []string{
		"HTTP total 412ms vs baseline 85ms", "Target:   cloudflare", "Rule:     http-slow (http_latency)", "State:    FIRING",
		"Value:    412 ms", "Baseline: 85 ms", "Started:  2026-03-10 12:00:00 UTC", "Duration: 7m",
		"https://nas.local:8080/#/target/3?from=1&to=2",
	} {
		want(t, strings.Contains(body, b), "missing %q in body:\n%s", b, body)
	}
	want(t, !strings.Contains(strings.ReplaceAll(msg, "\r\n", ""), "\n"), "CRLF line endings throughout")

	res := string(s.Message(noteFor(StateResolved)))
	want(t, strings.Contains(res, "Subject: [pathwatch] RESOLVED cloudflare: http-slow") && strings.Contains(res, "Ended:    2026-03-10 12:05:00 UTC") && strings.Contains(res, "Duration: 5m"), "resolved message:\n%s", res)

	// non-ASCII target names are encoded in the subject
	n.Target = "bürö"
	want(t, strings.Contains(string(s.Message(n)), "Subject: =?utf-8?q?"), "encoded subject")
	// the local outage's suppressed alerts are listed
	n = noteFor(StateResolved)
	n.RuleType = RuleLocalConnectivity
	n.Details = []byte(`{"reason":"gateway","suppressed":[{"alert_id":4,"target":"cf","rule":"end-loss"}]}`)
	want(t, strings.Contains(Body(n), "cf: end-loss"), "suppressed list in body:\n%s", Body(n))
}

func TestEmailSendNoTLS(t *testing.T) {
	f := newFakeSMTP(t, false, false, true)
	s := emailSender(emailCfg(f, "none"))
	if err := s.Send(context.Background(), noteFor(StateFiring)); err != nil {
		t.Fatal(err)
	}
	m := f.messages()
	want(t, len(m) == 1, "one message per alert event, got %d", len(m))
	want(t, m[0].from == "alerts@nas.local", "envelope sender %q", m[0].from)
	want(t, strings.Join(m[0].rcpts, ",") == "me@example.com,you@example.com", "recipients %v", m[0].rcpts)
	want(t, !m[0].usedTLS, "tls: none stays in the clear")
	want(t, m[0].authed == "|bob|hunter2", "AUTH PLAIN credentials from env, got %q", m[0].authed)
	want(t, strings.Contains(m[0].data, "Subject: [pathwatch] FIRING cloudflare: http-slow"), "data:\n%s", m[0].data)
}

func TestEmailSendStartTLS(t *testing.T) {
	f := newFakeSMTP(t, true, false, true)
	if err := emailSender(emailCfg(f, "starttls")).Send(context.Background(), noteFor(StateResolved)); err != nil {
		t.Fatal(err)
	}
	m := f.messages()
	want(t, len(m) == 1 && m[0].usedTLS, "the message must travel over the upgraded connection: %+v", m)
	want(t, m[0].authed == "|bob|hunter2", "credentials sent after STARTTLS")
	want(t, strings.Contains(m[0].data, "RESOLVED"), "data")
}

func TestEmailStartTLSRequiredButNotOffered(t *testing.T) {
	f := newFakeSMTP(t, false, false, false)
	err := emailSender(emailCfg(f, "starttls")).Send(context.Background(), noteFor(StateFiring))
	want(t, err != nil && strings.Contains(err.Error(), "STARTTLS"), "never silently downgrade: %v", err)
	want(t, len(f.messages()) == 0, "nothing was sent")
}

func TestEmailSendImplicitTLS(t *testing.T) {
	f := newFakeSMTP(t, false, true, true)
	if err := emailSender(emailCfg(f, "tls")).Send(context.Background(), noteFor(StateFiring)); err != nil {
		t.Fatal(err)
	}
	m := f.messages()
	want(t, len(m) == 1 && m[0].usedTLS, "implicit TLS (465 style): %+v", m)
}

func TestEmailVerifiesCertificateByDefault(t *testing.T) {
	f := newFakeSMTP(t, false, true, false)
	s := NewEmailSender(emailCfg(f, "tls"), func(string) string { return "" }, nil)
	err := s.Send(context.Background(), noteFor(StateFiring))
	want(t, err != nil, "a self-signed certificate must be rejected unless configured: got nil")
}

func TestEmailServerRejects(t *testing.T) {
	f := newFakeSMTP(t, false, false, false)
	f.fail = true
	err := emailSender(emailCfg(f, "none")).Send(context.Background(), noteFor(StateFiring))
	want(t, err != nil, "a 554 is a delivery failure (retried by the outbox)")
	if err := (&EmailSender{cfg: config.EmailConfig{}}).Send(context.Background(), noteFor(StateFiring)); err == nil || !IsPermanent(err) {
		t.Errorf("incomplete config is permanent: %v", err)
	}
	// connection refused: not permanent
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	err = emailSender(config.EmailConfig{SMTPHost: "127.0.0.1", SMTPPort: port, TLS: "none", From: "a@b", To: []string{"c@d"}}).Send(context.Background(), noteFor(StateFiring))
	want(t, err != nil && !IsPermanent(err), "connect failure retries: %v", err)
}

func TestEmailDefaultPorts(t *testing.T) {
	for mode, port := range map[string]int{"starttls": 587, "tls": 465, "none": 25} {
		s := NewEmailSender(config.EmailConfig{TLS: mode}, nil, nil)
		want(t, s.port() == port, "%s -> %d (%s)", mode, s.port(), strconv.Itoa(port))
	}
}

// between returns the text inside <...> of an SMTP command line.
func between(line string) string {
	i, j := strings.Index(line, "<"), strings.Index(line, ">")
	if i < 0 || j < i {
		return strings.TrimSpace(line)
	}
	return line[i+1 : j]
}

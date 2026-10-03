package alert

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

// emailTimeout bounds one whole SMTP delivery attempt.
const emailTimeout = 30 * time.Second

// EmailSender delivers one plain-text message per alert event over SMTP.
type EmailSender struct {
	cfg    config.EmailConfig
	getenv func(string) string
	now    func() time.Time
	// TLSConfig overrides the TLS client configuration (tests use a self-signed server).
	TLSConfig *tls.Config
}

// NewEmailSender prepares a sender. getenv and now may be nil.
func NewEmailSender(cfg config.EmailConfig, getenv func(string) string, now func() time.Time) *EmailSender {
	if getenv == nil {
		getenv = os.Getenv
	}
	if now == nil {
		now = time.Now
	}
	return &EmailSender{cfg: cfg, getenv: getenv, now: now}
}

func (e *EmailSender) port() int {
	if e.cfg.SMTPPort > 0 {
		return e.cfg.SMTPPort
	}
	switch e.cfg.TLS {
	case "tls":
		return 465
	case "none":
		return 25
	}
	return 587
}

// Subject returns the message subject, for example "[pathwatch] FIRING cloudflare: http-slow".
func Subject(n Notification) string { return "[pathwatch] " + n.Title() }

// Body returns the plain-text message body.
func Body(n Notification) string {
	var b strings.Builder
	switch n.State {
	case StateResolved:
		b.WriteString("pathwatch: alert resolved\n\n")
	case StateEvent:
		b.WriteString("pathwatch: event\n\n")
	default:
		b.WriteString("pathwatch: alert firing\n\n")
	}
	b.WriteString(n.Message + "\n\n")
	row := func(k, v string) {
		if v != "" {
			b.WriteString(fmt.Sprintf("%-10s%s\n", k+":", v))
		}
	}
	row("Target", n.Target)
	row("Rule", n.Rule+" ("+n.RuleType+")")
	row("State", strings.ToUpper(n.State))
	row("Value", n.ValueText())
	row("Baseline", n.BaselineText())
	if n.PeakValue != nil && n.State == StateResolved {
		row("Peak", FormatValue(*n.PeakValue, n.Unit))
	}
	row("Started", n.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	if n.EndedAt != nil {
		row("Ended", n.EndedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	row("Duration", FormatDuration(n.Duration()))
	if sup := suppressedFromDetails(n.Details); len(sup) > 0 {
		b.WriteString("\nAlerts suppressed during this outage:\n")
		for _, s := range sup {
			b.WriteString("  - " + s + "\n")
		}
	}
	if n.Link != "" {
		b.WriteString("\n" + n.Link + "\n")
	}
	return b.String()
}

// Message renders the full RFC 5322 message (CRLF line endings).
func (e *EmailSender) Message(n Notification) []byte {
	var b strings.Builder
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", e.cfg.From)
	h("To", strings.Join(e.cfg.To, ", "))
	h("Subject", mime.QEncoding.Encode("utf-8", headerSafe(Subject(n))))
	h("Date", e.now().Format(time.RFC1123Z))
	h("Message-ID", fmt.Sprintf("<pathwatch-%d-%d@%s>", n.AlertID, n.CreatedAt.UnixNano(), messageIDHost(e.cfg.From)))
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "8bit")
	h("X-Pathwatch-State", n.State)
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(Body(n), "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}

func messageIDHost(from string) string {
	if i := strings.LastIndex(from, "@"); i >= 0 {
		return strings.Trim(from[i+1:], "<> ")
	}
	return "pathwatch.local"
}

func bareAddress(a string) string {
	if i := strings.LastIndex(a, "<"); i >= 0 {
		if j := strings.Index(a[i:], ">"); j > 0 {
			return a[i+1 : i+j]
		}
	}
	return strings.TrimSpace(a)
}

// plainAuth is SMTP PLAIN authentication that, unlike net/smtp.PlainAuth, is also allowed on a
// connection without TLS (tls: none is an explicit choice of the operator).
type plainAuth struct{ user, pass string }

func (a plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.user + "\x00" + a.pass), nil
}

func (a plainAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge")
	}
	return nil, nil
}

// Send delivers one notification.
func (e *EmailSender) Send(ctx context.Context, n Notification) error {
	if e.cfg.SMTPHost == "" || len(e.cfg.To) == 0 || e.cfg.From == "" {
		return permanentError{errors.New("email channel is incomplete (smtp_host, from and to are required)")}
	}
	deadline := time.Now().Add(emailTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	addr := net.JoinHostPort(e.cfg.SMTPHost, strconv.Itoa(e.port()))
	tlsCfg := e.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{ServerName: e.cfg.SMTPHost, MinVersion: tls.VersionTLS12}
	} else if tlsCfg.ServerName == "" {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.ServerName = e.cfg.SMTPHost
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if e.cfg.TLS == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, e.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer c.Close()
	if e.cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp server does not offer STARTTLS (set tls: none to allow an unencrypted connection)")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	user := e.getenv(e.cfg.UsernameEnv)
	if e.cfg.UsernameEnv != "" && user != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(plainAuth{user, e.getenv(e.cfg.PasswordEnv)}); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}
	if err := c.Mail(bareAddress(e.cfg.From)); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, to := range e.cfg.To {
		if err := c.Rcpt(bareAddress(to)); err != nil {
			return fmt.Errorf("smtp RCPT TO: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(e.Message(n)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	_ = c.Quit()
	return nil
}

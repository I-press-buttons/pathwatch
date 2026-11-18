package config

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// NotifyEnvPrefix is the environment namespace that notification channels edited in the web UI
// may reference (url_env, username_env, password_env, and $NAME in webhook header values).
// Channels can be edited through the API, so unrestricted references would let an API caller
// send PATHWATCH_PASSWORD (or any other variable) to a server of their choosing. References the
// config file already makes are allowed too, as long as the channel still delivers to the same
// place (see CheckNotifyEnv).
const NotifyEnvPrefix = "PATHWATCH_NOTIFY_"

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// envRefs lists the environment variable names a header value expands at send time.
func envRefs(v string) []string {
	var out []string
	os.Expand(v, func(name string) string {
		if envName.MatchString(name) {
			out = append(out, name)
		}
		return ""
	})
	return out
}

// webhookDest identifies where a webhook delivers: its env var or its literal URL.
func webhookDest(w *WebhookConfig) string {
	if w.URLEnv != "" {
		return "env:" + w.URLEnv
	}
	return "url:" + strings.TrimSpace(w.URL)
}

// emailDest identifies where an email channel logs in: server, port and encryption (a change
// to tls: none would send the credentials in the clear).
func emailDest(e *EmailConfig) string {
	mode := strings.ToLower(strings.TrimSpace(e.TLS))
	if mode == "" {
		mode = "starttls"
	}
	port := e.SMTPPort
	if port == 0 {
		port = map[string]int{"starttls": 587, "tls": 465, "none": 25}[mode]
	}
	return fmt.Sprintf("%s:%d/%s", strings.ToLower(strings.TrimSpace(e.SMTPHost)), port, mode)
}

func headerValue(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(strings.TrimSpace(k), strings.TrimSpace(name)) {
			return v, true
		}
	}
	return "", false
}

// RedactNotify returns n with its secrets replaced by HeaderPlaceholder: a literal webhook URL
// (Discord and Slack URLs embed their token), literal webhook header values (pure ${VAR}
// references stay visible) and a literal SMTP password. n is not modified.
func RedactNotify(n NotifySettings) NotifySettings {
	n.Webhook, n.Email = n.Webhook.clone(), n.Email.clone()
	if w := n.Webhook; w != nil {
		if w.URL != "" {
			w.URL = HeaderPlaceholder
		}
		for k, v := range w.Headers {
			if !headerIsReference(v) {
				w.Headers[k] = HeaderPlaceholder
			}
		}
	}
	if e := n.Email; e != nil && e.Password != "" {
		e.Password = HeaderPlaceholder
	}
	return n
}

// RestoreNotify replaces HeaderPlaceholder values in n (as RedactNotify produced them) with the
// values in stored. A header value or password is only restored while the channel still
// delivers to the same place (same webhook URL or variable; same SMTP host and port), so a
// stored secret can never be redirected to a new destination: it must be entered again.
// n is not modified.
func RestoreNotify(n, stored NotifySettings) (NotifySettings, error) {
	n.Webhook, n.Email = n.Webhook.clone(), n.Email.clone()
	if w := n.Webhook; w != nil {
		sw := stored.Webhook
		if w.URL == HeaderPlaceholder {
			if sw == nil || sw.URL == "" {
				return n, fmt.Errorf("webhook: there is no saved URL to keep; enter the URL")
			}
			w.URL = sw.URL
		}
		var names []string
		for k, v := range w.Headers {
			if v == HeaderPlaceholder {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		for _, k := range names {
			var v string
			ok := sw != nil && webhookDest(sw) == webhookDest(w)
			if ok {
				v, ok = headerValue(sw.Headers, k)
			}
			if !ok {
				return n, fmt.Errorf("webhook header %q has no saved value for this URL (the URL changed, or the header is new); enter the header value again", k)
			}
			w.Headers[k] = v
		}
	}
	if e := n.Email; e != nil && e.Password == HeaderPlaceholder {
		se := stored.Email
		if se == nil || se.Password == "" || emailDest(se) != emailDest(e) {
			return n, fmt.Errorf("email: there is no saved password for this SMTP server (the server, port or encryption changed, or none was saved); enter the password again")
		}
		e.Password = se.Password
	}
	return n, nil
}

// CheckNotifyEnv checks the environment references of notification channels edited in the web
// UI. A reference must use NotifyEnvPrefix, unless file (the config file's channels) makes the
// same reference for a channel that delivers to the same place.
func CheckNotifyEnv(n NotifySettings, file NotifyConfig) error {
	bad := func(what, name string) error {
		return fmt.Errorf("%s: environment variable %s cannot be used from the web UI; channels edited here may only read variables starting with %s (or the ones the config file already uses for the same destination)", what, name, NotifyEnvPrefix)
	}
	if w := n.Webhook; w != nil {
		fw := file.Webhook
		if w.URLEnv != "" && !strings.HasPrefix(w.URLEnv, NotifyEnvPrefix) && (fw == nil || fw.URLEnv != w.URLEnv) {
			return bad("webhook URL", w.URLEnv)
		}
		same := fw != nil && webhookDest(fw) == webhookDest(w)
		keys := make([]string, 0, len(w.Headers))
		for k := range w.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := w.Headers[k]
			for _, name := range envRefs(v) {
				if strings.HasPrefix(name, NotifyEnvPrefix) {
					continue
				}
				if same {
					if fv, ok := headerValue(fw.Headers, k); ok && fv == v {
						continue
					}
				}
				return bad(fmt.Sprintf("webhook header %q", k), name)
			}
		}
	}
	if e := n.Email; e != nil {
		fe := file.Email
		same := fe != nil && emailDest(fe) == emailDest(e)
		for _, f := range []struct{ what, v, fileV string }{
			{"email username", e.UsernameEnv, fileField(fe, true)},
			{"email password", e.PasswordEnv, fileField(fe, false)},
		} {
			if f.v != "" && !strings.HasPrefix(f.v, NotifyEnvPrefix) && !(same && f.v == f.fileV) {
				return bad(f.what, f.v)
			}
		}
	}
	return nil
}

func fileField(e *EmailConfig, user bool) string {
	if e == nil {
		return ""
	}
	if user {
		return e.UsernameEnv
	}
	return e.PasswordEnv
}

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func TestWeakPasswordWarning(t *testing.T) {
	for _, tc := range []struct {
		name string
		auth config.Auth
		warn bool
	}{
		{"short user-set password", config.Auth{Enabled: true, User: "admin", Password: "hunter2"}, true},
		{"11 characters", config.Auth{Enabled: true, User: "admin", Password: "elevenchars"}, true},
		{"12 characters", config.Auth{Enabled: true, User: "admin", Password: "twelve chars"}, false},
		{"generated", config.Auth{Enabled: true, User: "admin", Password: "x", Generated: true, FilePath: "/data/password"}, false},
		{"stored generated", config.Auth{Enabled: true, User: "admin", Password: "x", FilePath: "/data/password"}, false},
		{"auth off", config.Auth{User: "admin"}, false},
	} {
		var buf bytes.Buffer
		logAuthStatus(slog.New(slog.NewTextHandler(&buf, nil)), tc.auth)
		out := buf.String()
		if got := strings.Contains(out, "shorter than 12 characters"); got != tc.warn {
			t.Errorf("%s: warned=%v, want %v\n%s", tc.name, got, tc.warn, out)
		}
		if tc.warn && !strings.Contains(out, "level=WARN") {
			t.Errorf("%s: not a warning:\n%s", tc.name, out)
		}
		if tc.auth.Password != "" && !tc.auth.Generated && strings.Contains(out, tc.auth.Password) {
			t.Errorf("%s: password logged:\n%s", tc.name, out)
		}
	}
}

func TestUserPassword(t *testing.T) {
	cfg, err := config.Parse(nil, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvPassword, "")
	if got := userPassword(cfg); got != "" {
		t.Errorf("%q", got)
	}
	t.Setenv(config.EnvPassword, "short")
	if got := userPassword(cfg); got != "short" || !weakPassword(got) {
		t.Errorf("%q", got)
	}
	cfg.Auth.BasicPasswordEnv = "MY_PW"
	t.Setenv("MY_PW", "a-much-longer-password")
	if got := userPassword(cfg); got != "a-much-longer-password" || weakPassword(got) {
		t.Errorf("%q", got)
	}
}

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStarterConfigOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "sub", "pathwatch.yaml")
	if _, err := Load(path, LoadOptions{CreateIfMissing: true, Getenv: env(nil)}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s: %v %v", p, fi, err)
		}
	}
}

func TestExpandProbeHeader(t *testing.T) {
	env := func(k string) string {
		return map[string]string{"PATHWATCH_PROBE_A": "a", "PATHWATCH_PASSWORD": "pw"}[k]
	}
	for in, want := range map[string]string{
		"Bearer ${PATHWATCH_PROBE_A}": "Bearer a",
		"$PATHWATCH_PROBE_A":          "a",
		"${PATHWATCH_PASSWORD}":       "",
		"${HOME}x":                    "x",
		"plain":                       "plain",
		"p$$w":                        "p$w",
	} {
		if got := ExpandProbeHeader(in, env); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestRedactAndRestoreHeaders(t *testing.T) {
	tc := TargetConfig{Name: "t", Probes: []ProbeConfig{{Type: ProbeHTTP, URL: "http://h/", Headers: map[string]string{
		"X-Key": "secret", "X-Ref": "${PATHWATCH_PROBE_K}", "Authorization": "Bearer ${PATHWATCH_PROBE_K}", "X-Mix": "abc${PATHWATCH_PROBE_K}",
	}}}}
	red := RedactTarget(tc)
	h := red.Probes[0].Headers
	if h["X-Key"] != HeaderPlaceholder || h["X-Mix"] != HeaderPlaceholder || h["X-Ref"] != "${PATHWATCH_PROBE_K}" || h["Authorization"] != "Bearer ${PATHWATCH_PROBE_K}" {
		t.Fatalf("redacted: %v", h)
	}
	if tc.Probes[0].Headers["X-Key"] != "secret" {
		t.Fatal("input modified")
	}
	back, err := RestoreHeaders(red, tc)
	if err != nil || back.Probes[0].Headers["X-Key"] != "secret" || back.Probes[0].Headers["X-Mix"] != "abc${PATHWATCH_PROBE_K}" {
		t.Fatalf("restore: %v %v", back.Probes[0].Headers, err)
	}
	if red.Probes[0].Headers["X-Key"] != HeaderPlaceholder {
		t.Fatal("restore modified its input")
	}
	red.Probes[0].URL = "http://other/"
	if _, err := RestoreHeaders(red, tc); err == nil || !strings.Contains(err.Error(), "re-enter") {
		t.Fatalf("changed url: %v", err)
	}
}

func TestProbeLabelMasksPassword(t *testing.T) {
	p := Probe{Type: ProbeHTTP, Method: "GET", URL: "https://u:pw@h.example/x"}
	if l := p.Label(); strings.Contains(l, "pw@") || !strings.Contains(l, "u:") {
		t.Errorf("label %q", l)
	}
}

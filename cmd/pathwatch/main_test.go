package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReorderFlags(t *testing.T) {
	got := reorderFlags([]string{"example.com", "-c", "5", "-n", "--mode", "raw"})
	want := []string{"-c", "5", "-n", "--mode", "raw", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%v != %v", got, want)
	}
}

func TestRotatingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "pw.log")
	r, err := newRotatingFile(p, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	line := strings.Repeat("x", 60) + "\n"
	for i := 0; i < 8; i++ {
		if _, err := r.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{p, p + ".1", p + ".2"} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Error("kept more rotated files than configured")
	}
}

func TestVersionString(t *testing.T) {
	if !strings.HasPrefix(versionString(), "pathwatch "+version) {
		t.Error(versionString())
	}
}

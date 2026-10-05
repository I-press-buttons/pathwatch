package store

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenCreatesOwnerOnlyFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not enforced on Windows")
	}
	path := filepath.Join(t.TempDir(), "t.db")
	s, err := Open(path, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), NoBackground: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	flushW(t, s)
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
	}
}

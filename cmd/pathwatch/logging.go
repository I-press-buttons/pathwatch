package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

// newLogger builds the slog logger. When a log file is configured, output goes to both stderr
// and the (size-rotated) file. Secrets are never passed to the logger by the application.
func newLogger(c config.LogConfig) (*slog.Logger, io.Closer) {
	var lvl slog.Level
	switch strings.ToLower(c.Level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	var w io.Writer = os.Stderr
	var closer io.Closer = nopCloser{}
	if c.File != "" {
		rf, err := newRotatingFile(c.File, 10<<20, 3)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pathwatch: cannot open log file %s: %v (logging to stderr only)\n", c.File, err)
		} else {
			w = io.MultiWriter(os.Stderr, rf)
			closer = rf
		}
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.EqualFold(c.Format, "json") {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h), closer
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// rotatingFile is a minimal size-based rotating log writer: path, path.1, path.2, ...
type rotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	keep int
	f    *os.File
	size int64
}

func newRotatingFile(path string, maxBytes int64, keep int) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	r := &rotatingFile{path: path, max: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > r.max && r.size > 0 {
		r.f.Close()
		for i := r.keep - 1; i >= 1; i-- {
			_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
		}
		_ = os.Rename(r.path, r.path+".1")
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

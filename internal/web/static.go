package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// staticHandler serves the embedded UI files. Everything is computed once at construction (an
// embed.FS has no modification times, so http.FileServer can neither send Last-Modified nor an
// ETag, and clients would re-download every asset on every load): each file gets a strong
// content-hash ETag and, for compressible types, a pre-compressed gzip variant with its own ETag.
// Assets are not fingerprinted, so responses stay "no-cache": clients revalidate with
// If-None-Match and get a 304 instead of the bytes.
type staticHandler struct {
	files map[string]*staticAsset // keyed by slash-separated path without a leading slash
}

// staticAsset is one file in both representations.
type staticAsset struct {
	ctype  string
	raw    []byte
	rawTag string
	gz     []byte // nil when the type is not worth compressing or gzip would not be smaller
	gzTag  string
}

// newStaticHandler reads every file of fsys into memory. Unreadable entries are logged and
// skipped.
func newStaticHandler(fsys fs.FS, log *slog.Logger) *staticHandler {
	h := &staticHandler{files: map[string]*staticAsset{}}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Warn("ui asset skipped", "path", p, "err", err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			log.Warn("ui asset skipped", "path", p, "err", err)
			return nil
		}
		h.files[p] = newStaticAsset(p, b)
		return nil
	})
	if err != nil {
		log.Warn("ui assets incomplete", "err", err)
	}
	return h
}

func newStaticAsset(name string, raw []byte) *staticAsset {
	ct := mime.TypeByExtension(path.Ext(name))
	if ct == "" {
		ct = http.DetectContentType(raw)
	}
	a := &staticAsset{ctype: ct, raw: raw, rawTag: contentETag(raw)}
	if compressible(ct) {
		if gz := gzipBest(raw); len(gz) < len(raw) {
			a.gz, a.gzTag = gz, contentETag(gz)
		}
	}
	return a
}

// contentETag is a strong validator: the quoted hash of the exact bytes sent. The gzip variant is
// hashed over its compressed bytes, so it gets a different tag than the identity variant.
func contentETag(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

func gzipBest(b []byte) []byte {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil
	}
	if _, err := zw.Write(b); err != nil {
		return nil
	}
	if err := zw.Close(); err != nil {
		return nil
	}
	return buf.Bytes()
}

// compressible reports whether a Content-Type is text-like (already-compressed formats such as
// PNG or WOFF2 gain nothing).
func compressible(ctype string) bool {
	mt, _, err := mime.ParseMediaType(ctype)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(ctype))
	}
	switch {
	case strings.HasPrefix(mt, "text/"), strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"):
		return true
	}
	switch mt {
	case "application/javascript", "application/x-javascript", "application/json", "application/xml",
		"application/wasm", "image/x-icon", "image/vnd.microsoft.icon", "image/bmp",
		"font/ttf", "font/otf", "application/vnd.ms-fontobject":
		return true
	}
	return false
}

// ServeHTTP serves the file at the request path. Paths that are not files fall back like a
// single-page app: without a file extension they get index.html, with one (a missing asset) they
// are a plain 404. Directories are never listed.
func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := path.Clean(r.URL.Path)
	if p == "/" || p == "." {
		p = "/index.html"
	}
	name := strings.TrimPrefix(p, "/")
	if a, ok := h.files[name]; ok {
		a.serve(w, r)
		return
	}
	if path.Ext(name) != "" {
		http.NotFound(w, r)
		return
	}
	idx := h.files["index.html"]
	if idx == nil {
		http.NotFound(w, r)
		return
	}
	idx.serve(w, r)
}

// serve picks the representation the client accepts and lets http.ServeContent do the rest:
// If-None-Match (weak comparison, "*"), 304, HEAD, Content-Length and Range. The ETag identifies
// the variant being sent, so a validator from a gzip response never matches the identity one.
func (a *staticAsset) serve(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Cache-Control", "no-cache")
	hd.Set("Content-Type", a.ctype)
	body, tag := a.raw, a.rawTag
	if a.gz != nil {
		hd.Add("Vary", "Accept-Encoding")
		if acceptsGzip(r.Header) {
			body, tag = a.gz, a.gzTag
			hd.Set("Content-Encoding", "gzip")
		}
	}
	hd.Set("ETag", tag)
	// ServeContent leaves Content-Length unset when Content-Encoding is present (it is dropped
	// again for 304 and error responses).
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
}

// acceptsGzip parses Accept-Encoding (RFC 9110 section 12.5.3): an explicit gzip entry decides,
// otherwise "*" does, and a quality of 0 means "not acceptable". Anything malformed counts as not
// accepted, which is always safe because identity is always served correctly.
func acceptsGzip(h http.Header) bool {
	var gzQ, starQ float64
	var gzSeen, starSeen bool
	for _, v := range h.Values("Accept-Encoding") {
		for _, part := range strings.Split(v, ",") {
			coding, params, _ := strings.Cut(part, ";")
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding == "" {
				continue
			}
			q := 1.0
			for _, prm := range strings.Split(params, ";") {
				k, val, ok := strings.Cut(prm, "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(k), "q") {
					continue
				}
				f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
				if err != nil {
					f = 0
				}
				q = f
			}
			switch coding {
			case "gzip", "x-gzip":
				gzQ, gzSeen = q, true
			case "*":
				starQ, starSeen = q, true
			}
		}
	}
	if gzSeen {
		return gzQ > 0
	}
	return starSeen && starQ > 0
}

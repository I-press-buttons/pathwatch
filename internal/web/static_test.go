package web

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	webui "github.com/i-press-buttons/pathwatch/web"
)

// staticFS is a small UI with a compressible page, script and stylesheet, a nested asset, an
// incompressible binary and a tiny file that gzip cannot shrink.
func staticFS(t *testing.T) fstest.MapFS {
	t.Helper()
	noise := make([]byte, 2048)
	if _, err := rand.Read(noise); err != nil {
		t.Fatal(err)
	}
	return fstest.MapFS{
		"index.html":        {Data: []byte("<!doctype html><title>ui</title>" + strings.Repeat("<p>app shell</p>\n", 50))},
		"app.js":            {Data: []byte(strings.Repeat("console.log('hello world');\n", 100))},
		"css/app.css":       {Data: []byte(strings.Repeat("body{margin:0;padding:0}\n", 100))},
		"js/views/page.js":  {Data: []byte(strings.Repeat("export const x = 1;\n", 80))},
		"img/noise.png":     {Data: noise},
		"tiny.txt":          {Data: []byte("hi")},
		"blob.unknownext12": {Data: []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("x", 64))},
	}
}

func staticServer(t *testing.T, fsys fs.FS) http.Handler {
	t.Helper()
	return New(Deps{Static: fsys}).Handler()
}

// staticDo serves one request in-process; hdr is a flat list of name, value pairs.
func staticDo(h http.Handler, method, target string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return out
}

func TestStaticETagStrongAndStable(t *testing.T) {
	fsys := staticFS(t)
	h := staticServer(t, fsys)
	w1 := staticDo(h, "GET", "/app.js")
	w2 := staticDo(h, "GET", "/app.js")
	tag := w1.Header().Get("ETag")
	if len(tag) < 4 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		t.Fatalf("ETag should be a quoted strong validator, got %q", tag)
	}
	if tag != w2.Header().Get("ETag") {
		t.Errorf("ETag changed between requests: %q vs %q", tag, w2.Header().Get("ETag"))
	}
	// Same content in another server instance: same tag (it is a content hash).
	if got := staticDo(staticServer(t, fsys), "GET", "/app.js").Header().Get("ETag"); got != tag {
		t.Errorf("ETag differs across servers for identical content: %q vs %q", got, tag)
	}
	// Different content: different tag.
	fsys["app.js"] = &fstest.MapFile{Data: []byte("changed();\n" + strings.Repeat("x", 500))}
	if got := staticDo(staticServer(t, fsys), "GET", "/app.js").Header().Get("ETag"); got == tag {
		t.Errorf("ETag unchanged after the content changed: %q", got)
	}
	// Distinct files have distinct tags.
	if staticDo(h, "GET", "/css/app.css").Header().Get("ETag") == tag {
		t.Error("different files share an ETag")
	}
}

func TestStaticHeaders(t *testing.T) {
	h := staticServer(t, staticFS(t))
	tests := []struct {
		path, ctype string
	}{
		{"/", "text/html"},
		{"/index.html", "text/html"},
		{"/app.js", "javascript"},
		{"/css/app.css", "text/css"},
		{"/js/views/page.js", "javascript"},
		{"/img/noise.png", "image/png"},
		{"/blob.unknownext12", "image/png"}, // no known extension: sniffed
	}
	for _, tc := range tests {
		w := staticDo(h, "GET", tc.path)
		if w.Code != 200 {
			t.Errorf("%s: status %d", tc.path, w.Code)
			continue
		}
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, tc.ctype) {
			t.Errorf("%s: Content-Type %q, want it to contain %q", tc.path, ct, tc.ctype)
		}
		if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("%s: Cache-Control %q", tc.path, cc)
		}
		if w.Header().Get("ETag") == "" {
			t.Errorf("%s: no ETag", tc.path)
		}
		if w.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) {
			t.Errorf("%s: Content-Length %q, body %d", tc.path, w.Header().Get("Content-Length"), w.Body.Len())
		}
	}
	// Compressible assets vary on Accept-Encoding.
	if v := staticDo(h, "GET", "/app.js").Header().Get("Vary"); !strings.Contains(v, "Accept-Encoding") {
		t.Errorf("Vary = %q", v)
	}
}

func TestStaticGzipNegotiation(t *testing.T) {
	fsys := staticFS(t)
	h := staticServer(t, fsys)
	want := fsys["app.js"].Data
	identity := staticDo(h, "GET", "/app.js")
	if identity.Header().Get("Content-Encoding") != "" || !bytes.Equal(identity.Body.Bytes(), want) {
		t.Fatalf("no Accept-Encoding must yield the identity body (encoding %q)", identity.Header().Get("Content-Encoding"))
	}

	w := staticDo(h, "GET", "/app.js", "Accept-Encoding", "gzip")
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("gzip not negotiated: %d %q", w.Code, w.Header().Get("Content-Encoding"))
	}
	if w.Body.Len() >= len(want) {
		t.Errorf("gzip body (%d) not smaller than the original (%d)", w.Body.Len(), len(want))
	}
	if !bytes.Equal(gunzip(t, w.Body.Bytes()), want) {
		t.Error("gzip body does not decompress to the original")
	}
	if cl := w.Header().Get("Content-Length"); cl != strconv.Itoa(w.Body.Len()) {
		t.Errorf("gzip Content-Length %q, body %d", cl, w.Body.Len())
	}
	if w.Header().Get("ETag") == identity.Header().Get("ETag") {
		t.Error("gzip and identity variants share an ETag")
	}
	if w.Header().Get("ETag") != staticDo(h, "GET", "/app.js", "Accept-Encoding", "gzip").Header().Get("ETag") {
		t.Error("gzip ETag is not stable")
	}

	for _, ae := range []string{
		"", "identity", "deflate, br", "gzip;q=0", "gzip; q=0.0", "gzip;q=0, *", "*;q=0", "gzip;q=bogus",
	} {
		w := staticDo(h, "GET", "/app.js", "Accept-Encoding", ae)
		if w.Header().Get("Content-Encoding") != "" || !bytes.Equal(w.Body.Bytes(), want) {
			t.Errorf("Accept-Encoding %q: got encoding %q, want identity", ae, w.Header().Get("Content-Encoding"))
		}
	}
	for _, ae := range []string{
		"gzip", "GZIP", "x-gzip", "gzip, deflate, br", "br, gzip;q=0.5", "deflate, gzip;q=1.0", "*", "gzip;q=0.001",
	} {
		w := staticDo(h, "GET", "/app.js", "Accept-Encoding", ae)
		if w.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(gunzip(t, w.Body.Bytes()), want) {
			t.Errorf("Accept-Encoding %q: got encoding %q, want gzip", ae, w.Header().Get("Content-Encoding"))
		}
	}
	// Several header lines are combined.
	w = staticDo(h, "GET", "/app.js", "Accept-Encoding", "deflate", "Accept-Encoding", "gzip")
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Error("gzip in a second Accept-Encoding header line was ignored")
	}
}

func TestStaticGzipSkippedWhenUseless(t *testing.T) {
	h := staticServer(t, staticFS(t))
	for _, p := range []string{"/img/noise.png", "/tiny.txt", "/blob.unknownext12"} {
		w := staticDo(h, "GET", p, "Accept-Encoding", "gzip")
		if w.Code != 200 || w.Header().Get("Content-Encoding") != "" {
			t.Errorf("%s: status %d encoding %q, want identity", p, w.Code, w.Header().Get("Content-Encoding"))
		}
		if w.Header().Get("ETag") == "" {
			t.Errorf("%s: no ETag", p)
		}
	}
	// Incompressible types are not varied by encoding.
	if v := staticDo(h, "GET", "/img/noise.png").Header().Get("Vary"); v != "" {
		t.Errorf("png Vary = %q", v)
	}
}

func TestStaticConditionalRequests(t *testing.T) {
	h := staticServer(t, staticFS(t))
	const gz = "gzip"
	idTag := staticDo(h, "GET", "/app.js").Header().Get("ETag")
	gzTag := staticDo(h, "GET", "/app.js", "Accept-Encoding", gz).Header().Get("ETag")

	notModified := func(name string, w *httptest.ResponseRecorder, tag string) {
		t.Helper()
		if w.Code != http.StatusNotModified {
			t.Errorf("%s: status %d, want 304", name, w.Code)
			return
		}
		if w.Body.Len() != 0 {
			t.Errorf("%s: 304 carried a body (%d bytes)", name, w.Body.Len())
		}
		if got := w.Header().Get("ETag"); got != tag {
			t.Errorf("%s: 304 ETag %q, want %q", name, got, tag)
		}
		if w.Header().Get("Cache-Control") != "no-cache" || !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") {
			t.Errorf("%s: 304 lost Cache-Control/Vary: %v", name, w.Header())
		}
		for _, k := range []string{"Content-Length", "Content-Type", "Content-Encoding"} {
			if w.Header().Get(k) != "" {
				t.Errorf("%s: 304 has %s %q", name, k, w.Header().Get(k))
			}
		}
	}
	notModified("identity", staticDo(h, "GET", "/app.js", "If-None-Match", idTag), idTag)
	notModified("gzip", staticDo(h, "GET", "/app.js", "Accept-Encoding", gz, "If-None-Match", gzTag), gzTag)
	notModified("weak", staticDo(h, "GET", "/app.js", "If-None-Match", "W/"+idTag), idTag)
	notModified("list", staticDo(h, "GET", "/app.js", "If-None-Match", `"nope", `+idTag+`, "other"`), idTag)
	notModified("star", staticDo(h, "GET", "/app.js", "If-None-Match", "*"), idTag)
	notModified("head", staticDo(h, "HEAD", "/app.js", "If-None-Match", idTag), idTag)
	notModified("spa", staticDo(h, "GET", "/targets/3", "If-None-Match", staticDo(h, "GET", "/").Header().Get("ETag")),
		staticDo(h, "GET", "/").Header().Get("ETag"))

	// A validator only matches the variant being served.
	w := staticDo(h, "GET", "/app.js", "If-None-Match", gzTag)
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "" {
		t.Errorf("gzip tag against identity: %d %q", w.Code, w.Header().Get("Content-Encoding"))
	}
	w = staticDo(h, "GET", "/app.js", "Accept-Encoding", gz, "If-None-Match", idTag)
	if w.Code != 200 || w.Header().Get("Content-Encoding") != gz {
		t.Errorf("identity tag against gzip: %d %q", w.Code, w.Header().Get("Content-Encoding"))
	}
	w = staticDo(h, "GET", "/app.js", "If-None-Match", `"stale"`)
	if w.Code != 200 || w.Body.Len() == 0 {
		t.Errorf("stale tag: %d, %d bytes", w.Code, w.Body.Len())
	}
	// A different file's tag does not match.
	cssTag := staticDo(h, "GET", "/css/app.css").Header().Get("ETag")
	if w := staticDo(h, "GET", "/app.js", "If-None-Match", cssTag); w.Code != 200 {
		t.Errorf("other file's tag: %d", w.Code)
	}
	// An asset with no gzip variant revalidates too.
	pngTag := staticDo(h, "GET", "/img/noise.png", "Accept-Encoding", gz).Header().Get("ETag")
	if w := staticDo(h, "GET", "/img/noise.png", "Accept-Encoding", gz, "If-None-Match", pngTag); w.Code != http.StatusNotModified {
		t.Errorf("png revalidation: %d", w.Code)
	}
}

func TestStaticHEAD(t *testing.T) {
	h := staticServer(t, staticFS(t))
	for _, ae := range []string{"", "gzip"} {
		get := staticDo(h, "GET", "/css/app.css", "Accept-Encoding", ae)
		head := staticDo(h, "HEAD", "/css/app.css", "Accept-Encoding", ae)
		if head.Code != 200 || head.Body.Len() != 0 {
			t.Errorf("HEAD (%q): status %d, body %d bytes", ae, head.Code, head.Body.Len())
		}
		for _, k := range []string{"ETag", "Content-Length", "Content-Type", "Content-Encoding", "Cache-Control", "Vary"} {
			if head.Header().Get(k) != get.Header().Get(k) {
				t.Errorf("HEAD (%q) %s = %q, GET has %q", ae, k, head.Header().Get(k), get.Header().Get(k))
			}
		}
		if head.Header().Get("Content-Length") != strconv.Itoa(get.Body.Len()) {
			t.Errorf("HEAD (%q) Content-Length %q, GET body %d", ae, head.Header().Get("Content-Length"), get.Body.Len())
		}
	}
	// SPA fallback answers HEAD as well.
	if w := staticDo(h, "HEAD", "/overview"); w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("ETag") == "" {
		t.Errorf("HEAD spa: %d, %d bytes, %v", w.Code, w.Body.Len(), w.Header())
	}
}

func TestStaticRange(t *testing.T) {
	fsys := staticFS(t)
	h := staticServer(t, fsys)
	w := staticDo(h, "GET", "/app.js", "Range", "bytes=0-6")
	if w.Code != http.StatusPartialContent || w.Body.String() != "console" {
		t.Errorf("range: %d %q", w.Code, w.Body.String())
	}
	if cl := w.Header().Get("Content-Length"); cl != "7" {
		t.Errorf("range Content-Length %q", cl)
	}
	if w := staticDo(h, "GET", "/app.js", "Range", "bytes=99999999-"); w.Code != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("unsatisfiable range: %d", w.Code)
	}
}

func TestStaticOverRealConnection(t *testing.T) {
	fsys := staticFS(t)
	ts := httptest.NewServer(staticServer(t, fsys))
	defer ts.Close()
	// DisableCompression: the transport must not add or undo Accept-Encoding itself.
	cl := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	defer cl.CloseIdleConnections()

	req, _ := http.NewRequest("GET", ts.URL+"/js/views/page.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" || resp.ContentLength != int64(len(body)) {
		t.Errorf("gzip over the wire: encoding %q, Content-Length %d, body %d", resp.Header.Get("Content-Encoding"), resp.ContentLength, len(body))
	}
	if !bytes.Equal(gunzip(t, body), fsys["js/views/page.js"].Data) {
		t.Error("gzip body over the wire does not decompress to the original")
	}

	req.Header.Set("If-None-Match", resp.Header.Get("ETag"))
	resp, err = cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified || len(body) != 0 {
		t.Errorf("revalidation over the wire: %d, %d bytes", resp.StatusCode, len(body))
	}
}

func TestStaticFallbackAndErrors(t *testing.T) {
	fsys := staticFS(t)
	h := staticServer(t, fsys)
	index := fsys["index.html"].Data
	indexTag := staticDo(h, "GET", "/").Header().Get("ETag")

	// The app shell: at "/", at /index.html and for unknown extensionless paths (also nested ones
	// and directory names, which are never listed).
	for _, p := range []string{"/", "/index.html", "/targets/3/anything", "/overview", "/css", "/css/", "/js/views", "/img"} {
		w := staticDo(h, "GET", p)
		if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), index) {
			t.Errorf("%s: %d, want the app shell", p, w.Code)
			continue
		}
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s: headers %v", p, w.Header())
		}
		if w.Header().Get("ETag") != indexTag {
			t.Errorf("%s: ETag %q, want the index tag %q", p, w.Header().Get("ETag"), indexTag)
		}
	}
	w := staticDo(h, "GET", "/targets/3", "Accept-Encoding", "gzip")
	if w.Header().Get("Content-Encoding") != "gzip" || !bytes.Equal(gunzip(t, w.Body.Bytes()), index) {
		t.Error("SPA fallback is not served gzip-compressed")
	}

	// Existing assets, including nested ones.
	if w := staticDo(h, "GET", "/js/views/page.js"); w.Code != 200 || !bytes.Equal(w.Body.Bytes(), fsys["js/views/page.js"].Data) {
		t.Errorf("nested asset: %d", w.Code)
	}

	// Missing assets (a path with an extension) are plain 404s, not the app shell.
	for _, p := range []string{"/missing.js", "/js/nope.js", "/css/app.css.map", "/img/x.png"} {
		w := staticDo(h, "GET", p)
		if w.Code != 404 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") || w.Header().Get("ETag") != "" {
			t.Errorf("%s: %d %q etag %q", p, w.Code, w.Header().Get("Content-Type"), w.Header().Get("ETag"))
		}
	}

	// /api/ is never the UI.
	w = staticDo(h, "GET", "/api/nonexistent")
	if w.Code != 404 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || !strings.Contains(w.Body.String(), `"error"`) {
		t.Errorf("api 404: %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body)
	}

	// Anything but GET/HEAD is a JSON 405 with an Allow header.
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		for _, p := range []string{"/", "/app.js", "/missing.js", "/some/route"} {
			w := staticDo(h, m, p)
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" ||
				!strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || !strings.Contains(w.Body.String(), `"error"`) {
				t.Errorf("%s %s: %d allow %q type %q", m, p, w.Code, w.Header().Get("Allow"), w.Header().Get("Content-Type"))
			}
		}
	}
}

func TestStaticUnavailable(t *testing.T) {
	// No Static: a JSON "ui not available" 404, as before.
	h := New(Deps{}).Handler()
	for _, p := range []string{"/", "/app.js", "/targets/1"} {
		w := staticDo(h, "GET", p)
		if w.Code != 404 || !strings.Contains(w.Body.String(), "ui not available") {
			t.Errorf("%s: %d %s", p, w.Code, w.Body)
		}
	}
	// A file system without index.html: the SPA fallback is a 404 rather than a panic.
	h = staticServer(t, fstest.MapFS{"app.js": {Data: []byte("x")}})
	if w := staticDo(h, "GET", "/"); w.Code != 404 {
		t.Errorf("no index.html: %d", w.Code)
	}
	if w := staticDo(h, "GET", "/some/route"); w.Code != 404 {
		t.Errorf("no index.html, spa route: %d", w.Code)
	}
	if w := staticDo(h, "GET", "/app.js"); w.Code != 200 {
		t.Errorf("asset without index.html: %d", w.Code)
	}
}

func TestAcceptsGzip(t *testing.T) {
	tests := []struct {
		header string
		want   bool
	}{
		{"", false},
		{"gzip", true},
		{"identity", false},
		{"gzip;q=1", true},
		{"gzip;q=0", false},
		{"gzip;q=0.0", false},
		{"gzip;q=0.000", false},
		{"gzip ; q = 0.5", true},
		{"gzip;level=1;q=0", false},
		{"gzip;q=", false},
		{"gzip;q=NaN", false},
		{"gzip;q=-1", false},
		{"*", true},
		{"*;q=0", false},
		{"*;q=0.1", true},
		{"identity, *;q=0", false},
		{"gzip;q=0, *;q=1", false},
		{"gzip, *;q=0", true},
		{"deflate, GZip", true},
		{",,gzip,,", true},
		{"compress, br", false},
		{"xgzip", false},
		{"gzipped", false},
	}
	for _, tc := range tests {
		h := http.Header{}
		if tc.header != "" {
			h.Set("Accept-Encoding", tc.header)
		}
		if got := acceptsGzip(h); got != tc.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
}

// TestStaticEmbeddedUI runs the real embedded UI through the handler: every file must be served
// byte-for-byte (identity) and, when gzip is smaller, as a valid gzip stream of the same bytes.
func TestStaticEmbeddedUI(t *testing.T) {
	sub, err := fs.Sub(webui.Static, "static")
	if err != nil {
		t.Fatal(err)
	}
	h := staticServer(t, sub)
	var files, gzipped int
	var identityBytes, gzipBytes int
	err = fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		files++
		want, err := fs.ReadFile(sub, p)
		if err != nil {
			return err
		}
		target := "/" + p
		if p == "index.html" {
			target = "/"
		}
		id := staticDo(h, "GET", target)
		if id.Code != 200 || !bytes.Equal(id.Body.Bytes(), want) || id.Header().Get("ETag") == "" {
			t.Errorf("%s: identity response wrong (%d)", p, id.Code)
			return nil
		}
		identityBytes += id.Body.Len()
		z := staticDo(h, "GET", target, "Accept-Encoding", "gzip")
		if z.Code != 200 {
			t.Errorf("%s: gzip request status %d", p, z.Code)
			return nil
		}
		body := z.Body.Bytes()
		if z.Header().Get("Content-Encoding") == "gzip" {
			gzipped++
			if z.Header().Get("ETag") == id.Header().Get("ETag") {
				t.Errorf("%s: gzip and identity share an ETag", p)
			}
			body = gunzip(t, body)
			if z.Body.Len() >= len(want) {
				t.Errorf("%s: gzip variant (%d) is not smaller than the original (%d)", p, z.Body.Len(), len(want))
			}
		}
		gzipBytes += z.Body.Len()
		if !bytes.Equal(body, want) {
			t.Errorf("%s: gzip response does not match the file", p)
		}
		if n := staticDo(h, "GET", target, "Accept-Encoding", "gzip", "If-None-Match", z.Header().Get("ETag")); n.Code != http.StatusNotModified || n.Body.Len() != 0 {
			t.Errorf("%s: revalidation %d, %d bytes", p, n.Code, n.Body.Len())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 || gzipped == 0 {
		t.Fatalf("embedded UI looks empty: %d files, %d gzipped", files, gzipped)
	}
	t.Logf("embedded UI: %d files, %d gzipped, %d bytes identity, %d bytes with gzip", files, gzipped, identityBytes, gzipBytes)
}

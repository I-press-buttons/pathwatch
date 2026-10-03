// Package web embeds the browser UI (web/static) into the binary.
package web

import "embed"

// Static is the embedded UI: index.html, css, js and vendored libraries under "static/".
//
//go:embed static
var Static embed.FS

//go:build !embedui

// Package ui holds the web UI's built files for the suppline binary.
//
// This build was made without the embedui tag, so it serves a placeholder
// page. Build with `make build` (or `go build -tags embedui` after
// `npm run build` in ui/) to include the real UI.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed notbuilt
var notBuilt embed.FS

// Files returns a placeholder index.html explaining how to build the UI.
func Files() fs.FS {
	sub, err := fs.Sub(notBuilt, "notbuilt")
	if err != nil {
		panic(err) // the embed directive guarantees notbuilt exists
	}
	return sub
}

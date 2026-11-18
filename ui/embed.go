//go:build embedui

// Package ui holds the web UI's built files for the suppline binary.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed dist
var dist embed.FS

// Files returns the built UI (the contents of ui/dist).
func Files() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err) // the embed directive guarantees dist exists
	}
	return sub
}

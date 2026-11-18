package config

import (
	"path/filepath"
	"testing"
)

// TestShippedConfigsParse keeps the example configs in step with the strict
// schema: an unknown or renamed key fails here instead of at startup.
func TestShippedConfigsParse(t *testing.T) {
	for _, name := range []string{
		"suppline.yml.example",
		"suppline.demo.yml",
		"charts/suppline/suppline.yml",
		"test/integration/testdata/regsync.test.yml",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRegsync(filepath.Join("..", "..", name)); err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
		})
	}
}

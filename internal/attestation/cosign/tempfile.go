package cosign

import (
	"encoding/json"
	"fmt"
	"os"
)

// TempFile represents a temporary file that will be cleaned up
type TempFile struct {
	path string
}

// NewTempFile creates a temporary file with the given pattern and content
func NewTempFile(pattern string, data []byte) (*TempFile, error) {
	tmpFile, err := os.CreateTemp("", pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to write to temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	return &TempFile{path: tmpFile.Name()}, nil
}

// NewTempFileJSON creates a temporary file with JSON content
func NewTempFileJSON(pattern string, v interface{}) (*TempFile, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return NewTempFile(pattern, data)
}

// Path returns the path to the temporary file
func (t *TempFile) Path() string {
	return t.path
}

// Cleanup removes the temporary file
func (t *TempFile) Cleanup() error {
	if t.path != "" {
		return os.Remove(t.path)
	}
	return nil
}

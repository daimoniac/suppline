package triage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// RotateBackups shifts path.bak.1 (newest) toward path.bak.N and copies the
// current file into path.bak.1. Files past retention are removed.
func RotateBackups(path string, retention int) error {
	if retention < 1 {
		return nil
	}
	oldest := fmt.Sprintf("%s.bak.%d", path, retention)
	if err := os.Remove(oldest); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", oldest, err)
	}
	for i := retention - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.bak.%d", path, i)
		to := fmt.Sprintf("%s.bak.%d", path, i+1)
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("rotate %s: %w", from, err)
		}
	}
	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s for backup: %w", path, err)
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	dst, err := os.OpenFile(path+".bak.1", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Sync(); err != nil {
		dst.Close()
		return err
	}
	return dst.Close()
}

// AtomicWrite replaces path via a temporary file in the same directory.
func AtomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	cleanup = false
	return nil
}

// Writable reports whether path can be updated in place.
func Writable(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("suppline config is not writable (%s): %w", path, err)
	}
	return file.Close()
}

// WriteLocal keeps a rotated backup, then atomically replaces path.
func WriteLocal(path string, retention int, data []byte) error {
	if err := RotateBackups(path, retention); err != nil {
		return err
	}
	return AtomicWrite(path, data)
}

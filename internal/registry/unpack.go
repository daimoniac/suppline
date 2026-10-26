package registry

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const (
	maxImageExtractBytes = 512 << 20
	maxImageFileBytes    = 64 << 20
)

type extractLimits struct {
	maxTotal int64
	maxFile  int64
}

// UnpackImage writes the filesystem of a scanned image into dest.
func (c *clientImpl) UnpackImage(ctx context.Context, repo, digest, dest string) error {
	registryName, repository, err := parseImageRef(repo)
	if err != nil {
		return errors.NewPermanentf("failed to parse repository: %w", err)
	}
	imageRef := fmt.Sprintf("%s/%s@%s", registryName, repository, digest)
	ref, err := name.ParseReference(imageRef, c.nameOptions(registryName)...)
	if err != nil {
		return errors.NewPermanentf("failed to parse image reference: %w", err)
	}
	auth := c.getAuthForRegistry(registryName)
	opts := append([]remote.Option{remote.WithAuth(auth), remote.WithContext(ctx)}, c.remoteOpts...)
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return errors.ClassifyRegistryError(fmt.Errorf("failed to get image descriptor for %s: %w", imageRef, err))
	}
	img, err := desc.Image()
	if err != nil {
		return errors.ClassifyRegistryError(fmt.Errorf("failed to get image from descriptor for %s: %w", imageRef, err))
	}
	reader := mutate.Extract(img)
	defer reader.Close()
	if err := untarLimited(reader, dest, extractLimits{maxTotal: maxImageExtractBytes, maxFile: maxImageFileBytes}); err != nil {
		return errors.ClassifyRegistryError(fmt.Errorf("failed to unpack %s: %w", imageRef, err))
	}
	return nil
}

func untarLimited(r io.Reader, dest string, limits extractLimits) error {
	if limits.maxTotal <= 0 {
		limits.maxTotal = maxImageExtractBytes
	}
	if limits.maxFile <= 0 {
		limits.maxFile = maxImageFileBytes
	}
	tr := tar.NewReader(r)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		target, err := safeExtractPath(dest, hdr.Name)
		if err != nil || target == dest {
			continue
		}
		base := filepath.Base(target)
		if strings.HasPrefix(base, ".wh.") {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if hdr.Size > limits.maxFile || total+hdr.Size > limits.maxTotal {
				return fmt.Errorf("image file %s exceeds the unpack limit", hdr.Name)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			written, err := writeExtractFile(target, io.LimitReader(tr, hdr.Size))
			if err != nil {
				return err
			}
			total += written
		case tar.TypeSymlink:
			if err := extractSymlink(dest, target, hdr.Linkname); err != nil {
				return err
			}
		case tar.TypeLink:
			if err := extractHardlink(dest, target, hdr.Linkname); err != nil {
				return err
			}
		}
	}
}

func writeExtractFile(target string, r io.Reader) (int64, error) {
	f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, err
	}
	n, copyErr := io.Copy(f, r)
	closeErr := f.Close()
	if copyErr != nil {
		return n, copyErr
	}
	return n, closeErr
}

func extractSymlink(dest, target, linkname string) error {
	if filepath.IsAbs(linkname) || strings.TrimSpace(linkname) == "" {
		return nil
	}
	resolved := filepath.Join(filepath.Dir(target), linkname)
	rel, err := filepath.Rel(dest, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	_ = os.Remove(target)
	return os.Symlink(linkname, target)
}

func extractHardlink(dest, target, linkname string) error {
	src, err := safeExtractPath(dest, linkname)
	if err != nil || src == dest {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	_ = os.Remove(target)
	if err := os.Link(src, target); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return nil
	}
	defer in.Close()
	_, err = writeExtractFile(target, in)
	return err
}

func safeExtractPath(dest, name string) (string, error) {
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("path %s escapes the image", name)
	}
	clean := pathCleanSlash(name)
	if clean == "" || clean == "." {
		return dest, nil
	}
	full := filepath.Join(dest, filepath.FromSlash(clean))
	rel, err := filepath.Rel(dest, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %s escapes the image", name)
	}
	return full, nil
}

func pathCleanSlash(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "/")
	return pathClean(name)
}

func pathClean(name string) string {
	return strings.TrimPrefix(filepath.ToSlash(filepath.Clean("/"+name)), "/")
}

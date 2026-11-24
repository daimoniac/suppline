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

// SkippedFilesManifest names the file, at the root of an unpacked image, that
// lists the regular files left out because of the size limits. Each line is
// "path<TAB>size<TAB>elf", where elf is 1 for an ELF file and 0 otherwise.
const SkippedFilesManifest = ".suppline-skipped"

const (
	maxImageExtractBytes = 512 << 20
	maxImageFileBytes    = 64 << 20
	// legacyTypeReg is the pre-ustar regular-file flag, formerly tar.TypeRegA.
	legacyTypeReg = '\x00'
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

// untarLimited writes r into dest. A file over the per-file limit, or one that
// would take the total past its limit, is left out and listed in
// SkippedFilesManifest, so one large binary does not lose the rest of the image.
func untarLimited(r io.Reader, dest string, limits extractLimits) error {
	if limits.maxTotal <= 0 {
		limits.maxTotal = maxImageExtractBytes
	}
	if limits.maxFile <= 0 {
		limits.maxFile = maxImageFileBytes
	}
	tr := tar.NewReader(r)
	var total int64
	var skipped []skippedFile
	skippedAt := map[string]int{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return writeSkipped(dest, skipped)
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
		rel := pathCleanSlash(hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, legacyTypeReg:
			if hdr.Size > limits.maxFile || total+hdr.Size > limits.maxTotal {
				var magic [4]byte
				n, _ := io.ReadFull(tr, magic[:])
				_ = os.Remove(target)
				skippedAt[rel] = len(skipped)
				skipped = append(skipped, skippedFile{Path: rel, Size: hdr.Size, ELF: isELFMagic(magic[:n])})
				continue
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
			if at, ok := skippedAt[pathCleanSlash(hdr.Linkname)]; ok {
				entry := skipped[at]
				entry.Path = rel
				skippedAt[rel] = len(skipped)
				skipped = append(skipped, entry)
				continue
			}
			if err := extractHardlink(dest, target, hdr.Linkname); err != nil {
				return err
			}
		}
	}
}

type skippedFile struct {
	Path string
	Size int64
	ELF  bool
}

func isELFMagic(b []byte) bool {
	return len(b) >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
}

func writeSkipped(dest string, files []skippedFile) error {
	if len(files) == 0 {
		return nil
	}
	var b strings.Builder
	for _, file := range files {
		elf := 0
		if file.ELF {
			elf = 1
		}
		name := strings.NewReplacer("\t", " ", "\n", " ").Replace(file.Path)
		fmt.Fprintf(&b, "%s\t%d\t%d\n", name, file.Size, elf)
	}
	return os.WriteFile(filepath.Join(dest, SkippedFilesManifest), []byte(b.String()), 0o644)
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

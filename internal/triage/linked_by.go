package triage

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// linkedPrefix marks a recorded library-linkage search in the grep ledger.
const linkedPrefix = "linked:"

// libraryName is a shared library name or soname prefix, such as
// libbrotlidec or libcurl.so.4.
var libraryName = regexp.MustCompile(`^lib[A-Za-z0-9_+.-]+$`)

// elfInfo is the dynamic linking view of one ELF file in the image.
type elfInfo struct {
	path   string
	soname string
	needed []string
	exe    bool
}

// linkedBy reports which ELF files in the image load library, directly
// (DT_NEEDED) or through other libraries. It also lists files that name the
// library without linking it (dlopen candidates), files that contain symbol
// (a static copy) when symbol is given, and native files too large to unpack,
// which it could not check.
func linkedBy(ctx context.Context, roots *Roots, pub *publicSource, job Job, library, symbol string) (string, error) {
	library = strings.TrimSpace(library)
	symbol = strings.TrimSpace(symbol)
	if !libraryName.MatchString(library) {
		return "", fmt.Errorf("library must be a shared library name such as libbrotlidec or libssl.so.3")
	}
	if roots == nil {
		return "", fmt.Errorf("image checkout is unavailable")
	}
	if err := roots.mountImage(ctx); err != nil {
		return "", err
	}
	root, err := roots.checkout(imageCheckoutName)
	if err != nil {
		return "", err
	}
	files, err := scanELF(root.Dir)
	if err != nil {
		return "", err
	}
	loaders, providers := linkClosure(files, library)

	var rows []string
	for _, f := range loaders {
		kind := "library"
		if f.info.exe {
			kind = "executable"
		}
		rows = append(rows, fmt.Sprintf("%s:1:%s loads %s via %s", f.info.path, kind, library, f.via))
	}
	mentions, static := nameAndSymbolHits(root.Dir, files, library, symbol, providers)
	for _, path := range mentions {
		rows = append(rows, fmt.Sprintf("%s:1:names %s without linking it (possible dlopen)", path, library))
	}
	for _, path := range static {
		rows = append(rows, fmt.Sprintf("%s:1:contains %s without linking %s (static copy)", path, symbol, library))
	}
	unchecked := 0
	for _, file := range readSkipped(root.Dir) {
		rows = append(rows, fmt.Sprintf("%s:1:not checked: file not unpacked, %d bytes", file.Path, file.Size))
		unchecked++
	}
	if len(rows) > maxToolMatches {
		rows = rows[:maxToolMatches]
	}

	// Nothing found is evidence only when every file in the image was checked.
	absence := unchecked == 0
	pattern := linkedPrefix + library
	if symbol != "" {
		pattern += "|" + symbol
	}
	id := pub.recordImageGrep(imageCheckoutName, pattern, ".", job.Digest, strings.Join(rows, "\n"), absence)
	if id == "" {
		return "", fmt.Errorf("linkage search was not recorded")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "grep_id: %s\nrepo: %s\ncommit: %s\nlibrary: %s\n", id, imageCheckoutName, strings.TrimSpace(job.Digest), library)
	if symbol != "" {
		fmt.Fprintf(&b, "symbol: %s\n", symbol)
	}
	fmt.Fprintf(&b, "elf_files: %d\nproviders: %s\nloaders: %d\nnot_checked: %d\n%s\n",
		len(files), strings.Join(providers, ", "), len(loaders), unchecked, cite(len(loaders)+len(mentions)+len(static) == 0, absence).line())
	b.WriteString("note: dynamic linking only; a program can still load a library by a path it builds at run time\n")
	for _, row := range rows {
		b.WriteString(row)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// scanELF reads the dynamic section of every ELF file under dir.
func scanELF(dir string) ([]elfInfo, error) {
	var files []elfInfo
	err := filepath.WalkDir(dir, func(full string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(dir, full)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if imageMarker(rel) || !elfFile(full) {
			return nil
		}
		ef, err := elf.Open(full)
		if err != nil {
			return nil
		}
		defer ef.Close()
		info := elfInfo{path: rel, soname: filepath.Base(rel)}
		info.needed, _ = ef.ImportedLibraries()
		if names, err := ef.DynString(elf.DT_SONAME); err == nil && len(names) > 0 {
			info.soname = names[0]
		}
		info.exe = ef.Type == elf.ET_EXEC || (ef.Type == elf.ET_DYN && ef.Section(".interp") != nil)
		files = append(files, info)
		return nil
	})
	return files, err
}

type loader struct {
	info elfInfo
	via  string
}

// linkClosure returns the files that load library through DT_NEEDED, each
// with the dependency it reaches library through, and the sonames that
// provide library.
func linkClosure(files []elfInfo, library string) ([]loader, []string) {
	isProvider := func(f elfInfo) bool {
		return strings.HasPrefix(f.soname, library) || strings.HasPrefix(filepath.Base(f.path), library)
	}
	reach := map[string]bool{} // sonames that are, or load, library
	var providers []string
	for _, f := range files {
		if isProvider(f) && !reach[f.soname] {
			reach[f.soname] = true
			providers = append(providers, f.soname)
		}
	}
	via := map[string]string{}
	for changed := true; changed; {
		changed = false
		for _, f := range files {
			if _, done := via[f.path]; done || isProvider(f) {
				continue
			}
			for _, need := range f.needed {
				if reach[need] || strings.HasPrefix(need, library) {
					via[f.path] = need
					reach[f.soname] = true
					changed = true
					break
				}
			}
		}
	}
	var out []loader
	for _, f := range files {
		if need, ok := via[f.path]; ok {
			out = append(out, loader{info: f, via: need})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].info.path < out[j].info.path })
	sort.Strings(providers)
	return out, providers
}

// nameAndSymbolHits lists ELF files that contain library's name or symbol
// without linking library. The providers themselves are left out.
func nameAndSymbolHits(dir string, files []elfInfo, library, symbol string, providers []string) (mentions, static []string) {
	provider := map[string]bool{}
	for _, p := range providers {
		provider[p] = true
	}
	name := []byte(library + ".so")
	sym := []byte(symbol)
	for _, f := range files {
		if provider[f.soname] || linksDirectly(f, library) {
			continue
		}
		hasName, hasSymbol := fileContains(filepath.Join(dir, filepath.FromSlash(f.path)), name, sym)
		if hasName {
			mentions = append(mentions, f.path)
		}
		if symbol != "" && hasSymbol {
			static = append(static, f.path)
		}
	}
	sort.Strings(mentions)
	sort.Strings(static)
	return mentions, static
}

func linksDirectly(f elfInfo, library string) bool {
	for _, need := range f.needed {
		if strings.HasPrefix(need, library) {
			return true
		}
	}
	return false
}

// fileContains reports whether the file holds name and sym, reading it in
// overlapping chunks so large binaries are not loaded at once. An empty sym
// is never found.
func fileContains(path string, name, sym []byte) (bool, bool) {
	file, err := os.Open(path)
	if err != nil {
		return false, false
	}
	defer file.Close()
	overlap := max(len(name), len(sym))
	buf := make([]byte, 1<<20+overlap)
	var foundName, foundSym bool
	carry := 0
	for !foundName || (len(sym) > 0 && !foundSym) {
		n, err := io.ReadFull(file, buf[carry:])
		chunk := buf[:carry+n]
		if !foundName && bytes.Contains(chunk, name) {
			foundName = true
		}
		if len(sym) > 0 && !foundSym && bytes.Contains(chunk, sym) {
			foundSym = true
		}
		if err != nil {
			break
		}
		carry = min(overlap, len(chunk))
		copy(buf, chunk[len(chunk)-carry:])
	}
	return foundName, foundSym
}

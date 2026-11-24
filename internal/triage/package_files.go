package triage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// packagePrefix marks a recorded package-database read in the grep ledger.
const packagePrefix = "package:"

const (
	apkInstalled = "lib/apk/db/installed"
	dpkgInfoDir  = "var/lib/dpkg/info"
	// maxPackageRows caps what the model sees. The ledger keeps every row.
	maxPackageRows = 200
)

// packageFiles reads the files one installed package owns from the scanned
// image's package database. The rows are real lines of that database, so a
// verdict can cite them: they show what the package the scanner matched
// actually ships.
func packageFiles(ctx context.Context, roots *Roots, pub *publicSource, job Job, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("package is required")
	}
	if strings.ContainsAny(name, "/\\\n\t*?[") || strings.Contains(name, "..") {
		return "", fmt.Errorf("package name is not allowed")
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
	db, rows, err := readPackageFiles(root.Dir, name)
	if err != nil {
		return "", err
	}
	id := pub.recordImageGrep(imageCheckoutName, packagePrefix+name, db, job.Digest, strings.Join(rows, "\n"), false)
	if id == "" {
		return "", fmt.Errorf("package read was not recorded")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "grep_id: %s\nrepo: %s\ncommit: %s\npackage: %s\ndatabase: %s\nrows: %d\ncomplete: %t\n%s\n",
		id, imageCheckoutName, strings.TrimSpace(job.Digest), name, db, len(rows), len(rows) <= maxPackageRows, cite(len(rows) == 0, false).line())
	shown := rows
	if len(shown) > maxPackageRows {
		shown = shown[:maxPackageRows]
	}
	for _, row := range shown {
		b.WriteString(row)
		b.WriteByte('\n')
	}
	if len(rows) == 0 {
		fmt.Fprintf(&b, "package %s is not in %s\n", name, db)
	}
	return b.String(), nil
}

// readPackageFiles returns the database path and its rows as "path:line:text".
func readPackageFiles(dir, name string) (string, []string, error) {
	if raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(apkInstalled))); err == nil {
		return apkInstalled, apkPackageRows(string(raw), name), nil
	}
	for _, candidate := range dpkgListFiles(dir, name) {
		raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(candidate)))
		if err != nil {
			continue
		}
		var rows []string
		for i, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			rows = append(rows, fmt.Sprintf("%s:%d:%s", candidate, i+1, line))
		}
		return candidate, rows, nil
	}
	if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(dpkgInfoDir))); err == nil {
		return dpkgInfoDir + "/" + name + ".list", nil, nil
	}
	return "", nil, fmt.Errorf("image has no apk or dpkg package database; rpm is not supported")
}

// apkPackageRows returns the lines of the package's record: name, version,
// and the F: directory and R: file lines that list what it installs.
func apkPackageRows(db, name string) []string {
	var rows []string
	var record []string
	inPackage := false
	flush := func() {
		if inPackage {
			rows = append(rows, record...)
		}
		record = nil
		inPackage = false
	}
	for i, line := range strings.Split(db, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line == "P:"+name {
			inPackage = true
		}
		switch {
		case strings.HasPrefix(line, "P:"), strings.HasPrefix(line, "V:"), strings.HasPrefix(line, "o:"),
			strings.HasPrefix(line, "F:"), strings.HasPrefix(line, "R:"):
			record = append(record, fmt.Sprintf("%s:%d:%s", apkInstalled, i+1, line))
		}
	}
	flush()
	return rows
}

func dpkgListFiles(dir, name string) []string {
	out := []string{dpkgInfoDir + "/" + name + ".list"}
	matches, _ := filepath.Glob(filepath.Join(dir, filepath.FromSlash(dpkgInfoDir), name+":*.list"))
	for _, match := range matches {
		rel, err := filepath.Rel(dir, match)
		if err == nil {
			out = append(out, filepath.ToSlash(rel))
		}
	}
	return out
}

package triage

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// rpmFixture is a tiny rpm SQLite database. TestWriteRPMSQLiteFixture writes
// it with the sqlite3 command line tool from headers rpmTestHeader builds, so
// no real package data is committed. It uses 512-byte pages so that its
// Packages table needs interior b-tree pages and its openssl-libs headers need
// overflow pages, which a database from a real image has too.
const rpmFixture = "testdata/rpmdb.sqlite"

// rpmFixtureFiles is how many files each openssl-libs header in the fixture lists.
const rpmFixtureFiles = 60

type rpmTestTag struct {
	tag, typ uint32
	value    any // string, []string or []int32
}

// rpmTestHeader encodes tags the way rpm stores a header in its database.
func rpmTestHeader(tags ...rpmTestTag) []byte {
	var index, data []byte
	for _, t := range tags {
		var count uint32
		switch v := t.value.(type) {
		case string:
			count = 1
			index = binary.BigEndian.AppendUint32(index, t.tag)
			index = binary.BigEndian.AppendUint32(index, t.typ)
			index = binary.BigEndian.AppendUint32(index, uint32(len(data)))
			data = append(append(data, v...), 0)
		case []string:
			count = uint32(len(v))
			index = binary.BigEndian.AppendUint32(index, t.tag)
			index = binary.BigEndian.AppendUint32(index, t.typ)
			index = binary.BigEndian.AppendUint32(index, uint32(len(data)))
			for _, s := range v {
				data = append(append(data, s...), 0)
			}
		case []int32:
			for len(data)%4 != 0 {
				data = append(data, 0)
			}
			count = uint32(len(v))
			index = binary.BigEndian.AppendUint32(index, t.tag)
			index = binary.BigEndian.AppendUint32(index, t.typ)
			index = binary.BigEndian.AppendUint32(index, uint32(len(data)))
			for _, n := range v {
				data = binary.BigEndian.AppendUint32(data, uint32(n))
			}
		}
		index = binary.BigEndian.AppendUint32(index, count)
	}
	blob := binary.BigEndian.AppendUint32(nil, uint32(len(tags)))
	blob = binary.BigEndian.AppendUint32(blob, uint32(len(data)))
	return append(append(blob, index...), data...)
}

// rpmTestPackage builds a header with rpm 4's split file list.
func rpmTestPackage(name, version, release, arch string, epoch int32, files []string) []byte {
	var dirs, bases []string
	var indexes []int32
	seen := map[string]int32{}
	for _, f := range files {
		dir, base := path.Dir(f)+"/", path.Base(f)
		idx, ok := seen[dir]
		if !ok {
			idx = int32(len(dirs))
			seen[dir] = idx
			dirs = append(dirs, dir)
		}
		bases = append(bases, base)
		indexes = append(indexes, idx)
	}
	tags := []rpmTestTag{
		{rpmTagName, rpmTypeString, name},
		{rpmTagVersion, rpmTypeString, version},
		{rpmTagRelease, rpmTypeString, release},
		{rpmTagArch, rpmTypeString, arch},
	}
	if epoch != 0 {
		tags = append(tags, rpmTestTag{rpmTagEpoch, rpmTypeInt32, []int32{epoch}})
	}
	if len(files) > 0 {
		tags = append(tags,
			rpmTestTag{rpmTagDirIndexes, rpmTypeInt32, indexes},
			rpmTestTag{rpmTagBasenames, rpmTypeStringArray, bases},
			rpmTestTag{rpmTagDirNames, rpmTypeStringArray, dirs},
		)
	}
	return rpmTestHeader(tags...)
}

func opensslFiles(libdir string) []string {
	files := []string{libdir + "/libcrypto.so.3", libdir + "/libssl.so.3", "/etc/pki/tls/openssl.cnf"}
	for i := len(files); i < rpmFixtureFiles; i++ {
		files = append(files, fmt.Sprintf("%s/engines-3/module-%02d.so", libdir, i))
	}
	return files
}

// TestWriteRPMSQLiteFixture regenerates testdata/rpmdb.sqlite. It runs only
// with SUPPLINE_WRITE_RPM_FIXTURE=1 and needs the sqlite3 tool on PATH.
func TestWriteRPMSQLiteFixture(t *testing.T) {
	if os.Getenv("SUPPLINE_WRITE_RPM_FIXTURE") != "1" {
		t.Skip("set SUPPLINE_WRITE_RPM_FIXTURE=1 to regenerate " + rpmFixture)
	}
	var sql strings.Builder
	sql.WriteString("PRAGMA page_size=512;\n")
	// The Packages table as rpm's sqlite backend creates it.
	sql.WriteString("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL);\n")
	sql.WriteString("CREATE TABLE Name (key TEXT NOT NULL, hnum INTEGER NOT NULL, idx INTEGER NOT NULL, FOREIGN KEY (hnum) REFERENCES Packages (hnum));\n")
	insert := func(blob []byte) {
		fmt.Fprintf(&sql, "INSERT INTO Packages (blob) VALUES (x'%s');\n", hex.EncodeToString(blob))
	}
	// A public key pseudo-package lists no files.
	insert(rpmTestPackage("gpg-pubkey", "fd431d51", "4ae0493b", "", 0, nil))
	for i := range 20 {
		insert(rpmTestPackage(fmt.Sprintf("filler-%02d", i), "1.0", "1.el9", "noarch", 0,
			[]string{fmt.Sprintf("/usr/share/filler-%02d/README", i)}))
	}
	insert(rpmTestPackage("openssl-libs", "3.0.7", "27.el9", "x86_64", 1, opensslFiles("/usr/lib64")))
	insert(rpmTestPackage("openssl-libs", "3.0.7", "27.el9", "i686", 1, opensslFiles("/usr/lib")))
	insert(rpmTestPackage("openssl", "3.0.7", "27.el9", "x86_64", 1, []string{"/usr/bin/openssl"}))
	sql.WriteString("INSERT INTO Name (key, hnum, idx) SELECT 'x', hnum, 0 FROM Packages;\nVACUUM;\n")

	out := filepath.Join("testdata", "rpmdb.sqlite")
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(out)
	cmd := exec.Command("sqlite3", out)
	cmd.Stdin = strings.NewReader(sql.String())
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sqlite3: %v\n%s", err, msg)
	}
}

func rpmImage(t *testing.T, digest, dbPath string) *Roots {
	t.Helper()
	cache := filepath.Join(os.TempDir(), "suppline-image", sanitizeDigest(digest))
	if err := os.RemoveAll(cache); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cache) })
	src := t.TempDir()
	raw, err := os.ReadFile(rpmFixture)
	if err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(src, filepath.FromSlash(dbPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return &Roots{Image: newImageFS(&copyUnpacker{src: src}, "crunchydata/crunchy-postgres", digest)}
}

func TestPackageFilesReadsRPMSQLite(t *testing.T) {
	roots := rpmImage(t, "sha256:rpm1", "var/lib/rpm/rpmdb.sqlite")
	pub := newPublicSource()
	job := Job{CVEID: "CVE-2026-91404", PackageName: "openssl-libs", Digest: "sha256:rpm1"}
	pub.setPhase(job.CVEID)
	out, err := packageFiles(context.Background(), roots, pub, job, job.PackageName)
	if err != nil {
		t.Fatal(err)
	}
	const db = "var/lib/rpm/rpmdb.sqlite"
	wantRows := 2 * (3 + rpmFixtureFiles)
	for _, want := range []string{
		"database: " + db,
		fmt.Sprintf("rows: %d", wantRows),
		"citable: rows",
		db + ":1:Name: openssl-libs",
		db + ":2:Version: 1:3.0.7-27.el9",
		db + ":3:Arch: x86_64",
		db + ":4:/usr/lib64/libcrypto.so.3",
		db + ":5:/usr/lib64/libssl.so.3",
		fmt.Sprintf("%s:%d:/usr/lib64/engines-3/module-%02d.so", db, 3+rpmFixtureFiles, rpmFixtureFiles-1),
		fmt.Sprintf("%s:%d:Arch: i686", db, 6+rpmFixtureFiles),
		fmt.Sprintf("%s:%d:/usr/lib/libssl.so.3", db, 8+rpmFixtureFiles),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "/usr/bin/openssl") || strings.Contains(out, "filler") {
		t.Errorf("output includes another package:\n%s", out)
	}
	verdict := modelVerdict{Verdict: "not_affected", Justification: "code_not_reachable", Evidence: []modelEvidence{{GrepID: "g1"}}}
	if err := verifyEvidence(*roots, pub, job, &verdict); err != nil || len(verdict.Evidence) != wantRows {
		t.Fatalf("rpm package rows as evidence: %v (%d rows)", err, len(verdict.Evidence))
	}
	if got := verdict.Evidence[0]; got.Repo != imageCheckoutName || got.Path != db || got.Line != 1 || got.Quote != "Name: openssl-libs" {
		t.Fatalf("recorded evidence %+v", got)
	}

	missing, err := packageFiles(context.Background(), roots, pub, job, "openssl-devel")
	if err != nil || !strings.Contains(missing, "citable: no") || !strings.Contains(missing, "package openssl-devel is not in "+db) {
		t.Fatalf("absent package: %v\n%s", err, missing)
	}
	keys, err := packageFiles(context.Background(), roots, pub, job, "gpg-pubkey")
	if err != nil || !strings.Contains(keys, "rows: 2") || !strings.Contains(keys, db+":2:Version: fd431d51-4ae0493b") || strings.Contains(keys, "Arch:") {
		t.Fatalf("package without files or arch: %v\n%s", err, keys)
	}
}

func TestRecheckEvidenceReplaysRPMPackageRows(t *testing.T) {
	roots := rpmImage(t, "sha256:rpm2", "var/lib/rpm/rpmdb.sqlite")
	pub := newPublicSource()
	job := Job{CVEID: "CVE-1", PackageName: "openssl-libs", Digest: "sha256:rpm2"}
	pub.setPhase(job.CVEID)
	tools := &toolbox{roots: roots, pub: pub}
	var b strings.Builder
	out, err := tools.replay(context.Background(), checkouts{}, job, modelEvidence{
		Repo: imageCheckoutName, Path: "var/lib/rpm/rpmdb.sqlite", Pattern: packagePrefix + "openssl-libs",
	}, &b)
	if err != nil || !strings.Contains(b.String(), "package files of openssl-libs") || !strings.Contains(out, "var/lib/rpm/rpmdb.sqlite:4:/usr/lib64/libcrypto.so.3") {
		t.Fatalf("replay: %v\n%s%s", err, b.String(), out)
	}
}

func TestReadPackageFilesFindsRPMUnderSysimage(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(rpmFixture)
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "usr", "lib", "sysimage", "rpm")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "rpmdb.sqlite"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	db, rows, err := readPackageFiles(dir, "openssl")
	if err != nil || db != "usr/lib/sysimage/rpm/rpmdb.sqlite" || len(rows) != 4 || rows[3] != db+":4:/usr/bin/openssl" {
		t.Fatalf("db %q rows %v err %v", db, rows, err)
	}

	// Fedora links var/lib/rpm to the sysimage directory.
	if err := os.MkdirAll(filepath.Join(dir, "var", "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../usr/lib/sysimage/rpm", filepath.Join(dir, "var", "lib", "rpm")); err != nil {
		t.Fatal(err)
	}
	if db, rows, err := readPackageFiles(dir, "openssl"); err != nil || db != "var/lib/rpm/rpmdb.sqlite" || len(rows) != 4 {
		t.Fatalf("through the symlink: db %q rows %v err %v", db, rows, err)
	}
}

func TestReadPackageFilesRPMErrors(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := readPackageFiles(dir, "openssl"); err == nil || err.Error() != "image has no apk, dpkg, or rpm package database" {
		t.Fatalf("no database: %v", err)
	}

	rpmDir := filepath.Join(dir, "var", "lib", "rpm")
	if err := os.MkdirAll(rpmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(rpmFixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rpmDir, "rpmdb.sqlite"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rpmDir, "rpmdb.sqlite-wal"), []byte("pending"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPackageFiles(dir, "openssl"); err == nil || !strings.Contains(err.Error(), "write-ahead log") {
		t.Fatalf("pending write-ahead log: %v", err)
	}

	if err := os.WriteFile(filepath.Join(rpmDir, "rpmdb.sqlite"), []byte("not a database"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(rpmDir, "rpmdb.sqlite-wal")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readPackageFiles(dir, "openssl"); err == nil || !strings.Contains(err.Error(), "var/lib/rpm/rpmdb.sqlite") {
		t.Fatalf("corrupt database: %v", err)
	}
}

// Image data is untrusted: a damaged database or header must fail, not panic.
func TestRPMReadersRejectDamagedInput(t *testing.T) {
	raw, err := os.ReadFile(rpmFixture)
	if err != nil {
		t.Fatal(err)
	}
	read := func(data []byte) {
		db, err := parseSQLite(data)
		if err != nil {
			return
		}
		_, _ = rpmRowsFrom(db, rpmFixture, "openssl-libs")
	}
	for cut := 0; cut < len(raw); cut += 97 {
		read(raw[:cut])
	}
	for i := 0; i < len(raw); i += 13 {
		damaged := append([]byte(nil), raw...)
		damaged[i] ^= 0xa5
		read(damaged)
	}

	header := rpmTestPackage("openssl-libs", "3.0.7", "27.el9", "x86_64", 1, opensslFiles("/usr/lib64"))
	if h, err := parseRPMHeader(header); err != nil || len(h.files) != rpmFixtureFiles || h.evr() != "1:3.0.7-27.el9" {
		t.Fatalf("intact header: %+v %v", h, err)
	}
	for cut := 0; cut < len(header); cut++ {
		_, _ = parseRPMHeader(header[:cut])
	}
	for i := 0; i < len(header); i++ {
		damaged := append([]byte(nil), header...)
		damaged[i] ^= 0xff
		_, _ = parseRPMHeader(damaged)
	}
	badIndex := rpmTestHeader(
		rpmTestTag{rpmTagName, rpmTypeString, "x"},
		rpmTestTag{rpmTagDirIndexes, rpmTypeInt32, []int32{3}},
		rpmTestTag{rpmTagBasenames, rpmTypeStringArray, []string{"a"}},
		rpmTestTag{rpmTagDirNames, rpmTypeStringArray, []string{"/"}},
	)
	if _, err := parseRPMHeader(badIndex); err == nil {
		t.Fatal("accepted a dir index past the dir names")
	}
}

func TestParseRPMHeaderOldFilenames(t *testing.T) {
	h, err := parseRPMHeader(rpmTestHeader(
		rpmTestTag{rpmTagName, rpmTypeString, "old"},
		rpmTestTag{rpmTagVersion, rpmTypeString, "1"},
		rpmTestTag{rpmTagOldFilename, rpmTypeStringArray, []string{"/bin/old", "/etc/old.conf"}},
	))
	if err != nil || h.name != "old" || h.evr() != "1" || strings.Join(h.files, ",") != "/bin/old,/etc/old.conf" {
		t.Fatalf("%+v %v", h, err)
	}
}

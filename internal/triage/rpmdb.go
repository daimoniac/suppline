package triage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/knqyf263/go-rpmdb/pkg/bdb"
	dbi "github.com/knqyf263/go-rpmdb/pkg/db"
	"github.com/knqyf263/go-rpmdb/pkg/ndb"
)

// rpmDatabases lists where an image keeps its rpm database, newest format
// first: SQLite (RHEL/UBI 9, Fedora 33+, Amazon Linux 2023), ndb (SUSE), and
// BerkeleyDB (RHEL/UBI 8, CentOS 7, Amazon Linux 2). Fedora and SUSE keep the
// real files under usr/lib/sysimage/rpm.
var rpmDatabases = []struct {
	path string
	open func(string) (dbi.RpmDBInterface, error)
}{
	{"var/lib/rpm/rpmdb.sqlite", openRPMSQLite},
	{"usr/lib/sysimage/rpm/rpmdb.sqlite", openRPMSQLite},
	{"var/lib/rpm/Packages.db", func(p string) (dbi.RpmDBInterface, error) { return ndb.Open(p) }},
	{"usr/lib/sysimage/rpm/Packages.db", func(p string) (dbi.RpmDBInterface, error) { return ndb.Open(p) }},
	{"var/lib/rpm/Packages", func(p string) (dbi.RpmDBInterface, error) { return bdb.Open(p) }},
	{"usr/lib/sysimage/rpm/Packages", func(p string) (dbi.RpmDBInterface, error) { return bdb.Open(p) }},
}

// errNoRPMDatabase means the image has none of the rpmDatabases.
var errNoRPMDatabase = errors.New("no rpm database")

// rpmPackageRows reads the image's rpm database and returns its path and the
// rows of every installed package called name: its name, version and arch,
// then each file it installs. The row numbers count the rows of that record;
// the text is decoded from the rpm header, not a line of the database file.
func rpmPackageRows(dir, name string) (string, []string, error) {
	for _, candidate := range rpmDatabases {
		full, err := safePath(dir, candidate.path)
		if err != nil {
			continue
		}
		if info, err := os.Stat(full); err != nil || !info.Mode().IsRegular() {
			continue
		}
		db, err := candidate.open(full)
		if err != nil {
			return "", nil, fmt.Errorf("open rpm database %s: %w", candidate.path, err)
		}
		rows, err := rpmRowsFrom(db, candidate.path, name)
		if closeErr := db.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if err != nil {
			return "", nil, fmt.Errorf("read rpm database %s: %w", candidate.path, err)
		}
		return candidate.path, rows, nil
	}
	return "", nil, errNoRPMDatabase
}

func rpmRowsFrom(db dbi.RpmDBInterface, dbPath, name string) ([]string, error) {
	var rows []string
	var firstErr error
	// Drain the channel even after an error so the reader goroutine ends.
	for entry := range db.Read() {
		if firstErr != nil {
			continue
		}
		if entry.Err != nil {
			firstErr = entry.Err
			continue
		}
		hdr, err := parseRPMHeader(entry.Value)
		if err != nil {
			firstErr = err
			continue
		}
		if hdr.name != name {
			continue
		}
		add := func(text string) {
			rows = append(rows, fmt.Sprintf("%s:%d:%s", dbPath, len(rows)+1, text))
		}
		add("Name: " + hdr.name)
		add("Version: " + hdr.evr())
		if hdr.arch != "" {
			add("Arch: " + hdr.arch)
		}
		for _, file := range hdr.files {
			add(file)
		}
	}
	return rows, firstErr
}

// rpm header tags and types, from rpm's rpmtag.h.
const (
	rpmTagName        = 1000
	rpmTagVersion     = 1001
	rpmTagRelease     = 1002
	rpmTagEpoch       = 1003
	rpmTagArch        = 1022
	rpmTagOldFilename = 1027
	rpmTagDirIndexes  = 1116
	rpmTagBasenames   = 1117
	rpmTagDirNames    = 1118

	rpmTypeInt32       = 4
	rpmTypeString      = 6
	rpmTypeStringArray = 8
	rpmTypeI18NString  = 9
)

type rpmHeader struct {
	name, version, release, arch string
	epoch                        int32
	hasEpoch                     bool
	files                        []string
}

func (h rpmHeader) evr() string {
	v := h.version
	if h.release != "" {
		v += "-" + h.release
	}
	if h.hasEpoch && h.epoch != 0 {
		v = fmt.Sprintf("%d:%s", h.epoch, v)
	}
	return v
}

// parseRPMHeader decodes the header blob rpm stores per package: an index
// count and data length, then 16-byte index entries (tag, type, offset,
// count, big endian), then the data they point into.
func parseRPMHeader(blob []byte) (rpmHeader, error) {
	var h rpmHeader
	if len(blob) < 8 {
		return h, fmt.Errorf("rpm header is truncated")
	}
	il := binary.BigEndian.Uint32(blob[0:4])
	dl := binary.BigEndian.Uint32(blob[4:8])
	indexEnd := 8 + uint64(il)*16
	if indexEnd+uint64(dl) > uint64(len(blob)) {
		return h, fmt.Errorf("rpm header index or data overruns the blob")
	}
	data := blob[indexEnd : indexEnd+uint64(dl)]
	type entry struct{ typ, offset, count uint32 }
	entries := map[uint32]entry{}
	for i := uint64(0); i < uint64(il); i++ {
		raw := blob[8+i*16 : 8+i*16+16]
		tag := binary.BigEndian.Uint32(raw[0:4])
		if _, seen := entries[tag]; seen {
			continue
		}
		entries[tag] = entry{
			typ:    binary.BigEndian.Uint32(raw[4:8]),
			offset: binary.BigEndian.Uint32(raw[8:12]),
			count:  binary.BigEndian.Uint32(raw[12:16]),
		}
	}
	strs := func(tag uint32) ([]string, error) {
		e, ok := entries[tag]
		if !ok {
			return nil, nil
		}
		if e.typ != rpmTypeString && e.typ != rpmTypeStringArray && e.typ != rpmTypeI18NString {
			return nil, fmt.Errorf("rpm tag %d has type %d, want a string", tag, e.typ)
		}
		if e.typ == rpmTypeString {
			e.count = 1
		}
		if uint64(e.count) > uint64(len(data)) {
			return nil, fmt.Errorf("rpm tag %d count overruns the data", tag)
		}
		out := make([]string, 0, e.count)
		pos := uint64(e.offset)
		for range e.count {
			if pos > uint64(len(data)) {
				return nil, fmt.Errorf("rpm tag %d overruns the data", tag)
			}
			end := bytes.IndexByte(data[pos:], 0)
			if end < 0 {
				return nil, fmt.Errorf("rpm tag %d has an unterminated string", tag)
			}
			out = append(out, string(data[pos:pos+uint64(end)]))
			pos += uint64(end) + 1
		}
		return out, nil
	}
	str := func(tag uint32) (string, error) {
		v, err := strs(tag)
		if err != nil || len(v) == 0 {
			return "", err
		}
		return v[0], nil
	}
	ints := func(tag uint32) ([]int32, error) {
		e, ok := entries[tag]
		if !ok {
			return nil, nil
		}
		if e.typ != rpmTypeInt32 {
			return nil, fmt.Errorf("rpm tag %d has type %d, want int32", tag, e.typ)
		}
		if uint64(e.offset)+uint64(e.count)*4 > uint64(len(data)) {
			return nil, fmt.Errorf("rpm tag %d overruns the data", tag)
		}
		out := make([]int32, e.count)
		for i := range out {
			out[i] = int32(binary.BigEndian.Uint32(data[e.offset+uint32(i)*4:])) //nolint:gosec // rpm stores signed int32
		}
		return out, nil
	}

	var err error
	if h.name, err = str(rpmTagName); err != nil {
		return h, err
	}
	if h.version, err = str(rpmTagVersion); err != nil {
		return h, err
	}
	if h.release, err = str(rpmTagRelease); err != nil {
		return h, err
	}
	if h.arch, err = str(rpmTagArch); err != nil {
		return h, err
	}
	epoch, err := ints(rpmTagEpoch)
	if err != nil {
		return h, err
	}
	if len(epoch) > 0 {
		h.epoch, h.hasEpoch = epoch[0], true
	}

	basenames, err := strs(rpmTagBasenames)
	if err != nil {
		return h, err
	}
	if len(basenames) == 0 {
		// Packages built before rpm 4 list whole paths.
		h.files, err = strs(rpmTagOldFilename)
		return h, err
	}
	dirnames, err := strs(rpmTagDirNames)
	if err != nil {
		return h, err
	}
	dirindexes, err := ints(rpmTagDirIndexes)
	if err != nil {
		return h, err
	}
	if len(dirindexes) != len(basenames) {
		return h, fmt.Errorf("rpm header has %d basenames but %d dir indexes", len(basenames), len(dirindexes))
	}
	h.files = make([]string, len(basenames))
	for i, base := range basenames {
		idx := dirindexes[i]
		if idx < 0 || int(idx) >= len(dirnames) {
			return h, fmt.Errorf("rpm dir index %d is out of range", idx)
		}
		h.files[i] = path.Join(dirnames[idx], base)
	}
	return h, nil
}

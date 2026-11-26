package triage

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	dbi "github.com/knqyf263/go-rpmdb/pkg/db"
)

// This file reads the Packages table of an rpm SQLite database without a
// SQLite engine. rpm creates the table as
//
//	CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)
//
// so each row of its table b-tree is a record whose second column is the
// package header. The format is documented at https://www.sqlite.org/fileformat.html.
// The reader only reads: it never writes a journal or shared-memory file next
// to the image's database, which a SQLite engine opening it would.

const (
	sqliteMagic = "SQLite format 3\x00"
	// maxRPMSQLiteBytes bounds what is read into memory. The image unpack
	// already leaves out files over 64 MiB.
	maxRPMSQLiteBytes = 256 << 20
	// maxSQLiteDepth bounds b-tree recursion on a corrupt file.
	maxSQLiteDepth = 32
)

type rpmSQLite struct {
	data     []byte
	pageSize int
	usable   int
}

func openRPMSQLite(path string) (dbi.RpmDBInterface, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxRPMSQLiteBytes {
		return nil, fmt.Errorf("sqlite file is %d bytes, over the %d byte limit", info.Size(), maxRPMSQLiteBytes)
	}
	if wal, err := os.Stat(path + "-wal"); err == nil && wal.Size() > 0 {
		return nil, fmt.Errorf("sqlite file has an uncheckpointed write-ahead log, which this reader does not apply")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseSQLite(data)
}

func parseSQLite(data []byte) (*rpmSQLite, error) {
	if len(data) < 100 || string(data[:16]) != sqliteMagic {
		return nil, fmt.Errorf("not a sqlite file")
	}
	pageSize := int(binary.BigEndian.Uint16(data[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("sqlite page size %d is invalid", pageSize)
	}
	usable := pageSize - int(data[20])
	if usable < 480 {
		return nil, fmt.Errorf("sqlite usable page size %d is invalid", usable)
	}
	return &rpmSQLite{data: data, pageSize: pageSize, usable: usable}, nil
}

func (s *rpmSQLite) Close() error { return nil }

// Read sends the header blob of every row of the Packages table.
func (s *rpmSQLite) Read() <-chan dbi.Entry {
	out := make(chan dbi.Entry)
	go func() {
		defer close(out)
		root, err := s.tableRoot("Packages")
		if err != nil {
			out <- dbi.Entry{Err: err}
			return
		}
		err = s.walkTable(root, func(payload []byte) error {
			cols, err := sqliteRecord(payload)
			if err != nil {
				return err
			}
			if len(cols) < 2 || cols[1].kind != sqliteBlob {
				return fmt.Errorf("a row of the Packages table has no blob column")
			}
			out <- dbi.Entry{Value: cols[1].raw}
			return nil
		})
		if err != nil {
			out <- dbi.Entry{Err: err}
		}
	}()
	return out
}

// tableRoot finds a table's root page in sqlite_schema, the table on page 1
// with columns type, name, tbl_name, rootpage, sql.
func (s *rpmSQLite) tableRoot(name string) (uint32, error) {
	var root uint32
	err := s.walkTable(1, func(payload []byte) error {
		cols, err := sqliteRecord(payload)
		if err != nil || len(cols) < 4 {
			return err
		}
		if string(cols[0].raw) == "table" && strings.EqualFold(string(cols[1].raw), name) && cols[3].kind == sqliteInt && root == 0 {
			if cols[3].num <= 0 || cols[3].num > int64(len(s.data)/s.pageSize) {
				return fmt.Errorf("table %s has invalid root page %d", name, cols[3].num)
			}
			root = uint32(cols[3].num)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if root == 0 {
		return 0, fmt.Errorf("sqlite file has no %s table", name)
	}
	return root, nil
}

func (s *rpmSQLite) page(n uint32) ([]byte, error) {
	start := int64(n-1) * int64(s.pageSize)
	if n == 0 || start+int64(s.pageSize) > int64(len(s.data)) {
		return nil, fmt.Errorf("sqlite page %d is out of range", n)
	}
	return s.data[start : start+int64(s.pageSize)], nil
}

// walkTable calls fn with the payload of each row of a table b-tree, in rowid
// order.
func (s *rpmSQLite) walkTable(root uint32, fn func([]byte) error) error {
	return s.walkPage(root, 0, map[uint32]bool{}, fn)
}

func (s *rpmSQLite) walkPage(n uint32, depth int, visited map[uint32]bool, fn func([]byte) error) error {
	if depth > maxSQLiteDepth {
		return fmt.Errorf("sqlite b-tree is deeper than %d", maxSQLiteDepth)
	}
	if visited[n] {
		return fmt.Errorf("sqlite page %d is linked twice", n)
	}
	visited[n] = true
	page, err := s.page(n)
	if err != nil {
		return err
	}
	hdr := 0
	if n == 1 {
		hdr = 100
	}
	if hdr+12 > len(page) {
		return fmt.Errorf("sqlite page %d is truncated", n)
	}
	kind := page[hdr]
	cells := int(binary.BigEndian.Uint16(page[hdr+3 : hdr+5]))
	ptrs := hdr + 8
	if kind == 0x05 {
		ptrs = hdr + 12
	}
	if ptrs+2*cells > len(page) {
		return fmt.Errorf("sqlite page %d has too many cells", n)
	}
	for i := range cells {
		off := int(binary.BigEndian.Uint16(page[ptrs+2*i:]))
		if off >= s.usable {
			return fmt.Errorf("sqlite page %d cell %d is out of range", n, i)
		}
		switch kind {
		case 0x05: // interior table page: left child, rowid
			if off+4 > s.usable {
				return fmt.Errorf("sqlite page %d cell %d is truncated", n, i)
			}
			if err := s.walkPage(binary.BigEndian.Uint32(page[off:]), depth+1, visited, fn); err != nil {
				return err
			}
		case 0x0d: // leaf table page: payload size, rowid, payload
			payload, err := s.leafPayload(page[:s.usable], off)
			if err != nil {
				return fmt.Errorf("sqlite page %d cell %d: %w", n, i, err)
			}
			if err := fn(payload); err != nil {
				return err
			}
		default:
			return fmt.Errorf("sqlite page %d has type %#x, want a table page", n, kind)
		}
	}
	if kind == 0x05 {
		return s.walkPage(binary.BigEndian.Uint32(page[hdr+8:]), depth+1, visited, fn)
	}
	return nil
}

// leafPayload returns a table leaf cell's payload, following overflow pages.
func (s *rpmSQLite) leafPayload(page []byte, off int) ([]byte, error) {
	size, n := sqliteVarint(page[off:])
	if n == 0 {
		return nil, fmt.Errorf("bad payload size")
	}
	off += n
	if _, n = sqliteVarint(page[off:]); n == 0 {
		return nil, fmt.Errorf("bad rowid")
	}
	off += n
	if size < 0 || size > int64(len(s.data)) {
		return nil, fmt.Errorf("payload size %d is out of range", size)
	}
	total := int(size)
	// How much of the payload is stored on the page itself.
	x := s.usable - 35
	local := total
	if total > x {
		m := (s.usable-12)*32/255 - 23
		k := m + (total-m)%(s.usable-4)
		local = m
		if k <= x {
			local = k
		}
	}
	if off+local > len(page) {
		return nil, fmt.Errorf("payload overruns the page")
	}
	out := make([]byte, 0, total)
	out = append(out, page[off:off+local]...)
	if local == total {
		return out, nil
	}
	if off+local+4 > len(page) {
		return nil, fmt.Errorf("overflow pointer overruns the page")
	}
	next := binary.BigEndian.Uint32(page[off+local:])
	for hops := 0; len(out) < total; hops++ {
		if next == 0 || hops > len(s.data)/s.pageSize {
			return nil, fmt.Errorf("overflow chain ends early")
		}
		ovf, err := s.page(next)
		if err != nil {
			return nil, err
		}
		next = binary.BigEndian.Uint32(ovf[:4])
		chunk := ovf[4:s.usable]
		if rest := total - len(out); len(chunk) > rest {
			chunk = chunk[:rest]
		}
		out = append(out, chunk...)
	}
	return out, nil
}

type sqliteKind int

const (
	sqliteNull sqliteKind = iota
	sqliteInt
	sqliteFloat
	sqliteBlob
	sqliteText
)

type sqliteValue struct {
	kind sqliteKind
	num  int64
	raw  []byte
}

// sqliteRecord decodes a record: a header of serial types, then the values.
func sqliteRecord(payload []byte) ([]sqliteValue, error) {
	hdrLen, n := sqliteVarint(payload)
	if n == 0 || hdrLen < int64(n) || hdrLen > int64(len(payload)) {
		return nil, fmt.Errorf("bad sqlite record header")
	}
	types := payload[n:hdrLen]
	body := payload[hdrLen:]
	var cols []sqliteValue
	for len(types) > 0 {
		st, n := sqliteVarint(types)
		if n == 0 {
			return nil, fmt.Errorf("bad sqlite serial type")
		}
		types = types[n:]
		var v sqliteValue
		size := 0
		switch {
		case st == 0:
			v.kind = sqliteNull
		case st >= 1 && st <= 6:
			v.kind = sqliteInt
			size = [...]int{0, 1, 2, 3, 4, 6, 8}[st]
		case st == 7:
			v.kind, size = sqliteFloat, 8
		case st == 8 || st == 9:
			v.kind, v.num = sqliteInt, st-8
		case st >= 12 && st%2 == 0:
			v.kind, size = sqliteBlob, int((st-12)/2)
		case st >= 13:
			v.kind, size = sqliteText, int((st-13)/2)
		default:
			return nil, fmt.Errorf("reserved sqlite serial type %d", st)
		}
		if size < 0 || size > len(body) {
			return nil, fmt.Errorf("sqlite value overruns the record")
		}
		v.raw = body[:size]
		body = body[size:]
		if v.kind == sqliteInt && size > 0 {
			var u uint64
			for _, b := range v.raw {
				u = u<<8 | uint64(b)
			}
			shift := 64 - 8*size
			v.num = int64(u<<shift) >> shift //nolint:gosec // sign-extend a big-endian two's complement integer
		}
		cols = append(cols, v)
	}
	return cols, nil
}

// sqliteVarint decodes a SQLite varint and returns it with its length, or a
// zero length when b is too short.
func sqliteVarint(b []byte) (int64, int) {
	var v uint64
	for i := 0; i < 9; i++ {
		if i >= len(b) {
			return 0, 0
		}
		if i == 8 {
			v = v<<8 | uint64(b[i])
			return int64(v), 9 //nolint:gosec // varints are two's complement
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return int64(v), i + 1 //nolint:gosec // varints are two's complement
		}
	}
	return 0, 0
}

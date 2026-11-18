package malicious

import (
	"sort"

	"github.com/google/osv-scalibr/semantic"
)

// Package is one language package found in an image.
type Package struct {
	Ecosystem string
	Name      string
	Version   string
	PURL      string
}

// Finding is a package that matches a malicious-package advisory.
type Finding struct {
	ID          string
	Ecosystem   string
	PackageName string
	Version     string
	PURL        string
	Summary     string
	URL         string
}

type packageKey struct {
	ecosystem string
	name      string
}

// Index is an immutable, in-memory lookup of malicious-package entries keyed
// by repository path. Apply returns a new Index, so readers never lock.
type Index struct {
	ecosystems map[string]bool
	byPath     map[string]*Entry
	byPackage  map[packageKey][]*Entry
}

// NewIndex builds an index from entries keyed by their repository path.
// Entries outside the given ecosystems are ignored; nil means all known ones.
func NewIndex(entries map[string]*Entry, ecosystems []string) *Index {
	if len(ecosystems) == 0 {
		ecosystems = DefaultEcosystems
	}
	allowed := make(map[string]bool, len(ecosystems))
	for _, ecosystem := range ecosystems {
		allowed[ecosystem] = true
	}
	index := &Index{ecosystems: allowed, byPath: make(map[string]*Entry, len(entries))}
	for path, entry := range entries {
		index.byPath[path] = entry
	}
	index.rebuildPackages()
	return index
}

// Apply returns a new index with changed entries added or replaced and the
// removed paths dropped. The receiver is left unchanged.
func (ix *Index) Apply(changed map[string]*Entry, removed []string) *Index {
	next := &Index{ecosystems: ix.ecosystems, byPath: make(map[string]*Entry, len(ix.byPath)+len(changed))}
	for path, entry := range ix.byPath {
		next.byPath[path] = entry
	}
	for _, path := range removed {
		delete(next.byPath, path)
	}
	for path, entry := range changed {
		next.byPath[path] = entry
	}
	next.rebuildPackages()
	return next
}

func (ix *Index) rebuildPackages() {
	ix.byPackage = make(map[packageKey][]*Entry, len(ix.byPath))
	for _, entry := range ix.byPath {
		if entry.Withdrawn != "" {
			continue
		}
		seen := make(map[packageKey]bool)
		for _, affected := range entry.Affected {
			ecosystem := affected.Package.Ecosystem
			if !ix.ecosystems[ecosystem] {
				continue
			}
			key := packageKey{ecosystem: ecosystem, name: normalizeName(ecosystem, affected.Package.Name)}
			if seen[key] {
				continue
			}
			seen[key] = true
			ix.byPackage[key] = append(ix.byPackage[key], entry)
		}
	}
}

// Len is the number of active (not withdrawn) entries.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	count := 0
	for _, entry := range ix.byPath {
		if entry.Withdrawn == "" {
			count++
		}
	}
	return count
}

// CountByEcosystem is the number of indexed packages per ecosystem.
func (ix *Index) CountByEcosystem() map[string]int {
	counts := make(map[string]int)
	if ix == nil {
		return counts
	}
	for key := range ix.byPackage {
		counts[key.ecosystem]++
	}
	return counts
}

// Match returns one finding per (advisory, package) pair whose version is
// affected. Results are sorted by advisory id, then purl.
func (ix *Index) Match(packages []Package) []Finding {
	if ix == nil {
		return nil
	}
	var findings []Finding
	for _, pkg := range packages {
		key := packageKey{ecosystem: pkg.Ecosystem, name: normalizeName(pkg.Ecosystem, pkg.Name)}
		for _, entry := range ix.byPackage[key] {
			if !entryAffects(entry, key, pkg.Version) {
				continue
			}
			findings = append(findings, Finding{
				ID:          entry.ID,
				Ecosystem:   pkg.Ecosystem,
				PackageName: pkg.Name,
				Version:     pkg.Version,
				PURL:        pkg.PURL,
				Summary:     entry.Summary,
				URL:         URL(entry.ID),
			})
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		return findings[i].PURL < findings[j].PURL
	})
	return findings
}

func entryAffects(entry *Entry, key packageKey, version string) bool {
	for _, affected := range entry.Affected {
		if affected.Package.Ecosystem != key.ecosystem || normalizeName(key.ecosystem, affected.Package.Name) != key.name {
			continue
		}
		if versionAffected(key.ecosystem, affected, version) {
			return true
		}
	}
	return false
}

// versionAffected follows the OSV evaluation rules. An affected package with
// neither versions nor ranges means every version; for a package published as
// malware that is the safe reading.
func versionAffected(ecosystem string, affected Affected, version string) bool {
	version = normalizeVersion(ecosystem, version)
	if len(affected.Versions) == 0 && len(affected.Ranges) == 0 {
		return true
	}
	for _, listed := range affected.Versions {
		if normalizeVersion(ecosystem, listed) == version {
			return true
		}
	}
	if version == "" {
		return false
	}
	for _, r := range affected.Ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}
		if rangeAffects(ecosystem, r.Events, version) {
			return true
		}
	}
	return false
}

// rangeAffects evaluates one range: the version is affected when the latest
// event at or below it is an introduction, honouring fixed (exclusive),
// last_affected (inclusive) and limit (exclusive) bounds.
func rangeAffects(ecosystem string, events []Event, version string) bool {
	parsed, err := semantic.Parse(version, ecosystem)
	if err != nil {
		return false
	}
	// compare returns the sign of version - bound, and false when the bound
	// cannot be parsed. "0" is the lowest possible version.
	compare := func(bound string) (int, bool) {
		bound = normalizeVersion(ecosystem, bound)
		if bound == "0" {
			return 1, true
		}
		c, err := parsed.CompareStr(bound)
		if err != nil {
			return 0, false
		}
		return c, true
	}

	type bound struct {
		kind  string
		value string
	}
	var bounds []bound
	for _, event := range events {
		switch {
		case event.Introduced != "":
			bounds = append(bounds, bound{"introduced", event.Introduced})
		case event.Fixed != "":
			bounds = append(bounds, bound{"fixed", event.Fixed})
		case event.LastAffected != "":
			bounds = append(bounds, bound{"last_affected", event.LastAffected})
		case event.Limit != "":
			bounds = append(bounds, bound{"limit", event.Limit})
		}
	}

	// OSV does not require events to be ordered; evaluate them by version.
	sort.SliceStable(bounds, func(i, j int) bool {
		a, b := normalizeVersion(ecosystem, bounds[i].value), normalizeVersion(ecosystem, bounds[j].value)
		if a == "0" || b == "0" {
			return a == "0" && b != "0"
		}
		left, err := semantic.Parse(a, ecosystem)
		if err != nil {
			return false
		}
		c, err := left.CompareStr(b)
		return err == nil && c < 0
	})

	affected := false
	for _, b := range bounds {
		c, ok := compare(b.value)
		if !ok {
			continue
		}
		switch b.kind {
		case "introduced":
			if c >= 0 {
				affected = true
			}
		case "fixed", "limit":
			if c >= 0 {
				affected = false
			}
		case "last_affected":
			if c > 0 {
				affected = false
			}
		}
	}
	return affected
}

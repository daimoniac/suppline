// Package malicious detects known-malicious packages (OSV MAL-* entries from
// ossf/malicious-packages) in the language packages of a scanned image.
// See docs/adr/0001-in-process-malicious-package-detection.md.
package malicious

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Entry is the part of an OSV record the matcher needs.
type Entry struct {
	ID        string     `json:"id"`
	Summary   string     `json:"summary"`
	Withdrawn string     `json:"withdrawn"`
	Affected  []Affected `json:"affected"`
}

// Affected names one package and the versions of it that are malicious.
type Affected struct {
	Package  AffectedPackage `json:"package"`
	Versions []string        `json:"versions"`
	Ranges   []Range         `json:"ranges"`
}

// AffectedPackage identifies a package within an OSV ecosystem.
type AffectedPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Range is an OSV version range. Only SEMVER and ECOSYSTEM ranges are evaluated.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one OSV range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// ParseEntry decodes one OSV JSON record.
func ParseEntry(data []byte) (*Entry, error) {
	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("decode osv record: %w", err)
	}
	if strings.TrimSpace(entry.ID) == "" {
		return nil, fmt.Errorf("osv record has no id")
	}
	return &entry, nil
}

// URL is the public advisory page for an OSV id.
func URL(id string) string {
	return "https://osv.dev/vulnerability/" + id
}

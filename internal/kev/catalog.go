// Package kev keeps the CISA Known Exploited Vulnerabilities (KEV) catalog
// current and answers whether a CVE is listed.
package kev

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Entry is one catalog entry.
type Entry struct {
	CVEID     string
	DateAdded string // YYYY-MM-DD
	DueDate   string // YYYY-MM-DD; the remediation deadline for US federal agencies
	// Ransomware is true when CISA lists the CVE as known to be used in
	// ransomware campaigns.
	Ransomware bool
}

// Catalog is an immutable, parsed copy of the KEV feed.
type Catalog struct {
	Version      string // the feed's catalogVersion
	DateReleased string
	entries      map[string]Entry
}

// Lookup returns the entry for cve. A nil catalog has no entries.
func (c *Catalog) Lookup(cve string) (Entry, bool) {
	if c == nil {
		return Entry{}, false
	}
	entry, ok := c.entries[normalizeCVE(cve)]
	return entry, ok
}

// Len returns the number of entries. A nil catalog has none.
func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.entries)
}

// IDs returns every listed CVE ID, in no particular order.
func (c *Catalog) IDs() []string {
	if c == nil {
		return nil
	}
	ids := make([]string, 0, len(c.entries))
	for id := range c.entries {
		ids = append(ids, id)
	}
	return ids
}

func normalizeCVE(cve string) string {
	return strings.ToUpper(strings.TrimSpace(cve))
}

// Parse decodes the CISA KEV JSON feed. A feed with no entries is an error:
// an empty catalog would make every CVE look unlisted.
func Parse(body []byte) (*Catalog, error) {
	var feed struct {
		CatalogVersion  string `json:"catalogVersion"`
		DateReleased    string `json:"dateReleased"`
		Vulnerabilities []struct {
			CVEID                      string `json:"cveID"`
			DateAdded                  string `json:"dateAdded"`
			DueDate                    string `json:"dueDate"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("decode CISA KEV feed: %w", err)
	}
	catalog := &Catalog{
		Version:      feed.CatalogVersion,
		DateReleased: feed.DateReleased,
		entries:      make(map[string]Entry, len(feed.Vulnerabilities)),
	}
	for _, item := range feed.Vulnerabilities {
		id := normalizeCVE(item.CVEID)
		if id == "" {
			continue
		}
		catalog.entries[id] = Entry{
			CVEID:      id,
			DateAdded:  item.DateAdded,
			DueDate:    item.DueDate,
			Ransomware: strings.EqualFold(strings.TrimSpace(item.KnownRansomwareCampaignUse), "known"),
		}
	}
	if len(catalog.entries) == 0 {
		return nil, fmt.Errorf("CISA KEV feed has no entries")
	}
	return catalog, nil
}

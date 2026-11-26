package kev

import "testing"

const feedBody = `{
  "catalogVersion": "2026.11.25",
  "dateReleased": "2026-11-25T16:00:00.000Z",
  "vulnerabilities": [
    {"cveID": "CVE-2024-1234", "dateAdded": "2024-03-01", "dueDate": "2024-03-22", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "cve-2023-4911", "dateAdded": "2023-11-21", "dueDate": "2023-12-12", "knownRansomwareCampaignUse": "Unknown"}
  ]
}`

func TestParseKeepsFieldsAndNormalisesIDs(t *testing.T) {
	catalog, err := Parse([]byte(feedBody))
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Len() != 2 || catalog.Version != "2026.11.25" {
		t.Fatalf("len=%d version=%q", catalog.Len(), catalog.Version)
	}
	entry, ok := catalog.Lookup(" cve-2024-1234 ")
	if !ok || !entry.Ransomware || entry.DateAdded != "2024-03-01" || entry.DueDate != "2024-03-22" {
		t.Fatalf("entry=%+v ok=%v", entry, ok)
	}
	entry, ok = catalog.Lookup("CVE-2023-4911")
	if !ok || entry.Ransomware {
		t.Fatalf("lowercase feed ID should be found, without ransomware: %+v ok=%v", entry, ok)
	}
	if _, ok := catalog.Lookup("CVE-2099-0001"); ok {
		t.Fatal("unlisted CVE found")
	}
}

func TestParseRejectsEmptyFeed(t *testing.T) {
	if _, err := Parse([]byte(`{"vulnerabilities":[]}`)); err == nil {
		t.Fatal("an empty feed must be an error, or every CVE would look unlisted")
	}
	if _, err := Parse([]byte(`<html>blocked</html>`)); err == nil {
		t.Fatal("a non-JSON body must be an error")
	}
}

package types

// KEVInfo is a CVE's entry in the CISA Known Exploited Vulnerabilities
// catalog. A nil *KEVInfo means the CVE is not listed.
type KEVInfo struct {
	DateAdded  string // YYYY-MM-DD
	DueDate    string // YYYY-MM-DD
	Ransomware bool   // known to be used in ransomware campaigns
}

package statestore

import (
	"context"
	"errors"
	"time"
)

// ErrScanNotFound is returned by GetLastScan when no scan record exists for the given digest.
// This is a normal condition indicating the image has never been scanned before.
// Callers should use errors.Is() to check for this specific error.
var ErrScanNotFound = errors.New("scan not found")

// StateStore defines the interface for persisting and querying scan results
type StateStore interface {
	// RecordScan saves scan results with full vulnerability details
	RecordScan(ctx context.Context, record *ScanRecord) error

	// GetLastScan retrieves the most recent scan for a digest with vulnerabilities
	GetLastScan(ctx context.Context, digest string) (*ScanRecord, error)

	// ListDueForRescan returns digests that need rescanning
	ListDueForRescan(ctx context.Context, interval time.Duration) ([]string, error)

	// GetScanHistory returns scan history for a digest with full details
	GetScanHistory(ctx context.Context, digest string, limit int) ([]*ScanRecord, error)

	// QueryVulnerabilities searches vulnerabilities across all scans
	QueryVulnerabilities(ctx context.Context, filter VulnFilter) ([]*VulnerabilityRecord, error)

	// GetImagesByCVE returns all images affected by a specific CVE
	GetImagesByCVE(ctx context.Context, cveID string) ([]*ScanRecord, error)

	// ListScans returns scan records with optional filters
	ListScans(ctx context.Context, filter ScanFilter) ([]*ScanRecord, error)

	// ListTolerations returns tolerated CVEs with optional filters
	ListTolerations(ctx context.Context, filter TolerationFilter) ([]*TolerationInfo, error)
}

// ScanRecord represents a complete scan result for an image digest
type ScanRecord struct {
	Digest            string
	Repository        string
	Tag               string
	ScannedAt         time.Time
	CriticalVulnCount int
	HighVulnCount     int
	MediumVulnCount   int
	LowVulnCount      int
	PolicyPassed      bool
	Signed            bool
	SBOMAttested      bool
	VulnAttested      bool
	Vulnerabilities   []VulnerabilityRecord
	ToleratedCVEs     []ToleratedCVE
	ErrorMessage      string
}

// VulnerabilityRecord represents a single vulnerability found in an image
type VulnerabilityRecord struct {
	CVEID            string
	Severity         string
	PackageName      string
	InstalledVersion string
	FixedVersion     string
	Title            string
	Description      string
	PrimaryURL       string
	// Image information
	Repository string
	Tag        string
	Digest     string
	ScannedAt  time.Time
}

// ToleratedCVE represents a CVE that has been explicitly tolerated
type ToleratedCVE struct {
	CVEID       string
	Statement   string
	ToleratedAt time.Time
	ExpiresAt   *time.Time // Nil means no expiry
}

// VulnFilter defines criteria for querying vulnerabilities
type VulnFilter struct {
	CVEID       string
	Severity    string
	PackageName string
	Repository  string
	Limit       int
}

// ScanFilter defines criteria for listing scans
type ScanFilter struct {
	Repository   string
	PolicyPassed *bool
	Limit        int
	Offset       int
}

// TolerationFilter defines criteria for listing tolerations
type TolerationFilter struct {
	CVEID        string
	Repository   string
	Expired      *bool
	ExpiringSoon *bool // Within 7 days
	Limit        int
}

// TolerationInfo represents toleration information per repository
// Each toleration appears once per repository, regardless of how many tags/digests it applies to
type TolerationInfo struct {
	ToleratedCVE
	Repository string
}

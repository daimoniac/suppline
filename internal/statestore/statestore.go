package statestore

import (
	"context"
	"errors"
	"time"

	"github.com/daimoniac/suppline/daimoniac/suppline/internal/types"
)

// ErrScanNotFound is returned by GetLastScan when no scan record exists for the given digest.
// This is a normal condition indicating the image has never been scanned before.
// Callers should use errors.Is() to check for this specific error.
var ErrScanNotFound = errors.New("scan not found")

// StateStore defines the core interface for persisting scan results.
// This interface contains only the methods used by the worker for recording
// and checking scan state. For querying and reporting, use StateStoreQuery.
type StateStore interface {
	// RecordScan saves scan results with full vulnerability details
	RecordScan(ctx context.Context, record *ScanRecord) error

	// GetLastScan retrieves the most recent scan for a digest with vulnerabilities
	GetLastScan(ctx context.Context, digest string) (*ScanRecord, error)
}

// StateStoreQuery defines the extended interface for querying scan data.
// This interface is primarily used by the API layer for reporting and analysis.
// Implementations should also implement StateStore for core functionality.
type StateStoreQuery interface {
	StateStore

	// GetScanHistory returns scan history for a digest with full details
	GetScanHistory(ctx context.Context, digest string, limit int) ([]*ScanRecord, error)

	// QueryVulnerabilities searches vulnerabilities across all scans
	QueryVulnerabilities(ctx context.Context, filter VulnFilter) ([]*types.VulnerabilityRecord, error)

	// GetImagesByCVE returns all images affected by a specific CVE
	GetImagesByCVE(ctx context.Context, cveID string) ([]*ScanRecord, error)

	// ListScans returns scan records with optional filters
	ListScans(ctx context.Context, filter ScanFilter) ([]*ScanRecord, error)

	// ListTolerations returns tolerated CVEs with optional filters
	ListTolerations(ctx context.Context, filter TolerationFilter) ([]*types.TolerationInfo, error)
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
	Vulnerabilities   []types.VulnerabilityRecord // Using canonical type
	ToleratedCVEs     []types.ToleratedCVE        // Using canonical type
	ErrorMessage      string
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



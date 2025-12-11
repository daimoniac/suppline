package statestore

import (
	"context"
	"errors"
	"time"

	"github.com/daimoniac/suppline/internal/types"
)

// ErrScanNotFound is returned by GetLastScan when no scan record exists for the given digest.
// This is a normal condition indicating the image has never been scanned before.
// Callers should use errors.Is() to check for this specific error.
var ErrScanNotFound = errors.New("scan not found")

// Repository represents a container image repository
type Repository struct {
	ID        int64
	Name      string
	Registry  string
	CreatedAt time.Time
}

// Artifact represents an immutable container image (digest) with optional tag
type Artifact struct {
	ID           int64
	RepositoryID int64
	Digest       string
	Tag          string
	FirstSeen    time.Time
	LastSeen     time.Time
	LastScanID   *int64
	NextScanAt   *time.Time
	CreatedAt    time.Time
}

// StateStore defines the core interface for persisting scan results.
// This interface contains only the methods used by the worker for recording
// and checking scan state. For querying and reporting, use StateStoreQuery.
type StateStore interface {
	// RecordScan saves scan results with full vulnerability details
	RecordScan(ctx context.Context, record *ScanRecord) error

	// GetLastScan retrieves the most recent scan for a digest with vulnerabilities
	GetLastScan(ctx context.Context, digest string) (*ScanRecord, error)

	// ListDueForRescan returns digests that need rescanning (where next_scan_at < now)
	ListDueForRescan(ctx context.Context, interval time.Duration) ([]string, error)
}

// RepositoryInfo represents a repository with aggregated metadata
type RepositoryInfo struct {
	Name                 string
	TagCount             int
	LastScanTime         *int64 // Unix timestamp in seconds
	VulnerabilityCount   VulnerabilityCountSummary
	PolicyPassed         bool
}

// VulnerabilityCountSummary represents aggregated vulnerability counts
type VulnerabilityCountSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Tolerated int
}

// RepositoryDetail represents a repository with its tags
type RepositoryDetail struct {
	Name  string
	Tags  []TagInfo
	Total int
}

// TagInfo represents a tag within a repository
type TagInfo struct {
	Name                 string
	Digest               string
	LastScanTime         *int64 // Unix timestamp in seconds
	NextScanTime         *int64 // Unix timestamp in seconds
	VulnerabilityCount   VulnerabilityCountSummary
	PolicyPassed         bool
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

	// ListRepositories returns all repositories with aggregated metadata
	ListRepositories(ctx context.Context, filter RepositoryFilter) (*RepositoriesListResponse, error)

	// GetRepository returns a repository with all its tags
	GetRepository(ctx context.Context, name string, filter RepositoryTagFilter) (*RepositoryDetail, error)
}

// RepositoryFilter defines criteria for listing repositories
type RepositoryFilter struct {
	Search string
	Limit  int
	Offset int
}

// RepositoriesListResponse represents the response for listing repositories
type RepositoriesListResponse struct {
	Repositories []RepositoryInfo
	Total        int
}

// RepositoryTagFilter defines criteria for listing tags in a repository
type RepositoryTagFilter struct {
	Search string
	Limit  int
	Offset int
}

// ScanRecord represents a complete scan result for an image digest
type ScanRecord struct {
	ID                int64
	ArtifactID        int64
	ScanDurationMs    int
	CriticalVulnCount int
	HighVulnCount     int
	MediumVulnCount   int
	LowVulnCount      int
	PolicyPassed      bool
	SBOMAttested      bool
	VulnAttested      bool
	SCAIAttested      bool
	ErrorMessage      string
	CreatedAt         int64 // Unix timestamp in seconds
	// Denormalized for convenience (loaded via joins)
	Digest            string
	Repository        string
	Tag               string
	Vulnerabilities   []types.VulnerabilityRecord // Using canonical type
	ToleratedCVEs     []types.ToleratedCVE        // Using canonical type
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
	MaxAge       int    // Maximum age of scans in seconds (0 = no limit)
	SortBy       string // Sorting option: "age_desc" (default)
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



package api

import (
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/daimoniac/suppline/internal/types"
)

// formatTimestamp converts a Unix timestamp to ISO8601 (RFC 3339) format.
// The output is always in UTC timezone and ends with "Z".
//
// Example:
//   formatTimestamp(0) returns "1970-01-01T00:00:00Z"
//   formatTimestamp(1732896000) returns "2024-11-29T15:30:00Z"
func formatTimestamp(unixSeconds int64) string {
	return time.Unix(unixSeconds, 0).UTC().Format(time.RFC3339)
}

// formatNullableTimestamp converts a nullable Unix timestamp to ISO8601 or nil.
// If the input is nil, returns nil. Otherwise, converts to ISO8601 format.
//
// Example:
//   formatNullableTimestamp(nil) returns nil
//   formatNullableTimestamp(&timestamp) returns pointer to "2024-11-29T15:30:00Z"
func formatNullableTimestamp(unixSeconds *int64) *string {
	if unixSeconds == nil {
		return nil
	}
	formatted := formatTimestamp(*unixSeconds)
	return &formatted
}

// VulnerabilityRecordResponse represents a vulnerability for API responses.
// Timestamps are formatted as ISO8601 strings.
type VulnerabilityRecordResponse struct {
	CVEID            string `json:"cve_id"`
	Severity         string `json:"severity"`
	PackageName      string `json:"package_name"`
	InstalledVersion string `json:"installed_version"`
	FixedVersion     string `json:"fixed_version"`
	Title            string `json:"title"`
	Description      string `json:"description"`
	PrimaryURL       string `json:"primary_url"`
	Repository       string `json:"repository"`
	Tag              string `json:"tag"`
	Digest           string `json:"digest"`
	ScannedAt        string `json:"scanned_at"` // ISO8601
}

// ToleratedCVEResponse represents a tolerated CVE for API responses.
// Timestamps are formatted as ISO8601 strings.
type ToleratedCVEResponse struct {
	CVEID       string  `json:"cve_id"`
	Statement   string  `json:"statement"`
	ToleratedAt string  `json:"tolerated_at"` // ISO8601
	ExpiresAt   *string `json:"expires_at"`   // ISO8601 or null
}

// ScanRecordResponse represents a scan record for API responses.
// Timestamps are formatted as ISO8601 strings.
type ScanRecordResponse struct {
	ID                int64                         `json:"id"`
	ArtifactID        int64                         `json:"artifact_id"`
	ScanDurationMs    int                           `json:"scan_duration_ms"`
	CriticalVulnCount int                           `json:"critical_vuln_count"`
	HighVulnCount     int                           `json:"high_vuln_count"`
	MediumVulnCount   int                           `json:"medium_vuln_count"`
	LowVulnCount      int                           `json:"low_vuln_count"`
	PolicyPassed      bool                          `json:"policy_passed"`
	SBOMAttested      bool                          `json:"sbom_attested"`
	VulnAttested      bool                          `json:"vuln_attested"`
	SCAIAttested      bool                          `json:"scai_attested"`
	ErrorMessage      string                        `json:"error_message"`
	CreatedAt         string                        `json:"created_at"` // ISO8601
	Digest            string                        `json:"digest"`
	Repository        string                        `json:"repository"`
	Tag               string                        `json:"tag"`
	Vulnerabilities   []VulnerabilityRecordResponse `json:"vulnerabilities"`
	ToleratedCVEs     []ToleratedCVEResponse        `json:"tolerated_cves"`
}

// toVulnerabilityRecordResponse converts an internal VulnerabilityRecord to a response DTO.
func toVulnerabilityRecordResponse(vuln types.VulnerabilityRecord) VulnerabilityRecordResponse {
	return VulnerabilityRecordResponse{
		CVEID:            vuln.CVEID,
		Severity:         vuln.Severity,
		PackageName:      vuln.PackageName,
		InstalledVersion: vuln.InstalledVersion,
		FixedVersion:     vuln.FixedVersion,
		Title:            vuln.Title,
		Description:      vuln.Description,
		PrimaryURL:       vuln.PrimaryURL,
		Repository:       vuln.Repository,
		Tag:              vuln.Tag,
		Digest:           vuln.Digest,
		ScannedAt:        formatTimestamp(vuln.ScannedAt),
	}
}

// toToleratedCVEResponse converts an internal ToleratedCVE to a response DTO.
func toToleratedCVEResponse(cve types.ToleratedCVE) ToleratedCVEResponse {
	return ToleratedCVEResponse{
		CVEID:       cve.CVEID,
		Statement:   cve.Statement,
		ToleratedAt: formatTimestamp(cve.ToleratedAt),
		ExpiresAt:   formatNullableTimestamp(cve.ExpiresAt),
	}
}

// toScanRecordResponse converts an internal ScanRecord to a response DTO.
func toScanRecordResponse(record *statestore.ScanRecord) *ScanRecordResponse {
	if record == nil {
		return nil
	}

	// Convert vulnerabilities
	vulnerabilities := make([]VulnerabilityRecordResponse, len(record.Vulnerabilities))
	for i, vuln := range record.Vulnerabilities {
		vulnerabilities[i] = toVulnerabilityRecordResponse(vuln)
	}

	// Convert tolerated CVEs
	toleratedCVEs := make([]ToleratedCVEResponse, len(record.ToleratedCVEs))
	for i, cve := range record.ToleratedCVEs {
		toleratedCVEs[i] = toToleratedCVEResponse(cve)
	}

	return &ScanRecordResponse{
		ID:                record.ID,
		ArtifactID:        record.ArtifactID,
		ScanDurationMs:    record.ScanDurationMs,
		CriticalVulnCount: record.CriticalVulnCount,
		HighVulnCount:     record.HighVulnCount,
		MediumVulnCount:   record.MediumVulnCount,
		LowVulnCount:      record.LowVulnCount,
		PolicyPassed:      record.PolicyPassed,
		SBOMAttested:      record.SBOMAttested,
		VulnAttested:      record.VulnAttested,
		SCAIAttested:      record.SCAIAttested,
		ErrorMessage:      record.ErrorMessage,
		CreatedAt:         formatTimestamp(record.CreatedAt),
		Digest:            record.Digest,
		Repository:        record.Repository,
		Tag:               record.Tag,
		Vulnerabilities:   vulnerabilities,
		ToleratedCVEs:     toleratedCVEs,
	}
}

// RepositoryInfoResponse represents repository info for API responses.
// Timestamps are formatted as ISO8601 strings.
type RepositoryInfoResponse struct {
	Name               string                              `json:"name"`
	TagCount           int                                 `json:"tag_count"`
	LastScanTime       *string                             `json:"last_scan_time"` // ISO8601 or null
	VulnerabilityCount statestore.VulnerabilityCountSummary `json:"vulnerability_count"`
	PolicyPassed       bool                                `json:"policy_passed"`
}

// TagInfoResponse represents tag info for API responses.
// Timestamps are formatted as ISO8601 strings.
type TagInfoResponse struct {
	Name               string                              `json:"name"`
	Digest             string                              `json:"digest"`
	LastScanTime       *string                             `json:"last_scan_time"` // ISO8601 or null
	NextScanTime       *string                             `json:"next_scan_time"` // ISO8601 or null
	VulnerabilityCount statestore.VulnerabilityCountSummary `json:"vulnerability_count"`
	PolicyPassed       bool                                `json:"policy_passed"`
}

// RepositoryDetailResponse represents a repository with its tags for API responses.
// Timestamps are formatted as ISO8601 strings.
type RepositoryDetailResponse struct {
	Name  string            `json:"name"`
	Tags  []TagInfoResponse `json:"tags"`
	Total int               `json:"total"`
}

// RepositoriesListResponse represents the response for listing repositories.
// Timestamps are formatted as ISO8601 strings.
type RepositoriesListResponse struct {
	Repositories []RepositoryInfoResponse `json:"repositories"`
	Total        int                      `json:"total"`
}

// TolerationInfoResponse represents toleration info for API responses.
// Timestamps are formatted as ISO8601 strings.
type TolerationInfoResponse struct {
	CVEID       string  `json:"cve_id"`
	Statement   string  `json:"statement"`
	ToleratedAt string  `json:"tolerated_at"` // ISO8601
	ExpiresAt   *string `json:"expires_at"`   // ISO8601 or null
	Repository  string  `json:"repository"`
}

// toRepositoryInfoResponse converts an internal RepositoryInfo to a response DTO.
func toRepositoryInfoResponse(info statestore.RepositoryInfo) RepositoryInfoResponse {
	return RepositoryInfoResponse{
		Name:               info.Name,
		TagCount:           info.TagCount,
		LastScanTime:       formatNullableTimestamp(info.LastScanTime),
		VulnerabilityCount: info.VulnerabilityCount,
		PolicyPassed:       info.PolicyPassed,
	}
}

// toTagInfoResponse converts an internal TagInfo to a response DTO.
func toTagInfoResponse(tag statestore.TagInfo) TagInfoResponse {
	return TagInfoResponse{
		Name:               tag.Name,
		Digest:             tag.Digest,
		LastScanTime:       formatNullableTimestamp(tag.LastScanTime),
		NextScanTime:       formatNullableTimestamp(tag.NextScanTime),
		VulnerabilityCount: tag.VulnerabilityCount,
		PolicyPassed:       tag.PolicyPassed,
	}
}

// toRepositoryDetailResponse converts an internal RepositoryDetail to a response DTO.
func toRepositoryDetailResponse(detail *statestore.RepositoryDetail) *RepositoryDetailResponse {
	if detail == nil {
		return nil
	}

	// Convert tags
	tags := make([]TagInfoResponse, len(detail.Tags))
	for i, tag := range detail.Tags {
		tags[i] = toTagInfoResponse(tag)
	}

	return &RepositoryDetailResponse{
		Name:  detail.Name,
		Tags:  tags,
		Total: detail.Total,
	}
}

// toRepositoriesListResponse converts an internal RepositoriesListResponse to a response DTO.
func toRepositoriesListResponse(list *statestore.RepositoriesListResponse) *RepositoriesListResponse {
	if list == nil {
		return nil
	}

	// Convert repositories
	repositories := make([]RepositoryInfoResponse, len(list.Repositories))
	for i, repo := range list.Repositories {
		repositories[i] = toRepositoryInfoResponse(repo)
	}

	return &RepositoriesListResponse{
		Repositories: repositories,
		Total:        list.Total,
	}
}

// toTolerationInfoResponse converts an internal TolerationInfo to a response DTO.
func toTolerationInfoResponse(info types.TolerationInfo) TolerationInfoResponse {
	return TolerationInfoResponse{
		CVEID:       info.CVEID,
		Statement:   info.Statement,
		ToleratedAt: formatTimestamp(info.ToleratedAt),
		ExpiresAt:   formatNullableTimestamp(info.ExpiresAt),
		Repository:  info.Repository,
	}
}

// Note: TriggerScanResponse and ReevaluatePolicyResponse (defined in handlers.go)
// do not contain timestamp fields and therefore do not require response DTOs.
// These types only contain integer and string fields:
//   - TriggerScanResponse: Queued (int), TaskID (string)
//   - ReevaluatePolicyResponse: Queued (int), Repository (string)

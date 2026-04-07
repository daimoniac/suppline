package types

import (
	"fmt"
	"time"
)

// VEXAnalysisState represents the CycloneDX VEX analysis state for a vulnerability.
// See: https://cyclonedx.org/capabilities/vex/
type VEXAnalysisState string

const (
	VEXStateNotAffected          VEXAnalysisState = "not_affected"
	VEXStateAffected             VEXAnalysisState = "affected"
	VEXStateInTriage             VEXAnalysisState = "in_triage"
	VEXStateFalsePositive        VEXAnalysisState = "false_positive"
	VEXStateResolved             VEXAnalysisState = "resolved"
	VEXStateResolvedWithPedigree VEXAnalysisState = "resolved_with_pedigree"
)

// validVEXStates is the set of valid VEX analysis states.
var validVEXStates = map[VEXAnalysisState]bool{
	VEXStateNotAffected:          true,
	VEXStateAffected:             true,
	VEXStateInTriage:             true,
	VEXStateFalsePositive:        true,
	VEXStateResolved:             true,
	VEXStateResolvedWithPedigree: true,
}

// VEXJustification represents the CycloneDX VEX justification for a not_affected state.
type VEXJustification string

const (
	VEXJustCodeNotPresent         VEXJustification = "code_not_present"
	VEXJustCodeNotReachable       VEXJustification = "code_not_reachable"
	VEXJustRequiresConfiguration  VEXJustification = "requires_configuration"
	VEXJustRequiresDependency     VEXJustification = "requires_dependency"
	VEXJustRequiresEnvironment    VEXJustification = "requires_environment"
	VEXJustProtectedByCompiler    VEXJustification = "protected_by_compiler"
	VEXJustProtectedAtRuntime     VEXJustification = "protected_at_runtime"
	VEXJustProtectedAtPerimeter   VEXJustification = "protected_at_perimeter"
	VEXJustProtectedByMitigations VEXJustification = "protected_by_mitigations"
)

// validVEXJustifications is the set of valid VEX justifications.
var validVEXJustifications = map[VEXJustification]bool{
	VEXJustCodeNotPresent:         true,
	VEXJustCodeNotReachable:       true,
	VEXJustRequiresConfiguration:  true,
	VEXJustRequiresDependency:     true,
	VEXJustRequiresEnvironment:    true,
	VEXJustProtectedByCompiler:    true,
	VEXJustProtectedAtRuntime:     true,
	VEXJustProtectedAtPerimeter:   true,
	VEXJustProtectedByMitigations: true,
}

// VEXStatement represents a CycloneDX VEX statement for a vulnerability.
// This is the config-level type parsed from suppline.yml x-vex entries.
type VEXStatement struct {
	ID            string           `yaml:"id" json:"id"`
	State         VEXAnalysisState `yaml:"state" json:"state"`
	Justification VEXJustification `yaml:"justification,omitempty" json:"justification,omitempty"`
	Detail        string           `yaml:"detail,omitempty" json:"detail,omitempty"`
	ExpiresAt     *int64           `yaml:"expires_at,omitempty" json:"expiresAt,omitempty"` // Unix timestamp in seconds, nil means no expiry
}

// UnmarshalYAML implements custom YAML unmarshaling for VEXStatement.
// This allows expires_at to be specified as an RFC3339 timestamp or date string in YAML
// while storing it as a Unix timestamp internally.
func (v *VEXStatement) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var temp struct {
		ID            string  `yaml:"id"`
		State         string  `yaml:"state"`
		Justification string  `yaml:"justification,omitempty"`
		Detail        string  `yaml:"detail,omitempty"`
		ExpiresAt     *string `yaml:"expires_at,omitempty"`
	}

	if err := unmarshal(&temp); err != nil {
		return err
	}

	v.ID = temp.ID
	v.State = VEXAnalysisState(temp.State)
	v.Justification = VEXJustification(temp.Justification)
	v.Detail = temp.Detail

	// Parse expires_at if provided
	if temp.ExpiresAt != nil && *temp.ExpiresAt != "" {
		var t time.Time
		var err error

		// Try RFC3339 format first (2026-02-28T23:59:59Z)
		t, err = time.Parse(time.RFC3339, *temp.ExpiresAt)
		if err != nil {
			// Try date-only format (2026-02-28) - set to end of day
			t, err = time.Parse("2006-01-02", *temp.ExpiresAt)
			if err != nil {
				return fmt.Errorf("invalid expires_at format for %s: %w (expected RFC3339 like '2026-02-28T23:59:59Z' or date like '2026-02-28')", temp.ID, err)
			}
			// Set to end of day (23:59:59) for date-only format
			t = time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
		}

		timestamp := t.Unix()
		v.ExpiresAt = &timestamp
	}

	return nil
}

// ValidateVEXStatement validates a VEX statement's fields.
// Returns an error if the state is invalid, or if justification is set for a non-not_affected state.
func ValidateVEXStatement(v VEXStatement) error {
	if !validVEXStates[v.State] {
		return fmt.Errorf("invalid VEX state %q for %s: must be one of not_affected, affected, in_triage, false_positive, resolved, resolved_with_pedigree", v.State, v.ID)
	}

	if v.Justification != "" {
		if v.State != VEXStateNotAffected {
			return fmt.Errorf("VEX justification is only valid when state is not_affected, got state %q for %s", v.State, v.ID)
		}
		if !validVEXJustifications[v.Justification] {
			return fmt.Errorf("invalid VEX justification %q for %s", v.Justification, v.ID)
		}
	}

	return nil
}

// AppliedVEXStatement records a VEX statement that was actually applied during a scan.
// This is the storage/audit type persisted in scan records.
type AppliedVEXStatement struct {
	CVEID         string           `json:"CVEID"`
	State         VEXAnalysisState `json:"State"`
	Justification VEXJustification `json:"Justification,omitempty"`
	Detail        string           `json:"Detail,omitempty"`
	AppliedAt     int64            `json:"AppliedAt"` // Unix timestamp in seconds
	ExpiresAt     *int64           `json:"ExpiresAt"` // Unix timestamp in seconds, nil means no expiry
}

// VEXInfo extends AppliedVEXStatement with repository context for queries.
type VEXInfo struct {
	CVEID         string           `json:"CVEID"`
	State         VEXAnalysisState `json:"State"`
	Justification VEXJustification `json:"Justification,omitempty"`
	Detail        string           `json:"Detail,omitempty"`
	AppliedAt     int64            `json:"AppliedAt"` // Unix timestamp in seconds
	ExpiresAt     *int64           `json:"ExpiresAt"`
	Repository    string           `json:"Repository"`
}

// VEXSummary groups VEX info by CVE ID with list of affected repositories.
// Used by the API to provide a consolidated view of VEX statements across repositories.
type VEXSummary struct {
	CVEID              string              `json:"CVEID"`
	State              VEXAnalysisState    `json:"State"`
	Justification      VEXJustification    `json:"Justification,omitempty"`
	Detail             string              `json:"Detail,omitempty"`
	ExpiresAt          *int64              `json:"ExpiresAt"`
	Repositories       []RepositoryVEXInfo `json:"Repositories"`
	AffectedImageCount int                 `json:"AffectedImageCount"`
}

// RepositoryVEXInfo contains repository-specific VEX metadata.
type RepositoryVEXInfo struct {
	Repository string `json:"Repository"`
	AppliedAt  int64  `json:"AppliedAt"` // Unix timestamp when first applied, 0 if never applied
}

// FilterAppliedVEXStatements filters VEX statements based on a set of exempted CVE IDs.
// Only statements whose IDs are in the exemptedSet will be included.
func FilterAppliedVEXStatements(
	statements []VEXStatement,
	exemptedSet map[string]bool,
	appliedAt int64,
) []AppliedVEXStatement {
	filtered := make([]AppliedVEXStatement, 0, len(statements))
	for _, stmt := range statements {
		if exemptedSet[stmt.ID] {
			filtered = append(filtered, AppliedVEXStatement{
				CVEID:         stmt.ID,
				State:         stmt.State,
				Justification: stmt.Justification,
				Detail:        stmt.Detail,
				AppliedAt:     appliedAt,
				ExpiresAt:     stmt.ExpiresAt,
			})
		}
	}
	return filtered
}

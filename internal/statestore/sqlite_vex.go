package statestore

import (
	"context"
	"database/sql"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
)

func (s *SQLiteStore) ListVEXStatements(ctx context.Context, filter VEXFilter) ([]*types.VEXInfo, error) {
	query := `
		SELECT 
			r.name as repository,
			sr.vex_statements_json
		FROM scan_records sr
		JOIN artifacts a ON sr.artifact_id = a.id
		JOIN repositories r ON a.repository_id = r.id
		WHERE (sr.vex_statements_json IS NOT NULL AND sr.vex_statements_json != '[]' AND sr.vex_statements_json != '')
	`
	args := []interface{}{}

	if filter.Repository != "" {
		query += " AND r.name = ?"
		args = append(args, filter.Repository)
	}

	query += " ORDER BY sr.created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to query VEX statements: %w", err)
	}
	defer rows.Close()

	// Build a map of unique repository+CVE combinations
	vexMap := make(map[string]*types.VEXInfo)

	for rows.Next() {
		var repository string
		var vexJSON sql.NullString

		if err := rows.Scan(&repository, &vexJSON); err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}

		for _, vs := range decodeStoredExemptionsLenient(vexJSON) {
			if filter.CVEID != "" && vs.CVEID != filter.CVEID {
				continue
			}
			key := repository + ":" + vs.CVEID
			if _, found := vexMap[key]; !found {
				vexMap[key] = &types.VEXInfo{
					CVEID:         vs.CVEID,
					State:         vs.State,
					Justification: vs.Justification,
					Detail:        vs.Detail,
					AppliedAt:     vs.AppliedAt,
					ExpiresAt:     vs.ExpiresAt,
					Repository:    repository,
				}
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	// Convert map to slice
	results := make([]*types.VEXInfo, 0, len(vexMap))
	for _, info := range vexMap {
		results = append(results, info)
	}

	// Apply limit
	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}

	return results, nil
}

// GetExemptedCVEImageCounts returns a map of CVE ID → count of distinct digests
// that have this CVE exempted via VEX in the latest scan for each artifact.
func (s *SQLiteStore) GetExemptedCVEImageCounts(ctx context.Context) (map[string]int, error) {
	query := `
		SELECT a.digest, sr.vex_statements_json
		FROM artifacts a
		JOIN scan_records sr ON a.last_scan_id = sr.id
		WHERE (sr.vex_statements_json IS NOT NULL AND sr.vex_statements_json != '[]' AND sr.vex_statements_json != '')
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.NewTransientf("failed to query exempted CVE image counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var digest string
		var vexJSON sql.NullString
		if err := rows.Scan(&digest, &vexJSON); err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}

		for _, cveID := range extractAppliedCVEIDs(vexJSON) {
			counts[cveID]++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}
	return counts, nil
}

// getAppliedCVESet returns a set of all CVE IDs that have been applied (exempted via VEX)
// in at least one scan record. This is a helper method for inactive VEX queries.
func (s *SQLiteStore) getAppliedCVESet(ctx context.Context) (map[string]bool, error) {
	query := `
		SELECT 
			sr.vex_statements_json
		FROM scan_records sr
		WHERE (sr.vex_statements_json IS NOT NULL AND sr.vex_statements_json != '[]' AND sr.vex_statements_json != '')
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, errors.NewTransientf("failed to query applied CVEs: %w", err)
	}
	defer rows.Close()

	appliedCVEs := make(map[string]bool)

	for rows.Next() {
		var vexJSON sql.NullString

		if err := rows.Scan(&vexJSON); err != nil {
			return nil, errors.NewTransientf("failed to scan row: %w", err)
		}

		for _, cveID := range extractAppliedCVEIDs(vexJSON) {
			appliedCVEs[cveID] = true
		}
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating rows: %w", err)
	}

	return appliedCVEs, nil
}

// GetInactiveVEXCount returns the count of CVE IDs from the provided list
// that have never been applied via VEX in any scan record.
// This helps identify VEX statements defined in configuration that are no longer being used.
func (s *SQLiteStore) GetInactiveVEXCount(ctx context.Context, definedCVEIDs []string) (int, error) {
	if len(definedCVEIDs) == 0 {
		return 0, nil
	}

	appliedCVEs, err := s.getAppliedCVESet(ctx)
	if err != nil {
		return 0, err
	}

	// Count CVE IDs from the defined list that are NOT in the applied set
	inactiveCount := 0
	for _, cveID := range definedCVEIDs {
		if !appliedCVEs[cveID] {
			inactiveCount++
		}
	}

	return inactiveCount, nil
}

// GetAppliedVEXCVEIDs returns the subset of provided CVE IDs that have been applied
// via VEX in at least one scan record.
func (s *SQLiteStore) GetAppliedVEXCVEIDs(ctx context.Context, definedCVEIDs []string) ([]string, error) {
	if len(definedCVEIDs) == 0 {
		return []string{}, nil
	}

	appliedCVEs, err := s.getAppliedCVESet(ctx)
	if err != nil {
		return nil, err
	}

	// Filter definedCVEIDs to only those that have been applied
	result := make([]string, 0)
	for _, cveID := range definedCVEIDs {
		if appliedCVEs[cveID] {
			result = append(result, cveID)
		}
	}

	return result, nil
}

// ListRepositories returns all repositories with aggregated metadata

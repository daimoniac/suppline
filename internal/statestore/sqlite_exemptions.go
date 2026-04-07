package statestore

import (
	"database/sql"
	"encoding/json"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
)

func decodeStoredExemptionsStrict(toleratedJSON, vexJSON sql.NullString) ([]types.AppliedVEXStatement, []types.ToleratedCVE, error) {
	if vexJSON.Valid && vexJSON.String != "" && vexJSON.String != "[]" {
		var vex []types.AppliedVEXStatement
		if err := json.Unmarshal([]byte(vexJSON.String), &vex); err != nil {
			return nil, nil, errors.NewTransientf("failed to unmarshal VEX statements: %w", err)
		}
		return vex, nil, nil
	}

	if toleratedJSON.Valid && toleratedJSON.String != "" {
		var tolerated []types.ToleratedCVE
		if err := json.Unmarshal([]byte(toleratedJSON.String), &tolerated); err != nil {
			return nil, nil, errors.NewTransientf("failed to unmarshal tolerated CVEs: %w", err)
		}
		return nil, tolerated, nil
	}

	return nil, nil, nil
}

func decodeStoredExemptionsLenient(toleratedJSON, vexJSON sql.NullString) ([]types.AppliedVEXStatement, []types.ToleratedCVE) {
	vex, tolerated, err := decodeStoredExemptionsStrict(toleratedJSON, vexJSON)
	if err != nil {
		return nil, nil
	}

	return vex, tolerated
}

func applyStoredExemptions(record *ScanRecord, toleratedJSON, vexJSON sql.NullString) error {
	vex, tolerated, err := decodeStoredExemptionsStrict(toleratedJSON, vexJSON)
	if err != nil {
		return err
	}

	if len(vex) > 0 {
		record.AppliedVEXStatements = vex
		return nil
	}

	if len(tolerated) > 0 {
		record.ToleratedCVEs = tolerated
	}

	return nil
}

func extractAppliedCVEIDs(toleratedJSON, vexJSON sql.NullString) []string {
	vex, tolerated := decodeStoredExemptionsLenient(toleratedJSON, vexJSON)

	ids := make([]string, 0)
	seen := make(map[string]struct{})
	for _, vs := range vex {
		if _, ok := seen[vs.CVEID]; ok {
			continue
		}
		seen[vs.CVEID] = struct{}{}
		ids = append(ids, vs.CVEID)
	}

	for _, tc := range tolerated {
		if _, ok := seen[tc.CVEID]; ok {
			continue
		}
		seen[tc.CVEID] = struct{}{}
		ids = append(ids, tc.CVEID)
	}

	return ids
}

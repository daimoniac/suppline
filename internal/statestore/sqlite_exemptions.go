package statestore

import (
	"database/sql"
	"encoding/json"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
)

func decodeStoredExemptionsStrict(vexJSON sql.NullString) ([]types.AppliedVEXStatement, error) {
	if !vexJSON.Valid || vexJSON.String == "" || vexJSON.String == "[]" {
		return nil, nil
	}

	var vex []types.AppliedVEXStatement
	if err := json.Unmarshal([]byte(vexJSON.String), &vex); err != nil {
		return nil, errors.NewTransientf("failed to unmarshal VEX statements: %w", err)
	}

	return vex, nil
}

func decodeStoredExemptionsLenient(vexJSON sql.NullString) []types.AppliedVEXStatement {
	vex, err := decodeStoredExemptionsStrict(vexJSON)
	if err != nil {
		return nil
	}

	return vex
}

func applyStoredExemptions(record *ScanRecord, vexJSON sql.NullString) error {
	vex, err := decodeStoredExemptionsStrict(vexJSON)
	if err != nil {
		return err
	}

	record.AppliedVEXStatements = vex

	return nil
}

func extractAppliedCVEIDs(vexJSON sql.NullString) []string {
	vex := decodeStoredExemptionsLenient(vexJSON)

	ids := make([]string, 0)
	seen := make(map[string]struct{})
	for _, vs := range vex {
		if _, ok := seen[vs.CVEID]; ok {
			continue
		}
		seen[vs.CVEID] = struct{}{}
		ids = append(ids, vs.CVEID)
	}

	return ids
}

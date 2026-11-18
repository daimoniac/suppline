package statestore

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/daimoniac/suppline/internal/errors"
	"github.com/daimoniac/suppline/internal/types"
)

// encodeMaliciousCheck returns the status column and JSON for a scan's
// malicious-package check. A nil check stores an empty status and NULL.
func encodeMaliciousCheck(check *types.MaliciousCheck) (string, sql.NullString, error) {
	if check == nil {
		return "", sql.NullString{}, nil
	}
	data, err := json.Marshal(check)
	if err != nil {
		return "", sql.NullString{}, errors.NewTransientf("failed to marshal malicious check: %w", err)
	}
	return check.Status, sql.NullString{String: string(data), Valid: true}, nil
}

func applyStoredMaliciousCheck(record *ScanRecord, data sql.NullString) error {
	if !data.Valid || data.String == "" {
		record.Malicious = nil
		return nil
	}
	var check types.MaliciousCheck
	if err := json.Unmarshal([]byte(data.String), &check); err != nil {
		return errors.NewTransientf("failed to decode stored malicious check: %w", err)
	}
	record.Malicious = &check
	return nil
}

// ReplacePackageInventory stores the language packages of an image digest,
// replacing what was recorded before. Rows are removed once no artifact
// references the digest any more.
func (s *SQLiteStore) ReplacePackageInventory(ctx context.Context, digest string, packages []types.PackageRef) error {
	if digest == "" {
		return errors.NewPermanentf("digest is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.NewTransientf("failed to begin package inventory transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM package_inventory WHERE digest = ?`, digest); err != nil {
		return errors.NewTransientf("failed to clear package inventory: %w", err)
	}
	seen := make(map[string]bool, len(packages))
	for _, pkg := range packages {
		if pkg.PURL == "" || seen[pkg.PURL] {
			continue
		}
		seen[pkg.PURL] = true
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO package_inventory (digest, ecosystem, name, version, purl) VALUES (?, ?, ?, ?, ?)
		`, digest, pkg.Ecosystem, pkg.Name, pkg.Version, pkg.PURL); err != nil {
			return errors.NewTransientf("failed to insert package inventory: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return errors.NewTransientf("failed to commit package inventory: %w", err)
	}
	return nil
}

// ListPackageInventory returns the packages recorded for a digest.
func (s *SQLiteStore) ListPackageInventory(ctx context.Context, digest string) ([]types.PackageRef, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT ecosystem, name, version, purl FROM package_inventory WHERE digest = ? ORDER BY purl
	`, digest)
	if err != nil {
		return nil, errors.NewTransientf("failed to query package inventory: %w", err)
	}
	defer rows.Close()
	var packages []types.PackageRef
	for rows.Next() {
		var pkg types.PackageRef
		if err := rows.Scan(&pkg.Ecosystem, &pkg.Name, &pkg.Version, &pkg.PURL); err != nil {
			return nil, errors.NewTransientf("failed to scan package inventory: %w", err)
		}
		packages = append(packages, pkg)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating package inventory: %w", err)
	}
	return packages, nil
}

// deleteOrphanedInventoryTx drops the inventory of each digest that no
// artifact references any more.
func deleteOrphanedInventoryTx(ctx context.Context, tx *Tx, digests ...string) error {
	for _, digest := range digests {
		if digest == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `
			DELETE FROM package_inventory
			WHERE digest = ? AND NOT EXISTS (SELECT 1 FROM artifacts WHERE digest = ?)
		`, digest, digest); err != nil {
			return errors.NewTransientf("failed to delete package inventory: %w", err)
		}
	}
	return nil
}

func repositoryDigestsTx(ctx context.Context, tx *Tx, repositoryID int64) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT digest FROM artifacts WHERE repository_id = ?`, repositoryID)
	if err != nil {
		return nil, errors.NewTransientf("failed to list repository digests: %w", err)
	}
	defer rows.Close()
	var digests []string
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, errors.NewTransientf("failed to scan repository digest: %w", err)
		}
		digests = append(digests, digest)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating repository digests: %w", err)
	}
	return digests, nil
}

package statestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
)

func nullableInt64(value int64) interface{} {
	if value <= 0 {
		return nil
	}
	return value
}

// RecordClusterInventory replaces the image inventory snapshot for a cluster.

func (s *SQLiteStore) RecordScan(ctx context.Context, record *ScanRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.NewTransientf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Create or get repository by name
	var repositoryID int64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM repositories WHERE name = ?
	`, record.Repository).Scan(&repositoryID)
	if err == sql.ErrNoRows {
		// Repository doesn't exist, create it
		result, err := tx.ExecContext(ctx, `
			INSERT INTO repositories (name) VALUES (?)
		`, record.Repository)
		if err != nil {
			return errors.NewTransientf("failed to insert repository: %w", err)
		}
		repositoryID, err = result.LastInsertId()
		if err != nil {
			return errors.NewTransientf("failed to get repository ID: %w", err)
		}
	} else if err != nil {
		return errors.NewTransientf("failed to query repository: %w", err)
	}

	// Create or update artifact
	nowUnix := time.Now().Unix()
	var artifactID int64
	var existingArtifactID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM artifacts WHERE repository_id = ? AND digest = ? AND tag = ?
	`, repositoryID, record.Digest, record.Tag).Scan(&existingArtifactID)
	if err == sql.ErrNoRows {
		// Artifact doesn't exist, create it
		result, err := tx.ExecContext(ctx, `
			INSERT INTO artifacts (repository_id, digest, tag, first_seen, last_seen, image_created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, repositoryID, record.Digest, record.Tag, nowUnix, nowUnix, nullableInt64(record.ImageCreatedAt))
		if err != nil {
			return errors.NewTransientf("failed to insert artifact: %w", err)
		}
		artifactID, err = result.LastInsertId()
		if err != nil {
			return errors.NewTransientf("failed to get artifact ID: %w", err)
		}
	} else if err != nil {
		return errors.NewTransientf("failed to query artifact: %w", err)
	} else {
		// Artifact exists, update last_seen
		artifactID = existingArtifactID.Int64
		_, err := tx.ExecContext(ctx, `
			UPDATE artifacts
			SET last_seen = ?, image_created_at = CASE
				WHEN image_created_at IS NULL AND ? IS NOT NULL THEN ?
				ELSE image_created_at
			END
			WHERE id = ?
		`, nowUnix, nullableInt64(record.ImageCreatedAt), nullableInt64(record.ImageCreatedAt), artifactID)
		if err != nil {
			return errors.NewTransientf("failed to update artifact: %w", err)
		}
	}

	// A tag can only point at one digest. Drop older (repo, tag, other digest) bindings
	// so ListScans / GetRepository stay aligned after retags.
	if err := pruneSupersededTagBindingsTx(ctx, tx, repositoryID, record.Digest, record.Tag); err != nil {
		return err
	}

	// Insert scan record with applied VEX statements as JSON.
	vexJSON := "[]"
	if len(record.AppliedVEXStatements) > 0 {
		jsonBytes, err := json.Marshal(record.AppliedVEXStatements)
		if err != nil {
			return errors.NewTransientf("failed to marshal VEX statements: %w", err)
		}
		vexJSON = string(jsonBytes)
	}
	failureFindingsJSON := "[]"
	if len(record.PolicyFailureFindings) > 0 {
		jsonBytes, err := json.Marshal(record.PolicyFailureFindings)
		if err != nil {
			return errors.NewTransientf("failed to marshal policy failure findings: %w", err)
		}
		failureFindingsJSON = string(jsonBytes)
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO scan_records (
			artifact_id, scan_duration_ms,
			critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count,
			policy_passed, policy_status, policy_reason, policy_failure_findings_json, release_age_seconds, minimum_release_age_seconds, release_age_source,
			sbom_attested, vuln_attested, scai_attested, vex_attested, error_message,
			vex_statements_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		artifactID, record.ScanDurationMs,
		record.CriticalVulnCount, record.HighVulnCount, record.MediumVulnCount, record.LowVulnCount,
		record.PolicyPassed, record.PolicyStatus, record.PolicyReason, failureFindingsJSON, record.ReleaseAgeSeconds, record.MinimumReleaseAgeSeconds, record.ReleaseAgeSource,
		record.SBOMAttested, record.VulnAttested, record.SCAIAttested, record.VEXAttested, record.ErrorMessage,
		vexJSON,
	)
	if err != nil {
		return errors.NewTransientf("failed to insert scan record: %w", err)
	}

	scanRecordID, err := result.LastInsertId()
	if err != nil {
		return errors.NewTransientf("failed to get scan record ID: %w", err)
	}

	// Update all artifacts for this repository and digest to point to the new scan
	// This ensures that all tags pointing to the same digest show the same policy result,
	// which is consistent with the watcher skipping scans for identical digests.
	_, err = tx.ExecContext(ctx, `
		UPDATE artifacts 
		SET last_scan_id = ?, next_scan_at = ? 
		WHERE repository_id = ? AND digest = ?
	`, scanRecordID, nowUnix, repositoryID, record.Digest)
	if err != nil {
		return errors.NewTransientf("failed to update artifact last_scan_id and next_scan_at: %w", err)
	}

	// Insert vulnerabilities linked to this scan record
	if len(record.Vulnerabilities) > 0 {
		vulnStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO vulnerabilities (
				scan_record_id, cve_id, severity, package_name,
				installed_version, fixed_version, title, description, primary_url
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			return errors.NewTransientf("failed to prepare vulnerability statement: %w", err)
		}
		defer vulnStmt.Close()

		for _, vuln := range record.Vulnerabilities {
			_, err := vulnStmt.ExecContext(ctx,
				scanRecordID, vuln.CVEID, vuln.Severity, vuln.PackageName,
				vuln.InstalledVersion, vuln.FixedVersion, vuln.Title, vuln.Description, vuln.PrimaryURL,
			)
			if err != nil {
				return errors.NewTransientf("failed to insert vulnerability: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.NewTransientf("failed to commit transaction: %w", err)
	}

	return nil
}

// pruneSupersededTagBindingsTx deletes older artifact rows for the same repository+tag
// that point at a different digest. Empty tags are left untouched.
func pruneSupersededTagBindingsTx(ctx context.Context, tx *sql.Tx, repositoryID int64, digest, tag string) error {
	if tag == "" {
		return nil
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM artifacts
		WHERE repository_id = ? AND tag = ? AND digest != ?
	`, repositoryID, tag, digest)
	if err != nil {
		return errors.NewTransientf("failed to query superseded tag bindings: %w", err)
	}
	defer rows.Close()

	var artifactIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return errors.NewTransientf("failed to scan superseded artifact id: %w", err)
		}
		artifactIDs = append(artifactIDs, id)
	}
	if err := rows.Err(); err != nil {
		return errors.NewTransientf("error iterating superseded artifacts: %w", err)
	}
	if len(artifactIDs) == 0 {
		return nil
	}

	for _, artifactID := range artifactIDs {
		if err := deleteArtifactWithScansTx(ctx, tx, artifactID); err != nil {
			return err
		}
	}

	return nil
}

// deleteArtifactWithScansTx removes one artifact and the scan records it owns,
// clearing last_scan_id references first so foreign keys stay valid.
func deleteArtifactWithScansTx(ctx context.Context, tx *sql.Tx, artifactID int64) error {
	scanRows, err := tx.QueryContext(ctx, `
		SELECT id FROM scan_records WHERE artifact_id = ?
	`, artifactID)
	if err != nil {
		return errors.NewTransientf("failed to query scan records for superseded artifact: %w", err)
	}
	defer scanRows.Close()

	var scanIDs []int64
	for scanRows.Next() {
		var scanID int64
		if err := scanRows.Scan(&scanID); err != nil {
			return errors.NewTransientf("failed to scan scan record id for superseded artifact: %w", err)
		}
		scanIDs = append(scanIDs, scanID)
	}
	if err := scanRows.Err(); err != nil {
		return errors.NewTransientf("error iterating scan records for superseded artifact: %w", err)
	}

	if len(scanIDs) > 0 {
		placeholders := make([]string, len(scanIDs))
		args := make([]interface{}, len(scanIDs))
		for i, scanID := range scanIDs {
			placeholders[i] = "?"
			args[i] = scanID
		}
		_, err = tx.ExecContext(ctx, fmt.Sprintf(`
			UPDATE artifacts SET last_scan_id = NULL WHERE last_scan_id IN (%s)
		`, strings.Join(placeholders, ",")), args...)
		if err != nil {
			return errors.NewTransientf("failed to clear last_scan_id for superseded artifact scans: %w", err)
		}
	}

	_, err = tx.ExecContext(ctx, `
		UPDATE artifacts SET last_scan_id = NULL WHERE id = ?
	`, artifactID)
	if err != nil {
		return errors.NewTransientf("failed to clear superseded artifact last_scan_id: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		DELETE FROM scan_records WHERE artifact_id = ?
	`, artifactID)
	if err != nil {
		return errors.NewTransientf("failed to delete superseded artifact scan records: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		DELETE FROM artifacts WHERE id = ?
	`, artifactID)
	if err != nil {
		return errors.NewTransientf("failed to delete superseded artifact: %w", err)
	}

	return nil
}

// GetLastScan retrieves the most recent scan for a digest with vulnerabilities

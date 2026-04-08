package statestore

import (
	"context"
	"database/sql"
	"encoding/json"
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

	// Insert scan record with applied VEX statements as JSON.
	vexJSON := "[]"
	if len(record.AppliedVEXStatements) > 0 {
		jsonBytes, err := json.Marshal(record.AppliedVEXStatements)
		if err != nil {
			return errors.NewTransientf("failed to marshal VEX statements: %w", err)
		}
		vexJSON = string(jsonBytes)
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO scan_records (
			artifact_id, scan_duration_ms,
			critical_vuln_count, high_vuln_count, medium_vuln_count, low_vuln_count,
			policy_passed, policy_status, policy_reason, release_age_seconds, minimum_release_age_seconds, release_age_source,
			sbom_attested, vuln_attested, scai_attested, vex_attested, error_message,
			vex_statements_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		artifactID, record.ScanDurationMs,
		record.CriticalVulnCount, record.HighVulnCount, record.MediumVulnCount, record.LowVulnCount,
		record.PolicyPassed, record.PolicyStatus, record.PolicyReason, record.ReleaseAgeSeconds, record.MinimumReleaseAgeSeconds, record.ReleaseAgeSource,
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

// GetLastScan retrieves the most recent scan for a digest with vulnerabilities

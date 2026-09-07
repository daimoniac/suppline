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
	if record == nil {
		return errors.NewPermanentf("scan record is required")
	}
	if record.Repository == "" || record.Digest == "" {
		return errors.NewPermanentf("repository and digest are required")
	}
	if record.Tag == "" {
		return errors.NewPermanentf("cannot record scan with empty tag for %s@%s", record.Repository, record.Digest)
	}

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
		repositoryID, err = s.insertReturningID(ctx, tx, `
			INSERT INTO repositories (name) VALUES (?)
		`, record.Repository)
		if err != nil {
			return errors.NewTransientf("failed to insert repository: %w", err)
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
		artifactID, err = s.insertReturningID(ctx, tx, `
			INSERT INTO artifacts (repository_id, digest, tag, first_seen, last_seen, image_created_at)
			VALUES (?, ?, ?, ?, ?, ?)
		`, repositoryID, record.Digest, record.Tag, nowUnix, nowUnix, nullableInt64(record.ImageCreatedAt))
		if err != nil {
			return errors.NewTransientf("failed to insert artifact: %w", err)
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

	scanRecordID, err := s.insertReturningID(ctx, tx, `
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

	// Store CVE metadata once, then keep only package/version occurrences per scan.
	if len(record.Vulnerabilities) > 0 {
		catalogStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO cve_catalog (cve_id, severity, title, description, primary_url)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(cve_id) DO UPDATE SET
				severity = excluded.severity,
				title = CASE WHEN excluded.title != '' THEN excluded.title ELSE cve_catalog.title END,
				description = CASE WHEN excluded.description != '' THEN excluded.description ELSE cve_catalog.description END,
				primary_url = CASE WHEN excluded.primary_url != '' THEN excluded.primary_url ELSE cve_catalog.primary_url END
		`)
		if err != nil {
			return errors.NewTransientf("failed to prepare CVE catalog statement: %w", err)
		}
		defer catalogStmt.Close()

		findingStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO scan_findings (
				scan_record_id, cve_id, package_name, installed_version, fixed_version
			) VALUES (?, ?, ?, ?, ?)
		`)
		if err != nil {
			return errors.NewTransientf("failed to prepare scan finding statement: %w", err)
		}
		defer findingStmt.Close()

		firstSeenStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO cve_first_seen (artifact_id, cve_id, first_seen_at)
			VALUES (?, ?, ?)
			ON CONFLICT(artifact_id, cve_id) DO NOTHING
		`)
		if err != nil {
			return errors.NewTransientf("failed to prepare CVE first-seen statement: %w", err)
		}
		defer firstSeenStmt.Close()

		for _, vuln := range record.Vulnerabilities {
			if _, err := catalogStmt.ExecContext(ctx,
				vuln.CVEID, vuln.Severity, vuln.Title, vuln.Description, vuln.PrimaryURL,
			); err != nil {
				return errors.NewTransientf("failed to upsert CVE catalog entry: %w", err)
			}
			if _, err := findingStmt.ExecContext(ctx,
				scanRecordID, vuln.CVEID, vuln.PackageName, vuln.InstalledVersion, vuln.FixedVersion,
			); err != nil {
				return errors.NewTransientf("failed to insert scan finding: %w", err)
			}
			if _, err := firstSeenStmt.ExecContext(ctx, artifactID, vuln.CVEID, nowUnix); err != nil {
				return errors.NewTransientf("failed to record CVE first-seen time: %w", err)
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
func pruneSupersededTagBindingsTx(ctx context.Context, tx *Tx, repositoryID int64, digest, tag string) error {
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

// deleteArtifactWithScansTx removes one artifact. Scan records still referenced as
// last_scan_id by sibling aliases are reassigned to a surviving artifact; only
// unreferenced scans owned by this artifact are deleted.
func deleteArtifactWithScansTx(ctx context.Context, tx *Tx, artifactID int64) error {
	return deleteArtifactPreservingSharedScansTx(ctx, tx, artifactID)
}

// deleteArtifactPreservingSharedScansTx removes one artifact binding while keeping
// scan results that sibling tags on the same digest still need.
func deleteArtifactPreservingSharedScansTx(ctx context.Context, tx *Tx, artifactID int64) error {
	_, err := tx.ExecContext(ctx, `
		UPDATE artifacts SET last_scan_id = NULL WHERE id = ?
	`, artifactID)
	if err != nil {
		return errors.NewTransientf("failed to clear artifact last_scan_id: %w", err)
	}

	scanRows, err := tx.QueryContext(ctx, `
		SELECT id FROM scan_records WHERE artifact_id = ?
	`, artifactID)
	if err != nil {
		return errors.NewTransientf("failed to query scan records for artifact deletion: %w", err)
	}

	var scanIDs []int64
	for scanRows.Next() {
		var scanID int64
		if err := scanRows.Scan(&scanID); err != nil {
			_ = scanRows.Close()
			return errors.NewTransientf("failed to scan scan record id for artifact deletion: %w", err)
		}
		scanIDs = append(scanIDs, scanID)
	}
	if err := scanRows.Err(); err != nil {
		_ = scanRows.Close()
		return errors.NewTransientf("error iterating scan records for artifact deletion: %w", err)
	}
	if err := scanRows.Close(); err != nil {
		return errors.NewTransientf("failed to close scan rows for artifact deletion: %w", err)
	}

	for _, scanID := range scanIDs {
		var siblingID sql.NullInt64
		err := tx.QueryRowContext(ctx, `
			SELECT id FROM artifacts WHERE last_scan_id = ? LIMIT 1
		`, scanID).Scan(&siblingID)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return errors.NewTransientf("failed to find sibling for shared scan %d: %w", scanID, err)
		}
		_, err = tx.ExecContext(ctx, `
			UPDATE scan_records SET artifact_id = ? WHERE id = ?
		`, siblingID.Int64, scanID)
		if err != nil {
			return errors.NewTransientf("failed to reassign shared scan %d to sibling: %w", scanID, err)
		}
	}

	_, err = tx.ExecContext(ctx, `
		DELETE FROM scan_records WHERE artifact_id = ?
	`, artifactID)
	if err != nil {
		return errors.NewTransientf("failed to delete unreferenced scan records for artifact: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		DELETE FROM artifacts WHERE id = ?
	`, artifactID)
	if err != nil {
		return errors.NewTransientf("failed to delete artifact: %w", err)
	}

	return nil
}

// EnsureArtifactTagBinding ensures a (repository, digest, tag) artifact exists when the
// digest already has a scan via a sibling tag. Alias tags inherit last_scan_id so they
// appear in repository listings without a redundant rescan.
func (s *SQLiteStore) EnsureArtifactTagBinding(ctx context.Context, repository, digest, tag string) (bool, error) {
	if repository == "" || digest == "" {
		return false, errors.NewPermanentf("repository and digest are required")
	}
	if tag == "" {
		// Untagged artifacts are not part of the registry tag model.
		return false, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, errors.NewTransientf("failed to begin tag binding transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var repositoryID int64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM repositories WHERE name = ?
	`, repository).Scan(&repositoryID)
	if err == sql.ErrNoRows {
		// No repository yet means no sibling scan exists to inherit from.
		return false, nil
	}
	if err != nil {
		return false, errors.NewTransientf("failed to query repository for tag binding: %w", err)
	}

	nowUnix := time.Now().Unix()
	var existingID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT id FROM artifacts WHERE repository_id = ? AND digest = ? AND tag = ?
	`, repositoryID, digest, tag).Scan(&existingID)
	if err == nil {
		_, err = tx.ExecContext(ctx, `
			UPDATE artifacts SET last_seen = ? WHERE id = ?
		`, nowUnix, existingID.Int64)
		if err != nil {
			return false, errors.NewTransientf("failed to touch artifact last_seen: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return false, errors.NewTransientf("failed to commit tag binding touch: %w", err)
		}
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, errors.NewTransientf("failed to query artifact for tag binding: %w", err)
	}

	var lastScanID sql.NullInt64
	var nextScanAt sql.NullInt64
	var imageCreatedAt sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT last_scan_id, next_scan_at, image_created_at
		FROM artifacts
		WHERE repository_id = ? AND digest = ? AND last_scan_id IS NOT NULL
		ORDER BY id DESC
		LIMIT 1
	`, repositoryID, digest).Scan(&lastScanID, &nextScanAt, &imageCreatedAt)
	if err == sql.ErrNoRows {
		// Digest has not been scanned in this repository yet; RecordScan will create the binding.
		return false, nil
	}
	if err != nil {
		return false, errors.NewTransientf("failed to load sibling artifact for tag binding: %w", err)
	}

	if _, err := s.insertReturningID(ctx, tx, `
		INSERT INTO artifacts (repository_id, digest, tag, first_seen, last_seen, image_created_at, last_scan_id, next_scan_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, repositoryID, digest, tag, nowUnix, nowUnix, imageCreatedAt, lastScanID, nextScanAt); err != nil {
		return false, errors.NewTransientf("failed to insert alias artifact tag binding: %w", err)
	}

	if err := pruneSupersededTagBindingsTx(ctx, tx, repositoryID, digest, tag); err != nil {
		return false, err
	}

	if err := tx.Commit(); err != nil {
		return false, errors.NewTransientf("failed to commit alias tag binding: %w", err)
	}
	return true, nil
}

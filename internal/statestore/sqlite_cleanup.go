package statestore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/daimoniac/suppline/internal/errors"
)

func (s *SQLiteStore) CleanupArtifactScans(ctx context.Context, digest string) error {
	return s.executeCleanup(ctx, func(tx *sql.Tx) error {
		// First, get all artifact IDs and repository IDs for this digest
		rows, err := tx.QueryContext(ctx, `
			SELECT a.id, a.repository_id 
			FROM artifacts a 
			WHERE a.digest = ?
		`, digest)
		if err != nil {
			return errors.NewTransientf("failed to query artifacts for cleanup: %w", err)
		}
		defer rows.Close()

		type artifactInfo struct {
			id           int64
			repositoryID int64
		}
		var artifacts []artifactInfo
		for rows.Next() {
			var info artifactInfo
			if err := rows.Scan(&info.id, &info.repositoryID); err != nil {
				return errors.NewTransientf("failed to scan artifact info: %w", err)
			}
			artifacts = append(artifacts, info)
		}
		if err := rows.Err(); err != nil {
			return errors.NewTransientf("error iterating artifact rows: %w", err)
		}

		if len(artifacts) == 0 {
			// No artifacts exist for this digest, nothing to clean up
			return nil
		}

		// Collect unique repository IDs for later cleanup check
		repositoryIDs := make(map[int64]bool)
		for _, a := range artifacts {
			repositoryIDs[a.repositoryID] = true
		}

		// Clear last_scan_id references for all artifacts with this digest
		_, err = tx.ExecContext(ctx, `
			UPDATE artifacts SET last_scan_id = NULL WHERE digest = ?
		`, digest)
		if err != nil {
			return errors.NewTransientf("failed to clear last_scan_id references: %w", err)
		}

		// Delete all scan records for all artifacts with this digest
		for _, artifact := range artifacts {
			_, err = tx.ExecContext(ctx, `
				DELETE FROM scan_records WHERE artifact_id = ?
			`, artifact.id)
			if err != nil {
				return errors.NewTransientf("failed to delete scan records: %w", err)
			}
		}

		// Delete all artifacts with this digest
		_, err = tx.ExecContext(ctx, `
			DELETE FROM artifacts WHERE digest = ?
		`, digest)
		if err != nil {
			return errors.NewTransientf("failed to delete artifacts: %w", err)
		}

		// Check each affected repository for remaining artifacts and clean up if empty
		for repositoryID := range repositoryIDs {
			var remainingArtifacts int
			err = tx.QueryRowContext(ctx, `
				SELECT COUNT(*) FROM artifacts WHERE repository_id = ?
			`, repositoryID).Scan(&remainingArtifacts)
			if err != nil {
				return errors.NewTransientf("failed to count remaining artifacts: %w", err)
			}

			// If no artifacts remain, delete the repository
			if remainingArtifacts == 0 {
				_, err = tx.ExecContext(ctx, `
					DELETE FROM repositories WHERE id = ?
				`, repositoryID)
				if err != nil {
					return errors.NewTransientf("failed to delete empty repository: %w", err)
				}
			}
		}

		return nil
	})
}

// executeCleanup is a helper method for transaction management in cleanup operations
func (s *SQLiteStore) executeCleanup(ctx context.Context, operation func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.NewTransientf("failed to begin cleanup transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := operation(tx); err != nil {
		return err // Error already classified by operation
	}

	if err := tx.Commit(); err != nil {
		return errors.NewTransientf("failed to commit cleanup transaction: %w", err)
	}

	return nil
}

// CleanupOrphanedRepositories removes repositories with no remaining artifacts.
// Returns a list of deleted repository names for logging purposes.
func (s *SQLiteStore) CleanupOrphanedRepositories(ctx context.Context) ([]string, error) {
	var deletedRepos []string

	err := s.executeCleanup(ctx, func(tx *sql.Tx) error {
		// Find repositories with no artifacts.
		rows, err := tx.QueryContext(ctx, `
			SELECT r.id, r.name 
			FROM repositories r 
			LEFT JOIN artifacts a ON r.id = a.repository_id 
			WHERE a.id IS NULL
		`)
		if err != nil {
			return errors.NewTransientf("failed to query orphaned repositories: %w", err)
		}
		defer rows.Close()

		var repoIDs []int64
		for rows.Next() {
			var repoID int64
			var repoName string
			if err := rows.Scan(&repoID, &repoName); err != nil {
				return errors.NewTransientf("failed to scan orphaned repository: %w", err)
			}
			repoIDs = append(repoIDs, repoID)
			deletedRepos = append(deletedRepos, repoName)
		}

		if err := rows.Err(); err != nil {
			return errors.NewTransientf("error iterating orphaned repositories: %w", err)
		}

		// Delete the orphaned repositories
		for _, repoID := range repoIDs {
			_, err := tx.ExecContext(ctx, `
				DELETE FROM repositories WHERE id = ?
			`, repoID)
			if err != nil {
				return errors.NewTransientf("failed to delete orphaned repository: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return deletedRepos, nil
}

// CleanupExcessScans removes excess scan records for all artifacts with the given digest, keeping only the most recent N scans per artifact.
// This provides a more robust cleanup that handles concurrent scans and ensures a maximum number of scans per artifact.
// Note: Multiple tags may point to the same digest, and each gets its own scan cleanup.
func (s *SQLiteStore) CleanupExcessScans(ctx context.Context, digest string, maxScansToKeep int) error {
	if maxScansToKeep <= 0 {
		return errors.NewPermanentf("maxScansToKeep must be positive, got %d", maxScansToKeep)
	}

	return s.executeCleanup(ctx, func(tx *sql.Tx) error {
		// Get all artifact IDs for this digest
		rows, err := tx.QueryContext(ctx, `
			SELECT id FROM artifacts WHERE digest = ?
		`, digest)
		if err != nil {
			return errors.NewTransientf("failed to query artifacts for cleanup: %w", err)
		}
		defer rows.Close()

		var artifactIDs []int64
		for rows.Next() {
			var artifactID int64
			if err := rows.Scan(&artifactID); err != nil {
				return errors.NewTransientf("failed to scan artifact ID: %w", err)
			}
			artifactIDs = append(artifactIDs, artifactID)
		}
		if err := rows.Err(); err != nil {
			return errors.NewTransientf("error iterating artifact rows: %w", err)
		}

		if len(artifactIDs) == 0 {
			// No artifacts exist for this digest, nothing to clean up
			return nil
		}

		// Clean up excess scans for each artifact
		for _, artifactID := range artifactIDs {
			if err := s.cleanupExcessScansForArtifact(tx, ctx, artifactID, maxScansToKeep); err != nil {
				return err
			}
		}

		return nil
	})
}

// cleanupExcessScansForArtifact is a helper to clean up scans for a single artifact
func (s *SQLiteStore) cleanupExcessScansForArtifact(tx *sql.Tx, ctx context.Context, artifactID int64, maxScansToKeep int) error {
	// Get scan IDs to keep (most recent N scans)
	rows, err := tx.QueryContext(ctx, `
		SELECT id FROM scan_records 
		WHERE artifact_id = ? 
		ORDER BY created_at DESC, id DESC 
		LIMIT ?
	`, artifactID, maxScansToKeep)
	if err != nil {
		return errors.NewTransientf("failed to query scans to keep: %w", err)
	}
	defer rows.Close()

	var keepScanIDs []int64
	for rows.Next() {
		var scanID int64
		if err := rows.Scan(&scanID); err != nil {
			return errors.NewTransientf("failed to scan keep scan ID: %w", err)
		}
		keepScanIDs = append(keepScanIDs, scanID)
	}

	if err := rows.Err(); err != nil {
		return errors.NewTransientf("error iterating keep scan IDs: %w", err)
	}

	// If we have fewer scans than the limit, nothing to clean up
	if len(keepScanIDs) < maxScansToKeep {
		return nil
	}

	// Build placeholders for the IN clause
	placeholders := make([]string, len(keepScanIDs))
	args := make([]interface{}, len(keepScanIDs)+1)
	args[0] = artifactID
	for i, scanID := range keepScanIDs {
		placeholders[i] = "?"
		args[i+1] = scanID
	}

	// Delete scan records not in the keep list
	deleteQuery := fmt.Sprintf(`
		DELETE FROM scan_records 
		WHERE artifact_id = ? AND id NOT IN (%s)
	`, strings.Join(placeholders, ","))

	result, err := tx.ExecContext(ctx, deleteQuery, args...)
	if err != nil {
		return errors.NewTransientf("failed to delete excess scan records: %w", err)
	}

	deletedCount, err := result.RowsAffected()
	if err != nil {
		return errors.NewTransientf("failed to get deleted rows count: %w", err)
	}

	if deletedCount > 0 {
		// Update artifact's last_scan_id to point to the most recent remaining scan
		if len(keepScanIDs) > 0 {
			_, err = tx.ExecContext(ctx, `
				UPDATE artifacts 
				SET last_scan_id = ?
				WHERE id = ?
			`, keepScanIDs[0], artifactID) // keepScanIDs[0] is the most recent
			if err != nil {
				return errors.NewTransientf("failed to update artifact last_scan_id: %w", err)
			}
		}
	}

	return nil
}

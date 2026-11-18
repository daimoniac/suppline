package statestore

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"strings"

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

// InventoryPackage is a stored package together with the digest it belongs to.
type InventoryPackage struct {
	Digest  string
	Package types.PackageRef
}

// ListInventoryByPackage returns every stored package with the given
// ecosystem and (normalised) name, across all digests.
func (s *SQLiteStore) ListInventoryByPackage(ctx context.Context, ecosystem, name string) ([]InventoryPackage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT digest, ecosystem, name, version, purl FROM package_inventory
		WHERE ecosystem = ? AND name = ?
		ORDER BY digest, purl
	`, ecosystem, name)
	if err != nil {
		return nil, errors.NewTransientf("failed to query package inventory by package: %w", err)
	}
	defer rows.Close()
	var out []InventoryPackage
	for rows.Next() {
		var row InventoryPackage
		if err := rows.Scan(&row.Digest, &row.Package.Ecosystem, &row.Package.Name, &row.Package.Version, &row.Package.PURL); err != nil {
			return nil, errors.NewTransientf("failed to scan package inventory: %w", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating package inventory: %w", err)
	}
	return out, nil
}

// ListInventoryDigests returns every digest that has a stored inventory.
func (s *SQLiteStore) ListInventoryDigests(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT digest FROM package_inventory ORDER BY digest`)
	if err != nil {
		return nil, errors.NewTransientf("failed to list inventory digests: %w", err)
	}
	defer rows.Close()
	var digests []string
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, errors.NewTransientf("failed to scan inventory digest: %w", err)
		}
		digests = append(digests, digest)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating inventory digests: %w", err)
	}
	return digests, nil
}

// DigestScan is the latest scan of a digest within one repository.
type DigestScan struct {
	ScanID     int64
	Repository string
	Digest     string
	Tag        string
	Malicious  *types.MaliciousCheck
}

// ListLatestDigestScans returns, for each repository holding the digest, its
// latest scan and one tag to rescan it under.
func (s *SQLiteStore) ListLatestDigestScans(ctx context.Context, digest string) ([]DigestScan, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT sr.id, r.name, a.digest, COALESCE(MIN(a.tag), ''), sr.malicious_check_json
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		JOIN scan_records sr ON sr.id = a.last_scan_id
		WHERE a.digest = ?
		GROUP BY sr.id, r.name, a.digest, sr.malicious_check_json
		ORDER BY r.name
	`, digest)
	if err != nil {
		return nil, errors.NewTransientf("failed to query latest digest scans: %w", err)
	}
	defer rows.Close()
	var out []DigestScan
	for rows.Next() {
		var scan DigestScan
		var maliciousJSON sql.NullString
		if err := rows.Scan(&scan.ScanID, &scan.Repository, &scan.Digest, &scan.Tag, &maliciousJSON); err != nil {
			return nil, errors.NewTransientf("failed to scan latest digest scan: %w", err)
		}
		var record ScanRecord
		if err := applyStoredMaliciousCheck(&record, maliciousJSON); err != nil {
			return nil, err
		}
		scan.Malicious = record.Malicious
		out = append(out, scan)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating latest digest scans: %w", err)
	}
	return out, nil
}

// UpdateMaliciousCheck replaces the malicious-package check stored on a scan.
// It is used when a late re-match confirms an image that was scanned while the
// check was unavailable or stale; the signed attestation is not changed.
func (s *SQLiteStore) UpdateMaliciousCheck(ctx context.Context, scanID int64, check *types.MaliciousCheck) error {
	status, data, err := encodeMaliciousCheck(check)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE scan_records SET malicious_status = ?, malicious_check_json = ? WHERE id = ?
	`, status, data, scanID); err != nil {
		return errors.NewTransientf("failed to update malicious check: %w", err)
	}
	return nil
}

// MaliciousImage is a current image (repository and digest) whose latest scan
// recorded malicious-package findings.
type MaliciousImage struct {
	Repository   string
	Digest       string
	Tags         []string
	ScanID       int64
	ScannedAt    int64
	PolicyPassed bool
	PolicyStatus string
	RuntimeUsed  bool
	Runtime      RuntimeInventory
	Check        types.MaliciousCheck
}

// MaliciousCoverage counts current images by the status of their latest
// malicious-package check. Unchecked images were scanned before the check
// existed or while it was disabled.
type MaliciousCoverage struct {
	OK          int
	Unavailable int
	Stale       int
	Unchecked   int
}

// ListMaliciousImages returns every current image whose latest scan found
// malicious packages, in-use images first, and how many current images each
// check status covers.
func (s *SQLiteStore) ListMaliciousImages(ctx context.Context) ([]MaliciousImage, MaliciousCoverage, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.name, a.digest, COALESCE(a.tag, ''), sr.id, sr.created_at, sr.policy_passed, sr.policy_status,
			sr.malicious_status, sr.malicious_check_json
		FROM artifacts a
		JOIN repositories r ON a.repository_id = r.id
		JOIN scan_records sr ON sr.id = a.last_scan_id
		ORDER BY r.name, a.digest, a.tag
	`)
	if err != nil {
		return nil, MaliciousCoverage{}, errors.NewTransientf("failed to query malicious images: %w", err)
	}
	defer rows.Close()

	type imageKey struct{ repository, digest string }
	var coverage MaliciousCoverage
	byKey := make(map[imageKey]*MaliciousImage)
	var order []imageKey
	counted := make(map[imageKey]bool)
	for rows.Next() {
		var repository, digest, tag, policyStatus, status string
		var scanID, scannedAt int64
		var policyPassed bool
		var checkJSON sql.NullString
		if err := rows.Scan(&repository, &digest, &tag, &scanID, &scannedAt, &policyPassed, &policyStatus, &status, &checkJSON); err != nil {
			return nil, MaliciousCoverage{}, errors.NewTransientf("failed to scan malicious image: %w", err)
		}
		key := imageKey{repository, digest}
		if !counted[key] {
			counted[key] = true
			switch status {
			case types.MaliciousCheckOK:
				coverage.OK++
			case types.MaliciousCheckUnavailable:
				coverage.Unavailable++
			case types.MaliciousCheckStale:
				coverage.Stale++
			default:
				coverage.Unchecked++
			}
		}
		if image, ok := byKey[key]; ok {
			if tag != "" {
				image.Tags = append(image.Tags, tag)
			}
			continue
		}
		var record ScanRecord
		if err := applyStoredMaliciousCheck(&record, checkJSON); err != nil {
			return nil, MaliciousCoverage{}, err
		}
		if record.Malicious == nil || len(record.Malicious.Findings) == 0 {
			continue
		}
		image := &MaliciousImage{
			Repository: repository, Digest: digest, ScanID: scanID, ScannedAt: scannedAt,
			PolicyPassed: policyPassed, PolicyStatus: policyStatus, Check: *record.Malicious,
		}
		if tag != "" {
			image.Tags = []string{tag}
		}
		byKey[key] = image
		order = append(order, key)
	}
	if err := rows.Err(); err != nil {
		return nil, MaliciousCoverage{}, errors.NewTransientf("error iterating malicious images: %w", err)
	}

	images := make([]MaliciousImage, 0, len(order))
	digests := make([]string, 0, len(order))
	for _, key := range order {
		images = append(images, *byKey[key])
		digests = append(digests, key.digest)
	}
	if len(digests) > 0 {
		usage, err := s.queryRuntimeUsageByDigests(ctx, digests)
		if err != nil {
			return nil, MaliciousCoverage{}, err
		}
		for i := range images {
			used, u := runtimeUseForDigest(usage, images[i].Digest)
			images[i].RuntimeUsed = used
			if used {
				images[i].Runtime = u.Runtime
			}
		}
	}
	sort.SliceStable(images, func(i, j int) bool {
		return images[i].RuntimeUsed && !images[j].RuntimeUsed
	})
	return images, coverage, nil
}

// ListDigestsWithMaliciousStatus returns the digests whose latest scan (in any
// repository) recorded one of the given malicious-check statuses.
func (s *SQLiteStore) ListDigestsWithMaliciousStatus(ctx context.Context, statuses ...string) ([]string, error) {
	if len(statuses) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",")
	args := make([]any, 0, len(statuses))
	for _, status := range statuses {
		args = append(args, status)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT a.digest
		FROM artifacts a
		JOIN scan_records sr ON sr.id = a.last_scan_id
		WHERE sr.malicious_status IN (`+placeholders+`)
		ORDER BY a.digest
	`, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to list digests by malicious status: %w", err)
	}
	defer rows.Close()
	var digests []string
	for rows.Next() {
		var digest string
		if err := rows.Scan(&digest); err != nil {
			return nil, errors.NewTransientf("failed to scan digest: %w", err)
		}
		digests = append(digests, digest)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating digests: %w", err)
	}
	return digests, nil
}

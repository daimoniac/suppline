package statestore

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
)

func (s *SQLiteStore) InsertTriageRun(ctx context.Context, run *TriageRun) error {
	if run == nil {
		return errors.NewPermanentf("triage run is nil")
	}
	created := run.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO triage_runs (
			repository, cve_id, verdict, justification, confidence, evidence_json, reasoning,
			model, repo_shas_json, cve_hash, tokens, status, commit_sha, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, run.Repository, run.CVEID, run.Verdict, run.Justification, run.Confidence, run.EvidenceJSON, run.Reasoning,
		run.Model, run.RepoSHAsJSON, run.CVEHash, run.Tokens, run.Status, run.CommitSHA, created.Unix())
	if err != nil {
		return errors.NewTransientf("insert triage run: %w", err)
	}
	return nil
}

func (s *SQLiteStore) LatestTriageRun(ctx context.Context, repository, cveID string) (*TriageRun, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, repository, cve_id, verdict, justification, confidence, evidence_json, reasoning,
			model, repo_shas_json, cve_hash, tokens, status, commit_sha, created_at
		FROM triage_runs
		WHERE repository = ? AND cve_id = ?
		ORDER BY created_at DESC, id DESC
		LIMIT 1
	`, repository, cveID)
	run, err := scanTriageRun(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.NewTransientf("latest triage run: %w", err)
	}
	return run, nil
}

func (s *SQLiteStore) ListTriageRuns(ctx context.Context, filter TriageFilter) ([]TriageRun, error) {
	var where []string
	var args []any
	if filter.Repository != "" {
		where = append(where, "repository = ?")
		args = append(args, filter.Repository)
	}
	if filter.CVEID != "" {
		where = append(where, "cve_id = ?")
		args = append(args, filter.CVEID)
	}
	if filter.Status != "" {
		where = append(where, "status = ?")
		args = append(args, filter.Status)
	}
	query := `
		SELECT id, repository, cve_id, verdict, justification, confidence, evidence_json, reasoning,
			model, repo_shas_json, cve_hash, tokens, status, commit_sha, created_at
		FROM triage_runs`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC, id DESC"
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	query += " LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("list triage runs: %w", err)
	}
	defer rows.Close()
	var runs []TriageRun
	for rows.Next() {
		run, err := scanTriageRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, *run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return runs, nil
}

func (s *SQLiteStore) TriageTokensSince(ctx context.Context, since time.Time) (int, error) {
	var total int
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(tokens), 0) FROM triage_runs WHERE created_at >= ?`, since.Unix()).Scan(&total)
	if err != nil {
		return 0, errors.NewTransientf("sum triage tokens: %w", err)
	}
	return total, nil
}

type triageScanner interface {
	Scan(dest ...any) error
}

func scanTriageRun(row triageScanner) (*TriageRun, error) {
	var run TriageRun
	var created int64
	err := row.Scan(
		&run.ID, &run.Repository, &run.CVEID, &run.Verdict, &run.Justification, &run.Confidence,
		&run.EvidenceJSON, &run.Reasoning, &run.Model, &run.RepoSHAsJSON, &run.CVEHash,
		&run.Tokens, &run.Status, &run.CommitSHA, &created,
	)
	if err != nil {
		return nil, err
	}
	run.CreatedAt = time.Unix(created, 0).UTC()
	return &run, nil
}

package statestore

import (
	"context"
	"database/sql"
	"sort"
	"strings"

	"github.com/daimoniac/suppline/internal/errors"
)

// KEVImage is a current image whose latest scan has at least one CVE from
// the CISA KEV catalog that no VEX statement exempted.
type KEVImage struct {
	Repository   string
	Digest       string
	Tags         []string
	PolicyPassed bool
	RuntimeUsed  bool
	CVEs         []string // the unexempted KEV CVEs, sorted
}

// kevQueryChunk bounds the IN list per query; PostgreSQL allows 65535
// parameters and the catalog has a few thousand entries.
const kevQueryChunk = 5000

// ListKEVImages returns every current image whose latest scan has a CVE in
// kevIDs that the scan's applied VEX statements did not exempt, in-use images
// first. A nil or empty kevIDs returns none.
func (s *Store) ListKEVImages(ctx context.Context, kevIDs []string) ([]KEVImage, error) {
	type imageKey struct{ repository, digest string }
	byKey := map[imageKey]*KEVImage{}
	cves := map[imageKey]map[string]struct{}{}
	tags := map[imageKey]map[string]struct{}{}

	for start := 0; start < len(kevIDs); start += kevQueryChunk {
		chunk := kevIDs[start:min(start+kevQueryChunk, len(kevIDs))]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}
		rows, err := s.db.QueryContext(ctx, `
			SELECT r.name, a.digest, COALESCE(a.tag, ''), sr.policy_passed, sr.vex_statements_json, f.cve_id
			FROM artifacts a
			JOIN repositories r ON a.repository_id = r.id
			JOIN scan_records sr ON sr.id = a.last_scan_id
			JOIN scan_findings f ON f.scan_record_id = sr.id
			WHERE f.cve_id IN (`+placeholders+`)
		`, args...)
		if err != nil {
			return nil, errors.NewTransientf("failed to query KEV images: %w", err)
		}
		for rows.Next() {
			var repository, digest, tag, cve string
			var passed bool
			var vexJSON sql.NullString
			if err := rows.Scan(&repository, &digest, &tag, &passed, &vexJSON, &cve); err != nil {
				rows.Close()
				return nil, errors.NewTransientf("failed to scan KEV image: %w", err)
			}
			exempted := false
			for _, id := range extractAppliedCVEIDs(vexJSON) {
				if id == cve {
					exempted = true
					break
				}
			}
			if exempted {
				continue
			}
			key := imageKey{repository, digest}
			if _, ok := byKey[key]; !ok {
				byKey[key] = &KEVImage{Repository: repository, Digest: digest, PolicyPassed: passed}
				cves[key] = map[string]struct{}{}
				tags[key] = map[string]struct{}{}
			}
			cves[key][cve] = struct{}{}
			if tag != "" {
				tags[key][tag] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, errors.NewTransientf("error iterating KEV images: %w", err)
		}
		rows.Close()
	}

	images := make([]KEVImage, 0, len(byKey))
	digests := make([]string, 0, len(byKey))
	for key, image := range byKey {
		image.CVEs = sortedKeys(cves[key])
		image.Tags = sortedKeys(tags[key])
		images = append(images, *image)
		digests = append(digests, key.digest)
	}
	if len(digests) > 0 {
		usage, err := s.queryRuntimeUsageByDigests(ctx, digests)
		if err != nil {
			return nil, err
		}
		for i := range images {
			images[i].RuntimeUsed, _ = runtimeUseForDigest(usage, images[i].Digest)
		}
	}
	sort.Slice(images, func(i, j int) bool {
		if images[i].RuntimeUsed != images[j].RuntimeUsed {
			return images[i].RuntimeUsed
		}
		if images[i].Repository != images[j].Repository {
			return images[i].Repository < images[j].Repository
		}
		return images[i].Digest < images[j].Digest
	})
	return images, nil
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

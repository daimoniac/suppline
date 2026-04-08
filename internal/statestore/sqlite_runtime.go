package statestore

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/errors"
)

func (s *SQLiteStore) RecordClusterInventory(ctx context.Context, clusterName string, images []ClusterImageEntry, reportedAt time.Time) error {
	clusterName = strings.TrimSpace(clusterName)
	if clusterName == "" {
		return errors.NewPermanentf("cluster name cannot be empty")
	}

	normalizedImages := normalizeClusterInventoryEntries(images)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return errors.NewTransientf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	reportedAtUnix := reportedAt.UTC().Unix()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO clusters (name, last_reported_at)
		VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET last_reported_at = excluded.last_reported_at
	`, clusterName, reportedAtUnix); err != nil {
		return errors.NewTransientf("failed to upsert cluster: %w", err)
	}

	var clusterID int64
	if err := tx.QueryRowContext(ctx, `
		SELECT id FROM clusters WHERE name = ?
	`, clusterName).Scan(&clusterID); err != nil {
		return errors.NewTransientf("failed to query cluster id: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM cluster_images WHERE cluster_id = ?
	`, clusterID); err != nil {
		return errors.NewTransientf("failed to clear previous cluster inventory: %w", err)
	}

	insertStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO cluster_images (cluster_id, namespace, image_ref, tag, digest, reported_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return errors.NewTransientf("failed to prepare cluster image insert: %w", err)
	}
	defer insertStmt.Close()

	seenStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO cluster_images_seen (cluster_id, namespace, image_ref, tag, digest, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(cluster_id, namespace, image_ref, tag, digest)
		DO UPDATE SET last_seen_at = excluded.last_seen_at
	`)
	if err != nil {
		return errors.NewTransientf("failed to prepare cluster image seen upsert: %w", err)
	}
	defer seenStmt.Close()

	for _, image := range normalizedImages {
		namespace := strings.TrimSpace(image.Namespace)
		imageRef := strings.TrimSpace(image.ImageRef)
		tag := strings.TrimSpace(image.Tag)
		digest := strings.TrimSpace(image.Digest)

		if _, err := seenStmt.ExecContext(
			ctx,
			clusterID,
			namespace,
			imageRef,
			tag,
			digest,
			reportedAtUnix,
			reportedAtUnix,
		); err != nil {
			return errors.NewTransientf("failed to upsert cluster image seen row: %w", err)
		}

		if _, err := insertStmt.ExecContext(
			ctx,
			clusterID,
			namespace,
			imageRef,
			tag,
			digest,
			reportedAtUnix,
		); err != nil {
			return errors.NewTransientf("failed to insert cluster image: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return errors.NewTransientf("failed to commit cluster inventory transaction: %w", err)
	}

	return nil
}

func (s *SQLiteStore) runtimeInUseCutoffUnix() int64 {
	window := s.runtimeInUseWindow
	if window <= 0 {
		window = defaultRuntimeInUseWindow
	}

	return time.Now().UTC().Add(-window).Unix()
}

// normalizeClusterInventoryEntries keeps distinct digest variants, but removes
// digest-less duplicates when any digest was observed for the same
// namespace/image_ref/tag tuple.
func normalizeClusterInventoryEntries(images []ClusterImageEntry) []ClusterImageEntry {
	if len(images) == 0 {
		return nil
	}

	groups := make(map[clusterImageIdentity]*normalizedClusterImageGroup)
	order := make([]clusterImageIdentity, 0, len(images))

	for _, image := range images {
		namespace := strings.TrimSpace(image.Namespace)
		imageRef := strings.TrimSpace(image.ImageRef)
		tag := strings.TrimSpace(image.Tag)
		digest := strings.TrimSpace(image.Digest)

		id := clusterImageIdentity{namespace: namespace, imageRef: imageRef, tag: tag}
		group, ok := groups[id]
		if !ok {
			group = &normalizedClusterImageGroup{
				identity:   id,
				digests:    make([]string, 0, 1),
				digestSeen: make(map[string]struct{}),
			}
			groups[id] = group
			order = append(order, id)
		}

		if digest == "" {
			group.hasEmpty = true
			continue
		}

		if _, exists := group.digestSeen[digest]; exists {
			continue
		}
		group.digestSeen[digest] = struct{}{}
		group.digests = append(group.digests, digest)
	}

	result := make([]ClusterImageEntry, 0, len(images))
	for _, id := range order {
		group := groups[id]
		if len(group.digests) > 0 {
			for _, digest := range group.digests {
				result = append(result, ClusterImageEntry{
					Namespace: id.namespace,
					ImageRef:  id.imageRef,
					Tag:       id.tag,
					Digest:    digest,
				})
			}
			continue
		}

		if group.hasEmpty {
			result = append(result, ClusterImageEntry{
				Namespace: id.namespace,
				ImageRef:  id.imageRef,
				Tag:       id.tag,
				Digest:    "",
			})
		}
	}

	return result
}

// ListClusterSummaries returns one summary row per cluster.
func (s *SQLiteStore) ListClusterSummaries(ctx context.Context) ([]ClusterSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT c.name, c.last_reported_at, COUNT(ci.id) AS image_count
		FROM clusters c
		LEFT JOIN cluster_images ci ON ci.cluster_id = c.id
		GROUP BY c.id, c.name, c.last_reported_at
		ORDER BY c.name ASC
	`)
	if err != nil {
		return nil, errors.NewTransientf("failed to query cluster summaries: %w", err)
	}
	defer rows.Close()

	summaries := make([]ClusterSummary, 0)
	for rows.Next() {
		var summary ClusterSummary
		var lastReported sql.NullInt64
		if err := rows.Scan(&summary.Name, &lastReported, &summary.ImageCount); err != nil {
			return nil, errors.NewTransientf("failed to scan cluster summary row: %w", err)
		}
		if lastReported.Valid {
			v := lastReported.Int64
			summary.LastReported = &v
		}
		summaries = append(summaries, summary)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating cluster summary rows: %w", err)
	}

	return summaries, nil
}

// ListClusterImages returns all runtime image rows for a specific cluster.
func (s *SQLiteStore) ListClusterImages(ctx context.Context, clusterName string) ([]ClusterImageSummary, error) {
	clusterName = strings.TrimSpace(clusterName)
	if clusterName == "" {
		return nil, errors.NewPermanentf("cluster name cannot be empty")
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT ci.namespace, ci.image_ref, COALESCE(ci.tag, ''), COALESCE(ci.digest, '')
		FROM cluster_images ci
		JOIN clusters c ON c.id = ci.cluster_id
		WHERE c.name = ?
		ORDER BY ci.namespace ASC, ci.image_ref ASC
	`, clusterName)
	if err != nil {
		return nil, errors.NewTransientf("failed to query cluster images: %w", err)
	}
	defer rows.Close()

	images := make([]ClusterImageSummary, 0)
	for rows.Next() {
		var image ClusterImageSummary
		if err := rows.Scan(&image.Namespace, &image.ImageRef, &image.Tag, &image.Digest); err != nil {
			return nil, errors.NewTransientf("failed to scan cluster image row: %w", err)
		}
		images = append(images, image)
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating cluster image rows: %w", err)
	}

	return images, nil
}

// DeleteClusterInventory removes a cluster and all of its inventory rows.
func (s *SQLiteStore) DeleteClusterInventory(ctx context.Context, clusterName string) error {
	clusterName = strings.TrimSpace(clusterName)
	if clusterName == "" {
		return errors.NewPermanentf("cluster name cannot be empty")
	}

	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM clusters WHERE name = ?
	`, clusterName); err != nil {
		return errors.NewTransientf("failed to delete cluster inventory: %w", err)
	}

	return nil
}

// RecordScan saves scan results with full vulnerability details in a transaction

func (s *SQLiteStore) GetRuntimeUsageForScans(ctx context.Context, scans []RuntimeLookupInput) (map[string]RuntimeUsage, error) {
	usageByDigest := make(map[string]RuntimeUsage)
	if len(scans) == 0 {
		return usageByDigest, nil
	}

	digests := make([]string, 0, len(scans))
	seenDigests := make(map[string]struct{}, len(scans))
	for _, scan := range scans {
		digest := strings.TrimSpace(scan.Digest)
		if digest == "" {
			continue
		}
		if _, exists := seenDigests[digest]; exists {
			continue
		}
		seenDigests[digest] = struct{}{}
		digests = append(digests, digest)
	}

	byDigest, err := s.queryRuntimeUsageByDigests(ctx, digests)
	if err != nil {
		return nil, err
	}

	fallbackCache := make(map[string]RuntimeUsage)
	for _, scan := range scans {
		digest := strings.TrimSpace(scan.Digest)
		usage := byDigest[digest]

		repo := strings.TrimSpace(scan.Repository)
		tag := strings.TrimSpace(scan.Tag)
		if repo == "" || tag == "" || digest == "" {
			if usage.RuntimeUsed {
				usageByDigest[digest] = usage
			}
			continue
		}

		cacheKey := normalizeRepositoryRef(repo) + "|" + tag
		fallbackUsage, ok := fallbackCache[cacheKey]
		if !ok {
			fallbackUsage, err = s.queryRuntimeUsageByRepoTag(ctx, repo, tag)
			if err != nil {
				return nil, err
			}
			fallbackCache[cacheKey] = fallbackUsage
		}

		usage = mergeRuntimeUsage(usage, fallbackUsage)
		if usage.RuntimeUsed {
			usageByDigest[digest] = usage
		}
	}

	return usageByDigest, nil
}

// GetRuntimeUsageForScan returns runtime usage for one scan detail response.
func (s *SQLiteStore) GetRuntimeUsageForScan(ctx context.Context, digest, repository, tag string) (*RuntimeUsage, error) {
	digest = strings.TrimSpace(digest)
	repository = strings.TrimSpace(repository)
	tag = strings.TrimSpace(tag)

	if digest != "" {
		byDigest, err := s.queryRuntimeUsageByDigests(ctx, []string{digest})
		if err != nil {
			return nil, err
		}
		if usage, ok := byDigest[digest]; ok {
			fallbackUsage, err := s.queryRuntimeUsageByRepoTag(ctx, repository, tag)
			if err != nil {
				return nil, err
			}
			merged := mergeRuntimeUsage(usage, fallbackUsage)
			if merged.RuntimeUsed {
				return &merged, nil
			}
		}
	}

	usage, err := s.queryRuntimeUsageByRepoTag(ctx, repository, tag)
	if err != nil {
		return nil, err
	}

	return &usage, nil
}

func (s *SQLiteStore) queryRuntimeUsageByDigests(ctx context.Context, digests []string) (map[string]RuntimeUsage, error) {
	result := make(map[string]RuntimeUsage)
	if len(digests) == 0 {
		return result, nil
	}

	cutoffUnix := s.runtimeInUseCutoffUnix()

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(digests)), ",")
	query := `
		SELECT ci.digest, ci.image_ref, COALESCE(ci.tag, ''), c.name, ci.namespace
		FROM cluster_images_seen ci
		JOIN clusters c ON c.id = ci.cluster_id
		WHERE ci.last_seen_at >= ?
		  AND ci.digest IN (` + placeholders + `)
	`

	args := make([]interface{}, 0, len(digests)+1)
	args = append(args, cutoffUnix)
	for _, digest := range digests {
		args = append(args, digest)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, errors.NewTransientf("failed to query runtime usage by digest: %w", err)
	}
	defer rows.Close()

	locationsByDigest := make(map[string][]RuntimeLocation)
	for rows.Next() {
		var digest, imageRef, imageTag, cluster, namespace string
		if err := rows.Scan(&digest, &imageRef, &imageTag, &cluster, &namespace); err != nil {
			return nil, errors.NewTransientf("failed to scan runtime usage by digest: %w", err)
		}
		locationsByDigest[digest] = append(locationsByDigest[digest], RuntimeLocation{
			Cluster:   cluster,
			Namespace: namespace,
			ImageRef:  imageRef,
			Tag:       imageTag,
			Digest:    digest,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, errors.NewTransientf("error iterating runtime usage by digest rows: %w", err)
	}

	for digest, locations := range locationsByDigest {
		result[digest] = buildRuntimeUsage(locations)
	}

	return result, nil
}

func (s *SQLiteStore) queryRuntimeUsageByRepoTag(ctx context.Context, repository, tag string) (RuntimeUsage, error) {
	repository = normalizeRepositoryRef(repository)
	tag = strings.TrimSpace(tag)
	if repository == "" || tag == "" {
		return RuntimeUsage{}, nil
	}

	cutoffUnix := s.runtimeInUseCutoffUnix()

	rows, err := s.db.QueryContext(ctx, `
		SELECT ci.image_ref, COALESCE(ci.tag, ''), COALESCE(ci.digest, ''), c.name, ci.namespace
		FROM cluster_images_seen ci
		JOIN clusters c ON c.id = ci.cluster_id
		WHERE ci.last_seen_at >= ?
		  AND COALESCE(ci.tag, '') = ?
	`, cutoffUnix, tag)
	if err != nil {
		return RuntimeUsage{}, errors.NewTransientf("failed to query runtime fallback usage: %w", err)
	}
	defer rows.Close()

	locations := make([]RuntimeLocation, 0)
	for rows.Next() {
		var imageRef, imageTag, imageDigest, cluster, namespace string
		if err := rows.Scan(&imageRef, &imageTag, &imageDigest, &cluster, &namespace); err != nil {
			return RuntimeUsage{}, errors.NewTransientf("failed to scan runtime fallback usage: %w", err)
		}

		if imageTag != tag {
			continue
		}
		if normalizeRepositoryRef(imageRef) != repository {
			continue
		}

		locations = append(locations, RuntimeLocation{
			Cluster:   cluster,
			Namespace: namespace,
			ImageRef:  imageRef,
			Tag:       imageTag,
			Digest:    imageDigest,
		})
	}

	if err := rows.Err(); err != nil {
		return RuntimeUsage{}, errors.NewTransientf("error iterating runtime fallback usage rows: %w", err)
	}

	return buildRuntimeUsage(locations), nil
}

func (s *SQLiteStore) queryRuntimeUsageByRepository(ctx context.Context, repository string) (RuntimeUsage, error) {
	repository = normalizeRepositoryRef(repository)
	if repository == "" {
		return RuntimeUsage{}, nil
	}

	cutoffUnix := s.runtimeInUseCutoffUnix()

	rows, err := s.db.QueryContext(ctx, `
		SELECT ci.image_ref, COALESCE(ci.tag, ''), COALESCE(ci.digest, ''), c.name, ci.namespace
		FROM cluster_images_seen ci
		JOIN clusters c ON c.id = ci.cluster_id
		WHERE ci.last_seen_at >= ?
	`, cutoffUnix)
	if err != nil {
		return RuntimeUsage{}, errors.NewTransientf("failed to query runtime repository usage: %w", err)
	}
	defer rows.Close()

	locations := make([]RuntimeLocation, 0)
	for rows.Next() {
		var imageRef, imageTag, imageDigest, cluster, namespace string
		if err := rows.Scan(&imageRef, &imageTag, &imageDigest, &cluster, &namespace); err != nil {
			return RuntimeUsage{}, errors.NewTransientf("failed to scan runtime repository usage: %w", err)
		}

		if normalizeRepositoryRef(imageRef) != repository {
			continue
		}

		locations = append(locations, RuntimeLocation{
			Cluster:   cluster,
			Namespace: namespace,
			ImageRef:  imageRef,
			Tag:       imageTag,
			Digest:    imageDigest,
		})
	}

	if err := rows.Err(); err != nil {
		return RuntimeUsage{}, errors.NewTransientf("error iterating runtime repository usage rows: %w", err)
	}

	return buildRuntimeUsage(locations), nil
}

func mergeRuntimeUsage(primary, secondary RuntimeUsage) RuntimeUsage {
	if !primary.RuntimeUsed {
		return secondary
	}
	if !secondary.RuntimeUsed {
		return primary
	}

	locations := make([]RuntimeLocation, 0)
	locations = appendRuntimeLocations(locations, primary.Runtime)
	locations = appendRuntimeLocations(locations, secondary.Runtime)

	return buildRuntimeUsage(locations)
}

func buildRuntimeUsage(locations []RuntimeLocation) RuntimeUsage {
	if len(locations) == 0 {
		return RuntimeUsage{}
	}

	runtime := make(RuntimeInventory)
	entrySet := make(map[string]struct{}, len(locations))

	for _, location := range locations {
		cluster := strings.TrimSpace(location.Cluster)
		namespace := strings.TrimSpace(location.Namespace)
		if cluster == "" {
			continue
		}

		key := strings.Join([]string{cluster, namespace, location.ImageRef, location.Tag, location.Digest}, "|")
		if _, ok := entrySet[key]; ok {
			continue
		}
		entrySet[key] = struct{}{}

		namespaces := runtime[cluster]
		if namespaces == nil {
			namespaces = make(map[string][]RuntimeImage)
			runtime[cluster] = namespaces
		}

		namespaces[namespace] = append(namespaces[namespace], RuntimeImage{
			ImageRef: location.ImageRef,
			Tag:      location.Tag,
			Digest:   location.Digest,
		})
	}

	if len(runtime) == 0 {
		return RuntimeUsage{}
	}

	for cluster, namespaces := range runtime {
		for namespace, images := range namespaces {
			ordered := append([]RuntimeImage(nil), images...)
			sort.Slice(ordered, func(i, j int) bool {
				if ordered[i].ImageRef != ordered[j].ImageRef {
					return ordered[i].ImageRef < ordered[j].ImageRef
				}
				if ordered[i].Tag != ordered[j].Tag {
					return ordered[i].Tag < ordered[j].Tag
				}
				return ordered[i].Digest < ordered[j].Digest
			})
			namespaces[namespace] = ordered
		}
		runtime[cluster] = namespaces
	}

	return RuntimeUsage{
		RuntimeUsed: true,
		Runtime:     runtime,
	}
}

func appendRuntimeLocations(locations []RuntimeLocation, runtime RuntimeInventory) []RuntimeLocation {
	for cluster, namespaces := range runtime {
		for namespace, images := range namespaces {
			for _, image := range images {
				locations = append(locations, RuntimeLocation{
					Cluster:   cluster,
					Namespace: namespace,
					ImageRef:  image.ImageRef,
					Tag:       image.Tag,
					Digest:    image.Digest,
				})
			}
		}
	}

	return locations
}

func normalizeRepositoryRef(imageRef string) string {
	ref := strings.ToLower(strings.TrimSpace(imageRef))
	if ref == "" {
		return ""
	}

	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}

	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > lastSlash {
		ref = ref[:lastColon]
	}

	parts := strings.Split(ref, "/")
	if len(parts) == 0 {
		return ""
	}

	hasRegistry := false
	if len(parts) > 1 {
		first := parts[0]
		hasRegistry = strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost"
	}

	registry := "docker.io"
	path := ""
	if hasRegistry {
		registry = parts[0]
		path = strings.Join(parts[1:], "/")
	} else {
		path = strings.Join(parts, "/")
	}

	if registry == "index.docker.io" || registry == "registry-1.docker.io" {
		registry = "docker.io"
	}

	if registry == "docker.io" && !strings.Contains(path, "/") {
		path = "library/" + path
	}

	if path == "" {
		return ""
	}

	return registry + "/" + path
}

// GetUniqueVulnerabilityCounts returns the count of unique CVE IDs by severity across all latest scans.
// This deduplicates vulnerabilities so that a CVE ID is counted only once for the whole configuration,
// even if it appears in multiple repositories or multiple tags.

package observability

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dbCollectorOnce     sync.Once
	dbCollectorInstance *DatabaseCollector
)

// DatabaseCollector collects metrics from the database on-demand when /metrics is scraped
type DatabaseCollector struct {
	store  statestore.StateStore
	logger *slog.Logger

	// Metric descriptors
	vulnerabilitiesFoundDesc *prometheus.Desc
	policyFailedDesc         *prometheus.Desc
	policyPendingDesc        *prometheus.Desc
	clusterLastSyncDesc      *prometheus.Desc
}

// NewDatabaseCollector creates a new database metrics collector
func NewDatabaseCollector(store statestore.StateStore, logger *slog.Logger) *DatabaseCollector {
	return &DatabaseCollector{
		store:  store,
		logger: logger,
		vulnerabilitiesFoundDesc: prometheus.NewDesc(
			"suppline_vulnerabilities_found",
			"Current number of vulnerabilities found by severity across all scanned artifacts",
			[]string{"severity"},
			nil,
		),
		policyFailedDesc: prometheus.NewDesc(
			"suppline_policy_failed_current",
			"Current number of artifacts that failed policy evaluation by source",
			[]string{"source"},
			nil,
		),
		policyPendingDesc: prometheus.NewDesc(
			"suppline_policy_pending_current",
			"Current number of artifacts with pending policy evaluation by source",
			[]string{"source"},
			nil,
		),
		clusterLastSyncDesc: prometheus.NewDesc(
			"suppline_cluster_last_sync_timestamp_seconds",
			"Unix timestamp of the last successful cluster inventory sync, labelled by cluster name",
			[]string{"cluster"},
			nil,
		),
	}
}

// RegisterDatabaseCollector registers the database collector exactly once
func RegisterDatabaseCollector(store statestore.StateStore, logger *slog.Logger) {
	dbCollectorOnce.Do(func() {
		dbCollectorInstance = NewDatabaseCollector(store, logger)
		prometheus.MustRegister(dbCollectorInstance)
		logger.Info("database metrics collector registered")
	})
}

// Describe sends the metric descriptors to the provided channel
func (c *DatabaseCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.vulnerabilitiesFoundDesc
	ch <- c.policyFailedDesc
	ch <- c.policyPendingDesc
	ch <- c.clusterLastSyncDesc
}

// Collect queries the database and sends current metrics to the provided channel
func (c *DatabaseCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if clusterStore, ok := c.store.(statestore.ClusterInventoryStore); ok {
		c.collectClusterLastSync(ctx, clusterStore, ch)
	}

	queryStore, ok := c.store.(statestore.StateStoreQuery)
	if !ok {
		c.logger.Warn("state store does not support queries, skipping database metrics")
		return
	}

	// Collect policy failed metric
	c.collectPolicyOutcomes(ctx, queryStore, ch)

	// Collect vulnerability metrics
	c.collectVulnerabilities(ctx, queryStore, ch)
}

func (c *DatabaseCollector) collectClusterLastSync(ctx context.Context, store statestore.ClusterInventoryStore, ch chan<- prometheus.Metric) {
	summaries, err := store.ListClusterSummaries(ctx)
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("cluster sync metric collection timed out", "error", err)
		} else {
			c.logger.Error("failed to collect cluster sync metrics", "error", err)
		}
		return
	}

	for _, summary := range summaries {
		if summary.LastReported == nil {
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			c.clusterLastSyncDesc,
			prometheus.GaugeValue,
			float64(*summary.LastReported),
			summary.Name,
		)
	}
}

func (c *DatabaseCollector) collectPolicyOutcomes(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	scans, err := store.GetFailedArtifacts(ctx)
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("policy outcome metric collection timed out", "error", err)
		} else {
			c.logger.Error("failed to collect policy outcome metric", "error", err)
		}
		return
	}

	failedScans := make([]*statestore.ScanRecord, 0, len(scans))
	pendingScans := make([]*statestore.ScanRecord, 0, len(scans))

	for _, scan := range scans {
		if scan.PolicyStatus == "pending" {
			pendingScans = append(pendingScans, scan)
			continue
		}

		// Backward compatibility: records with empty/non-pending status that did not pass policy are counted as failed.
		failedScans = append(failedScans, scan)
	}

	registryFailedCount := len(failedScans)
	registryPendingCount := len(pendingScans)
	runtimeFailedCount := 0
	runtimePendingCount := 0
	runtimeNewerFailedCount := 0
	runtimeNewerPendingCount := 0

	if len(scans) > 0 {
		runtimeInputs := make([]statestore.RuntimeLookupInput, 0, len(scans))
		reposSeen := make(map[string]struct{}, len(scans))
		var distinctRepos []string
		for _, scan := range scans {
			runtimeInputs = append(runtimeInputs, statestore.RuntimeLookupInput{
				Digest:     scan.Digest,
				Repository: scan.Repository,
				Tag:        scan.Tag,
			})
			repo := strings.TrimSpace(scan.Repository)
			if repo != "" {
				if _, ok := reposSeen[repo]; !ok {
					reposSeen[repo] = struct{}{}
					distinctRepos = append(distinctRepos, repo)
				}
			}
		}

		runtimeUsageByDigest, err := store.GetRuntimeUsageForScans(ctx, runtimeInputs)
		if err != nil {
			if ctx.Err() != nil {
				c.logger.Debug("runtime policy failed metric collection timed out", "error", err)
			} else {
				c.logger.Error("failed to collect runtime policy failed metric", "error", err)
			}
			return
		}

		maxInUseByRepo, err := store.GetMaxInUseImageTagByRepositories(ctx, distinctRepos)
		if err != nil {
			if ctx.Err() != nil {
				c.logger.Debug("in-use+newer policy metric collection timed out", "error", err)
			} else {
				c.logger.Error("failed to collect in-use+newer policy metrics", "error", err)
			}
			return
		}

		for _, scan := range failedScans {
			usage := runtimeUsageByDigest[scan.Digest]
			used := usage.RuntimeUsed
			if used {
				runtimeFailedCount++
			}
			if statestore.PolicyArtifactMatchesInUseOrNewer(used, scan.Repository, scan.Tag, maxInUseByRepo) {
				runtimeNewerFailedCount++
			}
		}

		for _, scan := range pendingScans {
			usage := runtimeUsageByDigest[scan.Digest]
			used := usage.RuntimeUsed
			if used {
				runtimePendingCount++
			}
			if statestore.PolicyArtifactMatchesInUseOrNewer(used, scan.Repository, scan.Tag, maxInUseByRepo) {
				runtimeNewerPendingCount++
			}
		}
	}

	ch <- prometheus.MustNewConstMetric(
		c.policyFailedDesc,
		prometheus.GaugeValue,
		float64(registryFailedCount),
		"registry",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyFailedDesc,
		prometheus.GaugeValue,
		float64(runtimeFailedCount),
		"runtime",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyFailedDesc,
		prometheus.GaugeValue,
		float64(runtimeNewerFailedCount),
		"runtime+newer",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyPendingDesc,
		prometheus.GaugeValue,
		float64(registryPendingCount),
		"registry",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyPendingDesc,
		prometheus.GaugeValue,
		float64(runtimePendingCount),
		"runtime",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyPendingDesc,
		prometheus.GaugeValue,
		float64(runtimeNewerPendingCount),
		"runtime+newer",
	)
}

func (c *DatabaseCollector) collectVulnerabilities(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	counts, err := store.GetUniqueVulnerabilityCounts(ctx)
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("vulnerabilities metric collection timed out", "error", err)
		} else {
			c.logger.Error("failed to collect vulnerability metrics", "error", err)
		}
		return
	}

	for severity, count := range counts {
		ch <- prometheus.MustNewConstMetric(
			c.vulnerabilitiesFoundDesc,
			prometheus.GaugeValue,
			float64(count),
			severity,
		)
	}
}

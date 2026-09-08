package observability

import (
	"context"
	"log/slog"
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
	summary, err := store.GetPolicyOutcomeSummary(ctx)
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("policy outcome metric collection timed out", "error", err)
		} else {
			c.logger.Error("failed to collect policy outcome metric", "error", err)
		}
		return
	}

	ch <- prometheus.MustNewConstMetric(
		c.policyFailedDesc,
		prometheus.GaugeValue,
		float64(summary.Failed.All),
		"registry",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyFailedDesc,
		prometheus.GaugeValue,
		float64(summary.Failed.Runtime),
		"runtime",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyFailedDesc,
		prometheus.GaugeValue,
		float64(summary.Failed.RuntimeAndNewer),
		"runtime+newer",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyPendingDesc,
		prometheus.GaugeValue,
		float64(summary.Pending.All),
		"registry",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyPendingDesc,
		prometheus.GaugeValue,
		float64(summary.Pending.Runtime),
		"runtime",
	)

	ch <- prometheus.MustNewConstMetric(
		c.policyPendingDesc,
		prometheus.GaugeValue,
		float64(summary.Pending.RuntimeAndNewer),
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

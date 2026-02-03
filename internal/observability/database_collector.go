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
	toleratedCVEsDesc        *prometheus.Desc
	expiredTolerationsDesc   *prometheus.Desc
	expiringTolerationsDesc  *prometheus.Desc
	vulnerabilitiesFoundDesc *prometheus.Desc
}

// NewDatabaseCollector creates a new database metrics collector
func NewDatabaseCollector(store statestore.StateStore, logger *slog.Logger) *DatabaseCollector {
	return &DatabaseCollector{
		store:  store,
		logger: logger,
		toleratedCVEsDesc: prometheus.NewDesc(
			"suppline_tolerated_cves",
			"Current total number of CVEs that are tolerated",
			nil,
			nil,
		),
		expiredTolerationsDesc: prometheus.NewDesc(
			"suppline_expired_tolerations",
			"Number of expired tolerations per repository",
			[]string{"repository"},
			nil,
		),
		expiringTolerationsDesc: prometheus.NewDesc(
			"suppline_expiring_tolerations_soon",
			"Number of tolerations expiring within 7 days per repository",
			[]string{"repository"},
			nil,
		),
		vulnerabilitiesFoundDesc: prometheus.NewDesc(
			"suppline_vulnerabilities_found",
			"Current number of vulnerabilities found by severity",
			[]string{"severity"},
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
	ch <- c.toleratedCVEsDesc
	ch <- c.expiredTolerationsDesc
	ch <- c.expiringTolerationsDesc
	ch <- c.vulnerabilitiesFoundDesc
}

// Collect queries the database and sends current metrics to the provided channel
func (c *DatabaseCollector) Collect(ch chan<- prometheus.Metric) {
	// Create a context with a reasonable timeout for metrics collection.
	// Metrics don't need to be real-time or ACID-compliant, but we want them to succeed
	// even during moderate database contention. Use 3 seconds to allow retries but not
	// block the /metrics endpoint indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Check if store supports queries
	queryStore, ok := c.store.(statestore.StateStoreQuery)
	if !ok {
		c.logger.Warn("state store does not support queries, skipping database metrics")
		return
	}

	// Collect tolerated CVEs metric
	c.collectToleratedCVEs(ctx, queryStore, ch)

	// Collect toleration expiry metrics
	c.collectTolerationExpiry(ctx, queryStore, ch)

	// Collect vulnerability metrics
	c.collectVulnerabilities(ctx, queryStore, ch)
}

// collectToleratedCVEs collects the total count of tolerated CVEs
func (c *DatabaseCollector) collectToleratedCVEs(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	tolerations, err := store.ListTolerations(ctx, statestore.TolerationFilter{})
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("tolerated CVEs metric collection timed out (likely database locked)", "error", err)
		} else {
			c.logger.Error("failed to collect tolerated CVEs metric", "error", err)
		}
		return
	}

	ch <- prometheus.MustNewConstMetric(
		c.toleratedCVEsDesc,
		prometheus.GaugeValue,
		float64(len(tolerations)),
	)
}

// collectTolerationExpiry collects expired and expiring-soon toleration counts per repository
func (c *DatabaseCollector) collectTolerationExpiry(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	tolerations, err := store.ListTolerations(ctx, statestore.TolerationFilter{})
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("toleration expiry metric collection timed out (likely database locked)", "error", err)
		} else {
			c.logger.Error("failed to collect toleration expiry metrics", "error", err)
		}
		return
	}

	// Aggregate by repository
	type repoMetrics struct {
		expired  int
		expiring int
	}
	repoStats := make(map[string]*repoMetrics)
	now := time.Now()

	for _, toleration := range tolerations {
		if toleration.ExpiresAt == nil {
			continue
		}

		// Initialize repo stats if needed
		if _, exists := repoStats[toleration.Repository]; !exists {
			repoStats[toleration.Repository] = &repoMetrics{}
		}

		expiresAt := time.Unix(*toleration.ExpiresAt, 0)
		if expiresAt.Before(now) {
			// Expired
			repoStats[toleration.Repository].expired++
		} else {
			// Check if expiring within 7 days
			daysUntilExpiry := expiresAt.Sub(now).Hours() / 24
			if daysUntilExpiry <= 7 {
				repoStats[toleration.Repository].expiring++
			}
		}
	}

	// Send metrics for each repository
	for repo, stats := range repoStats {
		ch <- prometheus.MustNewConstMetric(
			c.expiredTolerationsDesc,
			prometheus.GaugeValue,
			float64(stats.expired),
			repo,
		)
		ch <- prometheus.MustNewConstMetric(
			c.expiringTolerationsDesc,
			prometheus.GaugeValue,
			float64(stats.expiring),
			repo,
		)
	}
}

// collectVulnerabilities collects vulnerability counts by severity
func (c *DatabaseCollector) collectVulnerabilities(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	// Get all scans from the database
	scans, err := store.ListScans(ctx, statestore.ScanFilter{})
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("vulnerabilities metric collection timed out (likely database locked)", "error", err)
		} else {
			c.logger.Error("failed to collect vulnerability metrics", "error", err)
		}
		return
	}

	// Aggregate vulnerabilities by severity across all scans
	// ListScans returns lightweight records with count fields only
	severityCounts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
	}

	for _, scan := range scans {
		severityCounts["CRITICAL"] += scan.CriticalVulnCount
		severityCounts["HIGH"] += scan.HighVulnCount
		severityCounts["MEDIUM"] += scan.MediumVulnCount
		severityCounts["LOW"] += scan.LowVulnCount
	}

	// Send metrics for each severity
	for severity, count := range severityCounts {
		ch <- prometheus.MustNewConstMetric(
			c.vulnerabilitiesFoundDesc,
			prometheus.GaugeValue,
			float64(count),
			severity,
		)
	}
}

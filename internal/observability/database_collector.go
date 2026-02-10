package observability

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	dbCollectorOnce     sync.Once
	dbCollectorInstance *DatabaseCollector
)

// DatabaseCollector collects metrics from the database on-demand when /metrics is scraped
type DatabaseCollector struct {
	store      statestore.StateStore
	logger     *slog.Logger
	regsyncCfg *config.RegsyncConfig // Optional: used to calculate unapplied tolerations

	// Metric descriptors
	toleratedCVEsDesc            *prometheus.Desc
	expiredTolerationsDesc       *prometheus.Desc
	expiringTolerationsDesc      *prometheus.Desc
	tolerationsWithoutExpiryDesc *prometheus.Desc
	vulnerabilitiesFoundDesc     *prometheus.Desc
	unappliedTolerationsDesc     *prometheus.Desc
	policyFailedDesc             *prometheus.Desc

	// Cache for unapplied tolerations (10-minute TTL)
	unappliedTolerationsMutex sync.RWMutex
	unappliedTolerationsCache int
	unappliedTolerationsTime  time.Time
	unappliedTolerationsTTL   time.Duration
}

// NewDatabaseCollector creates a new database metrics collector
func NewDatabaseCollector(store statestore.StateStore, regsyncCfg *config.RegsyncConfig, logger *slog.Logger) *DatabaseCollector {
	return &DatabaseCollector{
		store:                   store,
		logger:                  logger,
		regsyncCfg:              regsyncCfg,
		unappliedTolerationsTTL: 10 * time.Minute,
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
		tolerationsWithoutExpiryDesc: prometheus.NewDesc(
			"suppline_tolerations_without_expiry",
			"Number of tolerations without an expiry date per repository",
			[]string{"repository"},
			nil,
		),
		vulnerabilitiesFoundDesc: prometheus.NewDesc(
			"suppline_vulnerabilities_found",
			"Current number of vulnerabilities found by severity",
			[]string{"severity"},
			nil,
		),
		unappliedTolerationsDesc: prometheus.NewDesc(
			"suppline_unapplied_tolerations",
			"Number of toleration CVE IDs defined in configuration that have never been applied to any digest",
			nil,
			nil,
		),
		policyFailedDesc: prometheus.NewDesc(
			"suppline_policy_failed_total",
			"Current number of artifacts that failed policy evaluation",
			nil,
			nil,
		),
	}
}

// RegisterDatabaseCollector registers the database collector exactly once
func RegisterDatabaseCollector(store statestore.StateStore, regsyncCfg *config.RegsyncConfig, logger *slog.Logger) {
	dbCollectorOnce.Do(func() {
		dbCollectorInstance = NewDatabaseCollector(store, regsyncCfg, logger)
		prometheus.MustRegister(dbCollectorInstance)
		logger.Info("database metrics collector registered")
	})
}

// Describe sends the metric descriptors to the provided channel
func (c *DatabaseCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.toleratedCVEsDesc
	ch <- c.expiredTolerationsDesc
	ch <- c.expiringTolerationsDesc
	ch <- c.tolerationsWithoutExpiryDesc
	ch <- c.vulnerabilitiesFoundDesc
	ch <- c.unappliedTolerationsDesc
	ch <- c.policyFailedDesc
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

	// Collect tolerations without expiry metric
	c.collectTolerationsWithoutExpiry(ctx, queryStore, ch)

	// Collect unapplied tolerations metric
	c.collectUnappliedTolerations(ctx, queryStore, ch)

	// Collect policy failed metric
	c.collectPolicyFailed(ctx, queryStore, ch)

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

// collectTolerationsWithoutExpiry collects the count of tolerations without expiry dates per repository
func (c *DatabaseCollector) collectTolerationsWithoutExpiry(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	tolerations, err := store.ListTolerations(ctx, statestore.TolerationFilter{})
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("tolerations without expiry metric collection timed out (likely database locked)", "error", err)
		} else {
			c.logger.Error("failed to collect tolerations without expiry metrics", "error", err)
		}
		return
	}

	// Count tolerations without expiry by repository
	repoNoExpiryCount := make(map[string]int)

	for _, toleration := range tolerations {
		// Count tolerations where ExpiresAt is nil (no expiry)
		if toleration.ExpiresAt == nil {
			repoNoExpiryCount[toleration.Repository]++
		}
	}

	// Send metrics for each repository
	for repo, count := range repoNoExpiryCount {
		ch <- prometheus.MustNewConstMetric(
			c.tolerationsWithoutExpiryDesc,
			prometheus.GaugeValue,
			float64(count),
			repo,
		)
	}
}

// collectUnappliedTolerations collects the count of tolerations defined in config but not yet applied
func (c *DatabaseCollector) collectUnappliedTolerations(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	// If no regsync config is available, skip this metric
	if c.regsyncCfg == nil {
		return
	}

	// Check cache first
	c.unappliedTolerationsMutex.RLock()
	if time.Since(c.unappliedTolerationsTime) < c.unappliedTolerationsTTL {
		// Cache is still valid
		cachedValue := c.unappliedTolerationsCache
		c.unappliedTolerationsMutex.RUnlock()
		ch <- prometheus.MustNewConstMetric(
			c.unappliedTolerationsDesc,
			prometheus.GaugeValue,
			float64(cachedValue),
		)
		return
	}
	c.unappliedTolerationsMutex.RUnlock()

	// Cache miss or expired, collect the metric
	// Collect all defined CVE IDs from the configuration
	definedCVEIDs := make(map[string]bool)

	// Get default tolerations
	for _, toleration := range c.regsyncCfg.Defaults.Tolerate {
		definedCVEIDs[toleration.ID] = true
	}

	// Get all unique CVE IDs from all syncs
	if c.regsyncCfg.Sync != nil {
		for _, sync := range c.regsyncCfg.Sync {
			for _, toleration := range sync.Tolerate {
				definedCVEIDs[toleration.ID] = true
			}
		}
	}

	// Convert map to slice for the statestore method
	cveIDSlice := make([]string, 0, len(definedCVEIDs))
	for cveID := range definedCVEIDs {
		cveIDSlice = append(cveIDSlice, cveID)
	}

	// Query the state store for unapplied tolerations
	unappliedCount, err := store.GetUnappliedTolerationsCount(ctx, cveIDSlice)
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("unapplied tolerations metric collection timed out (likely database locked)", "error", err)
		} else {
			c.logger.Error("failed to collect unapplied tolerations metric", "error", err)
		}
		return
	}

	// Update cache
	c.unappliedTolerationsMutex.Lock()
	c.unappliedTolerationsCache = unappliedCount
	c.unappliedTolerationsTime = time.Now()
	c.unappliedTolerationsMutex.Unlock()

	ch <- prometheus.MustNewConstMetric(
		c.unappliedTolerationsDesc,
		prometheus.GaugeValue,
		float64(unappliedCount),
	)
}

// collectPolicyFailed collects the count of artifacts that failed policy evaluation
func (c *DatabaseCollector) collectPolicyFailed(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	// Get all scans from the database
	scans, err := store.ListScans(ctx, statestore.ScanFilter{})
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("policy failed metric collection timed out (likely database locked)", "error", err)
		} else {
			c.logger.Error("failed to collect policy failed metric", "error", err)
		}
		return
	}

	// Count scans where policy_passed is false
	failedCount := 0
	for _, scan := range scans {
		if !scan.PolicyPassed {
			failedCount++
		}
	}

	ch <- prometheus.MustNewConstMetric(
		c.policyFailedDesc,
		prometheus.GaugeValue,
		float64(failedCount),
	)
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

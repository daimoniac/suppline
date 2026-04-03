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
}

// Collect queries the database and sends current metrics to the provided channel
func (c *DatabaseCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	queryStore, ok := c.store.(statestore.StateStoreQuery)
	if !ok {
		c.logger.Warn("state store does not support queries, skipping database metrics")
		return
	}

	// Collect policy failed metric
	c.collectPolicyFailed(ctx, queryStore, ch)

	// Collect vulnerability metrics
	c.collectVulnerabilities(ctx, queryStore, ch)
}

func (c *DatabaseCollector) collectPolicyFailed(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	scans, err := store.GetFailedArtifacts(ctx)
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("policy failed metric collection timed out", "error", err)
		} else {
			c.logger.Error("failed to collect policy failed metric", "error", err)
		}
		return
	}

	registryFailedCount := len(scans)
	runtimeFailedCount := 0

	if len(scans) > 0 {
		runtimeInputs := make([]statestore.RuntimeLookupInput, 0, len(scans))
		for _, scan := range scans {
			runtimeInputs = append(runtimeInputs, statestore.RuntimeLookupInput{
				Digest:     scan.Digest,
				Repository: scan.Repository,
				Tag:        scan.Tag,
			})
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

		for _, usage := range runtimeUsageByDigest {
			if usage.RuntimeUsed {
				runtimeFailedCount++
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

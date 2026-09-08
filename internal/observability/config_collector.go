package observability

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/policy/catalog"
	"github.com/daimoniac/suppline/internal/statestore"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	configCollectorOnce     sync.Once
	configCollectorInstance *ConfigCollector
)

// ConfigCollector collects metrics from the configuration on-demand when /metrics is scraped
type ConfigCollector struct {
	catalog catalog.Catalog
	store   statestore.StateStore
	logger  *slog.Logger

	// Metric descriptors
	exemptedCVEsDesc     *prometheus.Desc
	expiredVEXDesc       *prometheus.Desc
	expiringVEXDesc      *prometheus.Desc
	vexWithoutExpiryDesc *prometheus.Desc
	inactiveVEXDesc      *prometheus.Desc

	// Cache for inactive VEX statements (10-minute TTL)
	inactiveVEXMutex sync.RWMutex
	inactiveVEXCache int
	inactiveVEXTime  time.Time
	inactiveVEXTTL   time.Duration
}

// NewConfigCollector creates a new configuration metrics collector
func NewConfigCollector(regsyncCfg *config.RegsyncConfig, store statestore.StateStore, logger *slog.Logger) *ConfigCollector {
	return NewConfigCollectorWithCatalog(catalog.NewConfigCatalog(regsyncCfg), store, logger)
}

// NewConfigCollectorWithCatalog creates a collector using the policy catalog.
func NewConfigCollectorWithCatalog(policyCatalog catalog.Catalog, store statestore.StateStore, logger *slog.Logger) *ConfigCollector {
	return &ConfigCollector{
		catalog:        policyCatalog,
		store:          store,
		logger:         logger,
		inactiveVEXTTL: 10 * time.Minute,
		exemptedCVEsDesc: prometheus.NewDesc(
			"suppline_exempted_cves",
			"Current total number of CVEs exempted by VEX statements in configuration",
			nil,
			nil,
		),
		expiredVEXDesc: prometheus.NewDesc(
			"suppline_expired_vex_statements",
			"Number of expired VEX statements per repository in configuration",
			[]string{"repository"},
			nil,
		),
		expiringVEXDesc: prometheus.NewDesc(
			"suppline_expiring_vex_statements_soon",
			"Number of VEX statements expiring within 7 days per repository in configuration",
			[]string{"repository"},
			nil,
		),
		vexWithoutExpiryDesc: prometheus.NewDesc(
			"suppline_vex_statements_without_expiry",
			"Number of VEX statements without an expiry date per repository in configuration",
			[]string{"repository"},
			nil,
		),
		inactiveVEXDesc: prometheus.NewDesc(
			"suppline_inactive_vex_statements",
			"Number of configured VEX CVE IDs that have never been applied to any digest",
			nil,
			nil,
		),
	}
}

// RegisterConfigCollector registers the configuration collector exactly once
func RegisterConfigCollector(regsyncCfg *config.RegsyncConfig, store statestore.StateStore, logger *slog.Logger) {
	RegisterConfigCollectorWithCatalog(catalog.NewConfigCatalog(regsyncCfg), store, logger)
}

// RegisterConfigCollectorWithCatalog registers a collector using the shared policy catalog.
func RegisterConfigCollectorWithCatalog(policyCatalog catalog.Catalog, store statestore.StateStore, logger *slog.Logger) {
	configCollectorOnce.Do(func() {
		configCollectorInstance = NewConfigCollectorWithCatalog(policyCatalog, store, logger)
		prometheus.MustRegister(configCollectorInstance)
		logger.Info("configuration metrics collector registered")
	})
}

// Describe sends the metric descriptors to the provided channel
func (c *ConfigCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.exemptedCVEsDesc
	ch <- c.expiredVEXDesc
	ch <- c.expiringVEXDesc
	ch <- c.vexWithoutExpiryDesc
	ch <- c.inactiveVEXDesc
}

// Collect sends current metrics from configuration to the provided channel
func (c *ConfigCollector) Collect(ch chan<- prometheus.Metric) {
	if c.catalog == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Collect exempted CVEs metric
	c.collectExemptedCVEs(ch)

	// Collect VEX expiry metrics
	c.collectVEXExpiry(ch)

	// Collect VEX statements without expiry metric
	c.collectVEXWithoutExpiry(ch)

	// Collect inactive VEX metric (needs store)
	if c.store != nil {
		if queryStore, ok := c.store.(statestore.StateStoreQuery); ok {
			c.collectInactiveVEX(ctx, queryStore, ch)
		}
	}
}

func (c *ConfigCollector) collectExemptedCVEs(ch chan<- prometheus.Metric) {
	total := 0
	targets := c.catalog.Repositories()
	for _, target := range targets {
		total += len(c.catalog.ResolveEvidence(target).VEXStatements)
	}

	ch <- prometheus.MustNewConstMetric(
		c.exemptedCVEsDesc,
		prometheus.GaugeValue,
		float64(total),
	)
}

func (c *ConfigCollector) collectVEXExpiry(ch chan<- prometheus.Metric) {
	now := time.Now()
	threshold := now.Add(7 * 24 * time.Hour)
	targets := c.catalog.Repositories()

	for _, target := range targets {
		vexStatements := c.catalog.ResolveEvidence(target).VEXStatements
		expired := 0
		expiring := 0

		for _, s := range vexStatements {
			if s.ExpiresAt == nil {
				continue
			}

			expiresAt := time.Unix(*s.ExpiresAt, 0)
			if expiresAt.Before(now) {
				expired++
			} else if expiresAt.Before(threshold) {
				expiring++
			}
		}

		ch <- prometheus.MustNewConstMetric(
			c.expiredVEXDesc,
			prometheus.GaugeValue,
			float64(expired),
			target,
		)
		ch <- prometheus.MustNewConstMetric(
			c.expiringVEXDesc,
			prometheus.GaugeValue,
			float64(expiring),
			target,
		)
	}
}

func (c *ConfigCollector) collectVEXWithoutExpiry(ch chan<- prometheus.Metric) {
	targets := c.catalog.Repositories()

	for _, target := range targets {
		vexStatements := c.catalog.ResolveEvidence(target).VEXStatements
		noExpiryCount := 0

		for _, s := range vexStatements {
			if s.ExpiresAt == nil {
				noExpiryCount++
			}
		}

		ch <- prometheus.MustNewConstMetric(
			c.vexWithoutExpiryDesc,
			prometheus.GaugeValue,
			float64(noExpiryCount),
			target,
		)
	}
}

func (c *ConfigCollector) collectInactiveVEX(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	c.inactiveVEXMutex.RLock()
	if time.Since(c.inactiveVEXTime) < c.inactiveVEXTTL {
		cachedValue := c.inactiveVEXCache
		c.inactiveVEXMutex.RUnlock()
		ch <- prometheus.MustNewConstMetric(
			c.inactiveVEXDesc,
			prometheus.GaugeValue,
			float64(cachedValue),
		)
		return
	}
	c.inactiveVEXMutex.RUnlock()

	inactiveCount, err := store.GetInactiveVEXCount(ctx, c.catalog.StatementIDs())
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("inactive VEX metric collection timed out", "error", err)
		} else {
			c.logger.Error("failed to collect inactive VEX metric", "error", err)
		}
		return
	}

	c.inactiveVEXMutex.Lock()
	c.inactiveVEXCache = inactiveCount
	c.inactiveVEXTime = time.Now()
	c.inactiveVEXMutex.Unlock()

	ch <- prometheus.MustNewConstMetric(
		c.inactiveVEXDesc,
		prometheus.GaugeValue,
		float64(inactiveCount),
	)
}

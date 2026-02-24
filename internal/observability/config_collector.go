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
	configCollectorOnce     sync.Once
	configCollectorInstance *ConfigCollector
)

// ConfigCollector collects metrics from the configuration on-demand when /metrics is scraped
type ConfigCollector struct {
	regsyncCfg *config.RegsyncConfig
	store      statestore.StateStore
	logger     *slog.Logger

	// Metric descriptors
	toleratedCVEsDesc            *prometheus.Desc
	expiredTolerationsDesc       *prometheus.Desc
	expiringTolerationsDesc      *prometheus.Desc
	tolerationsWithoutExpiryDesc *prometheus.Desc
	inactiveTolerationsDesc     *prometheus.Desc

	// Cache for inactive tolerations (10-minute TTL)
	inactiveTolerationsMutex sync.RWMutex
	inactiveTolerationsCache int
	inactiveTolerationsTime  time.Time
	inactiveTolerationsTTL   time.Duration
}

// NewConfigCollector creates a new configuration metrics collector
func NewConfigCollector(regsyncCfg *config.RegsyncConfig, store statestore.StateStore, logger *slog.Logger) *ConfigCollector {
	return &ConfigCollector{
		regsyncCfg:              regsyncCfg,
		store:                   store,
		logger:                  logger,
		inactiveTolerationsTTL: 10 * time.Minute,
		toleratedCVEsDesc: prometheus.NewDesc(
			"suppline_tolerated_cves",
			"Current total number of CVEs that are tolerated in configuration",
			nil,
			nil,
		),
		expiredTolerationsDesc: prometheus.NewDesc(
			"suppline_expired_tolerations",
			"Number of expired tolerations per repository in configuration",
			[]string{"repository"},
			nil,
		),
		expiringTolerationsDesc: prometheus.NewDesc(
			"suppline_expiring_tolerations_soon",
			"Number of tolerations expiring within 7 days per repository in configuration",
			[]string{"repository"},
			nil,
		),
		tolerationsWithoutExpiryDesc: prometheus.NewDesc(
			"suppline_tolerations_without_expiry",
			"Number of tolerations without an expiry date per repository in configuration",
			[]string{"repository"},
			nil,
		),
		inactiveTolerationsDesc: prometheus.NewDesc(
			"suppline_inactive_tolerations",
			"Number of toleration CVE IDs defined in configuration that have never been applied to any digest",
			nil,
			nil,
		),
	}
}

// RegisterConfigCollector registers the configuration collector exactly once
func RegisterConfigCollector(regsyncCfg *config.RegsyncConfig, store statestore.StateStore, logger *slog.Logger) {
	configCollectorOnce.Do(func() {
		configCollectorInstance = NewConfigCollector(regsyncCfg, store, logger)
		prometheus.MustRegister(configCollectorInstance)
		logger.Info("configuration metrics collector registered")
	})
}

// Describe sends the metric descriptors to the provided channel
func (c *ConfigCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.toleratedCVEsDesc
	ch <- c.expiredTolerationsDesc
	ch <- c.expiringTolerationsDesc
	ch <- c.tolerationsWithoutExpiryDesc
	ch <- c.inactiveTolerationsDesc
}

// Collect sends current metrics from configuration to the provided channel
func (c *ConfigCollector) Collect(ch chan<- prometheus.Metric) {
	if c.regsyncCfg == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Collect tolerated CVEs metric
	c.collectToleratedCVEs(ch)

	// Collect toleration expiry metrics
	c.collectTolerationExpiry(ch)

	// Collect tolerations without expiry metric
	c.collectTolerationsWithoutExpiry(ch)

	// Collect inactive tolerations metric (needs store)
	if c.store != nil {
		if queryStore, ok := c.store.(statestore.StateStoreQuery); ok {
			c.collectInactiveTolerations(ctx, queryStore, ch)
		}
	}
}

func (c *ConfigCollector) collectToleratedCVEs(ch chan<- prometheus.Metric) {
	total := 0
	targets := c.regsyncCfg.GetTargetRepositories()
	for _, target := range targets {
		total += len(c.regsyncCfg.GetTolerationsForTarget(target))
	}

	ch <- prometheus.MustNewConstMetric(
		c.toleratedCVEsDesc,
		prometheus.GaugeValue,
		float64(total),
	)
}

func (c *ConfigCollector) collectTolerationExpiry(ch chan<- prometheus.Metric) {
	now := time.Now()
	threshold := now.Add(7 * 24 * time.Hour)
	targets := c.regsyncCfg.GetTargetRepositories()

	for _, target := range targets {
		tolerations := c.regsyncCfg.GetTolerationsForTarget(target)
		expired := 0
		expiring := 0

		for _, t := range tolerations {
			if t.ExpiresAt == nil {
				continue
			}

			expiresAt := time.Unix(*t.ExpiresAt, 0)
			if expiresAt.Before(now) {
				expired++
			} else if expiresAt.Before(threshold) {
				expiring++
			}
		}

		ch <- prometheus.MustNewConstMetric(
			c.expiredTolerationsDesc,
			prometheus.GaugeValue,
			float64(expired),
			target,
		)
		ch <- prometheus.MustNewConstMetric(
			c.expiringTolerationsDesc,
			prometheus.GaugeValue,
			float64(expiring),
			target,
		)
	}
}

func (c *ConfigCollector) collectTolerationsWithoutExpiry(ch chan<- prometheus.Metric) {
	targets := c.regsyncCfg.GetTargetRepositories()

	for _, target := range targets {
		tolerations := c.regsyncCfg.GetTolerationsForTarget(target)
		noExpiryCount := 0

		for _, t := range tolerations {
			if t.ExpiresAt == nil {
				noExpiryCount++
			}
		}

		ch <- prometheus.MustNewConstMetric(
			c.tolerationsWithoutExpiryDesc,
			prometheus.GaugeValue,
			float64(noExpiryCount),
			target,
		)
	}
}

func (c *ConfigCollector) collectInactiveTolerations(ctx context.Context, store statestore.StateStoreQuery, ch chan<- prometheus.Metric) {
	c.inactiveTolerationsMutex.RLock()
	if time.Since(c.inactiveTolerationsTime) < c.inactiveTolerationsTTL {
		cachedValue := c.inactiveTolerationsCache
		c.inactiveTolerationsMutex.RUnlock()
		ch <- prometheus.MustNewConstMetric(
			c.inactiveTolerationsDesc,
			prometheus.GaugeValue,
			float64(cachedValue),
		)
		return
	}
	c.inactiveTolerationsMutex.RUnlock()

	definedCVEIDs := make(map[string]bool)
	for _, toleration := range c.regsyncCfg.Defaults.Tolerate {
		definedCVEIDs[toleration.ID] = true
	}

	if c.regsyncCfg.Sync != nil {
		for _, sync := range c.regsyncCfg.Sync {
			for _, toleration := range sync.Tolerate {
				definedCVEIDs[toleration.ID] = true
			}
		}
	}

	cveIDSlice := make([]string, 0, len(definedCVEIDs))
	for cveID := range definedCVEIDs {
		cveIDSlice = append(cveIDSlice, cveID)
	}

	inactiveCount, err := store.GetInactiveTolerationsCount(ctx, cveIDSlice)
	if err != nil {
		if ctx.Err() != nil {
			c.logger.Debug("inactive tolerations metric collection timed out", "error", err)
		} else {
			c.logger.Error("failed to collect inactive tolerations metric", "error", err)
		}
		return
	}

	c.inactiveTolerationsMutex.Lock()
	c.inactiveTolerationsCache = inactiveCount
	c.inactiveTolerationsTime = time.Now()
	c.inactiveTolerationsMutex.Unlock()

	ch <- prometheus.MustNewConstMetric(
		c.inactiveTolerationsDesc,
		prometheus.GaugeValue,
		float64(inactiveCount),
	)
}

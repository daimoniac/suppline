package observability

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the application
type Metrics struct {
	// Queue metrics
	QueueDepth prometheus.Gauge
	QueueEnqueued prometheus.Counter
	QueueDequeued prometheus.Counter
	QueueCompleted prometheus.Counter
	QueueFailed prometheus.Counter

	// Scan metrics
	ScansTotal prometheus.Counter
	ScansFailed prometheus.Counter
	ScanDuration prometheus.Histogram

	// Policy metrics
	PolicyPassed prometheus.Counter
	PolicyFailed prometheus.Counter

	// Vulnerability metrics
	VulnerabilitiesFound *prometheus.CounterVec
	ToleratedCVEs prometheus.Counter

	// Attestation metrics
	AttestationsCreated *prometheus.CounterVec
	AttestationsFailed *prometheus.CounterVec

	// Discovery metrics
	ImagesDiscovered prometheus.Counter
	DiscoveryErrors prometheus.Counter

	// Worker metrics
	WorkerTasksProcessed prometheus.Counter
	WorkerErrors prometheus.Counter

	// Conditional scanning metrics
	ConditionalScanDecisionsTotal *prometheus.CounterVec
	ConditionalScanSkippedTotal *prometheus.CounterVec
	ConditionalScanEnqueuedTotal *prometheus.CounterVec
	ConditionalScanSkipAgeSeconds *prometheus.HistogramVec
}

var (
	metricsInstance *Metrics
	metricsOnce     sync.Once
)

// GetMetrics returns the singleton metrics instance
func GetMetrics() *Metrics {
	metricsOnce.Do(func() {
		metricsInstance = &Metrics{
			// Queue metrics
			QueueDepth: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "suppline_queue_depth",
				Help: "Current number of tasks in the queue",
			}),
			QueueEnqueued: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_queue_enqueued_total",
				Help: "Total number of tasks enqueued",
			}),
			QueueDequeued: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_queue_dequeued_total",
				Help: "Total number of tasks dequeued",
			}),
			QueueCompleted: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_queue_completed_total",
				Help: "Total number of tasks completed successfully",
			}),
			QueueFailed: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_queue_failed_total",
				Help: "Total number of tasks that failed",
			}),

			// Scan metrics
			ScansTotal: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_scans_total",
				Help: "Total number of scans performed",
			}),
			ScansFailed: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_scans_failed_total",
				Help: "Total number of scans that failed",
			}),
			ScanDuration: promauto.NewHistogram(prometheus.HistogramOpts{
				Name:    "suppline_scan_duration_seconds",
				Help:    "Duration of scan operations in seconds",
				Buckets: prometheus.ExponentialBuckets(1, 2, 10), // 1s to ~17min
			}),

			// Policy metrics
			PolicyPassed: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_policy_passed_total",
				Help: "Total number of images that passed policy evaluation",
			}),
			PolicyFailed: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_policy_failed_total",
				Help: "Total number of images that failed policy evaluation",
			}),

			// Vulnerability metrics
			VulnerabilitiesFound: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "suppline_vulnerabilities_found_total",
					Help: "Total number of vulnerabilities found by severity",
				},
				[]string{"severity"},
			),
			ToleratedCVEs: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_tolerated_cves_total",
				Help: "Total number of CVEs that were tolerated",
			}),

			// Attestation metrics
			AttestationsCreated: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "suppline_attestations_created_total",
					Help: "Total number of attestations created by type",
				},
				[]string{"type"}, // sbom, vulnerability
			),
			AttestationsFailed: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "suppline_attestations_failed_total",
					Help: "Total number of attestations that failed by type",
				},
				[]string{"type"},
			),

			// Discovery metrics
			ImagesDiscovered: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_images_discovered_total",
				Help: "Total number of images discovered",
			}),
			DiscoveryErrors: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_discovery_errors_total",
				Help: "Total number of discovery errors",
			}),

			// Worker metrics
			WorkerTasksProcessed: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_worker_tasks_processed_total",
				Help: "Total number of tasks processed by workers",
			}),
			WorkerErrors: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_worker_errors_total",
				Help: "Total number of worker errors",
			}),

			// Conditional scanning metrics
			ConditionalScanDecisionsTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "suppline_conditional_scan_decisions_total",
					Help: "Total number of conditional scan decisions made",
				},
				[]string{"decision", "reason"},
			),
			ConditionalScanSkippedTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "suppline_conditional_scan_skipped_total",
					Help: "Total number of images skipped by conditional scanning",
				},
				[]string{"repo"},
			),
			ConditionalScanEnqueuedTotal: promauto.NewCounterVec(
				prometheus.CounterOpts{
					Name: "suppline_conditional_scan_enqueued_total",
					Help: "Total number of images enqueued by conditional scanning",
				},
				[]string{"repo", "reason"},
			),
			ConditionalScanSkipAgeSeconds: promauto.NewHistogramVec(
				prometheus.HistogramOpts{
					Name:    "suppline_conditional_scan_skip_age_seconds",
					Help:    "Time since last scan for skipped images in seconds",
					Buckets: prometheus.ExponentialBuckets(3600, 2, 10), // 1h to ~42 days
				},
				[]string{"repo"},
			),
		}
	})
	return metricsInstance
}

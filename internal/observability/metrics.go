package observability

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metrics for the application
type Metrics struct {
	// Queue metrics
	QueueDepth     prometheus.Gauge
	QueueEnqueued  prometheus.Counter
	QueueDequeued  prometheus.Counter
	QueueCompleted prometheus.Counter
	QueueFailed    prometheus.Counter

	// Scan metrics
	ScansTotal   prometheus.Counter
	ScanDuration prometheus.Histogram

	// Policy metrics
	PolicyPassed prometheus.Counter

	// Attestation metrics
	AttestationsCreated *prometheus.CounterVec
	AttestationsFailed  *prometheus.CounterVec

	// Discovery metrics
	ImagesDiscovered prometheus.Counter
	DiscoveryErrors  prometheus.Counter

	// Worker metrics
	WorkerTasksProcessed prometheus.Counter
	WorkerErrors         prometheus.Counter

	// Triage metrics
	TriageRuns            *prometheus.CounterVec
	TriageTokens          prometheus.Counter
	TriagePushFailures    prometheus.Counter
	TriageBudgetExhausted prometheus.Gauge

	// Malicious-package feed metrics
	MaliciousLastSync   prometheus.Gauge
	MaliciousSyncErrors prometheus.Counter
	MaliciousPackages   *prometheus.GaugeVec
	MaliciousRescans    prometheus.Counter

	// CISA KEV feed metrics
	KEVLastSync   prometheus.Gauge
	KEVSyncErrors prometheus.Counter
	KEVEntries    prometheus.Gauge
	KEVRescans    prometheus.Counter
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

			TriageRuns: promauto.NewCounterVec(prometheus.CounterOpts{
				Name: "suppline_triage_runs_total",
				Help: "Triage runs by status",
			}, []string{"status"}),
			TriageTokens: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_triage_tokens_total",
				Help: "Tokens reported by the triage LLM",
			}),
			TriagePushFailures: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_triage_push_failures_total",
				Help: "Config-repo pushes rejected after retries",
			}),
			TriageBudgetExhausted: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "suppline_triage_budget_exhausted",
				Help: "1 when the daily triage token budget is exhausted",
			}),
			MaliciousLastSync: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "suppline_malicious_db_last_sync_success_timestamp_seconds",
				Help: "Unix time of the last successful malicious-packages sync",
			}),
			MaliciousSyncErrors: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_malicious_db_sync_errors_total",
				Help: "Total number of failed malicious-packages syncs",
			}),
			MaliciousPackages: promauto.NewGaugeVec(prometheus.GaugeOpts{
				Name: "suppline_malicious_db_packages",
				Help: "Number of packages with an active malicious-package advisory, by ecosystem",
			}, []string{"ecosystem"}),
			MaliciousRescans: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_malicious_rematch_rescans_total",
				Help: "Total number of rescans queued because a new malicious-package advisory matched a stored image",
			}),
			KEVLastSync: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "suppline_kev_last_sync_success_timestamp_seconds",
				Help: "Unix time of the last successful CISA KEV catalog sync",
			}),
			KEVSyncErrors: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_kev_sync_errors_total",
				Help: "Total number of failed CISA KEV catalog syncs",
			}),
			KEVEntries: promauto.NewGauge(prometheus.GaugeOpts{
				Name: "suppline_kev_entries",
				Help: "Number of CVEs in the CISA KEV catalog",
			}),
			KEVRescans: promauto.NewCounter(prometheus.CounterOpts{
				Name: "suppline_kev_rescans_total",
				Help: "Total number of rescans queued because a CVE in a stored image was added to the CISA KEV catalog",
			}),
		}
	})
	return metricsInstance
}

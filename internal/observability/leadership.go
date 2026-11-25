package observability

import (
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// leaderGauge is 1 on the leader and 0 on a standby. Alert when the sum over
// all instances is not 1.
var leaderGauge = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "suppline_leader",
	Help: "1 when this instance is the leader, 0 while it stands by",
})

var (
	isLeader atomic.Bool

	// standbyRegistry is what a standby exports: process metrics and the
	// leader gauge. Business metrics come only from the leader, so alerts and
	// dashboards see one suppline however many instances run.
	standbyRegistry = func() *prometheus.Registry {
		r := prometheus.NewRegistry()
		r.MustRegister(
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
			leaderGauge,
		)
		return r
	}()
	standbyMetrics = promhttp.HandlerFor(standbyRegistry, promhttp.HandlerOpts{})
)

func init() {
	prometheus.MustRegister(leaderGauge)
}

// MarkLeader switches /metrics to the full registry and sets suppline_leader.
// Leadership only ever goes from standby to leader: an instance that loses
// it exits.
func MarkLeader() {
	leaderGauge.Set(1)
	isLeader.Store(true)
}

// IsLeader reports whether MarkLeader was called.
func IsLeader() bool {
	return isLeader.Load()
}

// metricsHandler serves the standby registry until this instance leads.
func metricsHandler() http.Handler {
	leader := promhttp.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLeader.Load() {
			leader.ServeHTTP(w, r)
			return
		}
		standbyMetrics.ServeHTTP(w, r)
	})
}

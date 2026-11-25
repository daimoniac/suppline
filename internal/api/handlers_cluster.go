package api

import (
	"context"
	"net/http"
	"time"

	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/statestore"
)

const (
	// clusterInstancesWindow is how long an instance stays listed after its
	// last heartbeat, so a crashed pod shows in red before it disappears.
	clusterInstancesWindow = 2 * time.Minute
	// heartbeatFreshFor marks an instance healthy only while its heartbeats,
	// sent every 10 s, keep arriving.
	heartbeatFreshFor = 30 * time.Second
)

type instanceLister interface {
	ListInstances(ctx context.Context, window time.Duration) ([]statestore.Instance, error)
}

// ClusterInstanceResponse is one running suppline instance.
type ClusterInstanceResponse struct {
	Hostname string
	Address  string
	Version  string
	Leader   bool
	// Status is the instance's own /health verdict at its last heartbeat.
	Status string
	// Healthy is true when Status is healthy and the last heartbeat is
	// recent.
	Healthy   bool
	StartedAt int64
	SeenAt    int64
}

// ClusterInstancesResponse lists the running instances, the leader first.
type ClusterInstancesResponse struct {
	Instances []ClusterInstanceResponse
}

// handleListClusterInstances lists the suppline instances sharing this database.
// @Summary Running suppline instances
// @Description Instances that sent a heartbeat in the last 2 minutes, the leader first. The leader runs the workers; standbys forward API requests to it. Healthy is false when the instance reports itself unhealthy or its last heartbeat is older than 30 s.
// @Tags Cluster
// @Produce json
// @Success 200 {object} ClusterInstancesResponse
// @Failure 401 {object} map[string]string "Unauthorized"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /cluster/instances [get]
func (s *APIServer) handleListClusterInstances(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	out := ClusterInstancesResponse{Instances: []ClusterInstanceResponse{}}
	if store, ok := s.stateStore.(instanceLister); ok {
		instances, err := store.ListInstances(r.Context(), clusterInstancesWindow)
		if err != nil {
			s.logger.Error("list cluster instances", "error", err.Error())
			s.respondStoreError(w, err, "Failed to list cluster instances")
			return
		}
		now := s.clock()
		for _, in := range instances {
			fresh := now.Sub(in.SeenAt) <= heartbeatFreshFor
			out.Instances = append(out.Instances, ClusterInstanceResponse{
				Hostname:  in.Hostname,
				Address:   in.Address,
				Version:   in.Version,
				Leader:    in.Leader,
				Status:    in.Status,
				Healthy:   fresh && in.Status == string(observability.StatusHealthy),
				StartedAt: in.StartedAt.Unix(),
				SeenAt:    in.SeenAt.Unix(),
			})
		}
	}
	s.respondJSON(w, http.StatusOK, out)
}

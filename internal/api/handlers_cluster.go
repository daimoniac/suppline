package api

import (
	"context"
	"net/http"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

// clusterInstancesWindow is how recently an instance must have sent a
// heartbeat to be listed. Instances send one every 10 s.
const clusterInstancesWindow = 30 * time.Second

type instanceLister interface {
	ListInstances(ctx context.Context, window time.Duration) ([]statestore.Instance, error)
}

// ClusterInstanceResponse is one running suppline instance.
type ClusterInstanceResponse struct {
	Hostname  string
	Address   string
	Version   string
	Leader    bool
	StartedAt int64
	SeenAt    int64
}

// ClusterInstancesResponse lists the running instances, the leader first.
type ClusterInstancesResponse struct {
	Instances []ClusterInstanceResponse
}

// handleListClusterInstances lists the suppline instances sharing this database.
// @Summary Running suppline instances
// @Description Instances that sent a heartbeat in the last 30 s, the leader first. The leader runs the workers; standbys forward API requests to it.
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
			s.respondError(w, http.StatusInternalServerError, "Failed to list cluster instances")
			return
		}
		for _, in := range instances {
			out.Instances = append(out.Instances, ClusterInstanceResponse{
				Hostname:  in.Hostname,
				Address:   in.Address,
				Version:   in.Version,
				Leader:    in.Leader,
				StartedAt: in.StartedAt.Unix(),
				SeenAt:    in.SeenAt.Unix(),
			})
		}
	}
	s.respondJSON(w, http.StatusOK, out)
}

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/observability"
	"github.com/daimoniac/suppline/internal/statestore"
)

type clusterInventoryRequest struct {
	Cluster string              `json:"cluster"`
	Images  []clusterImageInput `json:"images"`
}

type clusterImageInput struct {
	Namespace string `json:"namespace"`
	ImageRef  string `json:"image_ref"`
	Tag       string `json:"tag,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

// handleClusterInventory ingests a full runtime image snapshot for a cluster.
func (s *APIServer) handleClusterInventory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.respondError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if s.clusterInventory == nil {
		s.respondError(w, http.StatusNotImplemented, "cluster inventory storage is not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	defer r.Body.Close()

	var req clusterInventoryRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.respondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		s.respondError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if decoder.More() {
		s.respondError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	clusterName := strings.TrimSpace(req.Cluster)
	if clusterName == "" {
		s.respondError(w, http.StatusBadRequest, "cluster is required")
		return
	}
	if len(clusterName) > 255 {
		s.respondError(w, http.StatusBadRequest, "cluster must be 255 characters or fewer")
		return
	}
	if req.Images == nil {
		s.respondError(w, http.StatusBadRequest, "images is required")
		return
	}

	images := make([]statestore.ClusterImageEntry, 0, len(req.Images))
	for _, image := range req.Images {
		namespace := strings.TrimSpace(image.Namespace)
		if namespace == "" {
			s.respondError(w, http.StatusBadRequest, "namespace is required for each image")
			return
		}

		imageRef := strings.TrimSpace(image.ImageRef)
		if imageRef == "" {
			s.respondError(w, http.StatusBadRequest, "image_ref is required for each image")
			return
		}
		if len(namespace) > 255 {
			s.respondError(w, http.StatusBadRequest, "namespace must be 255 characters or fewer")
			return
		}
		if len(imageRef) > 1024 {
			s.respondError(w, http.StatusBadRequest, "image_ref must be 1024 characters or fewer")
			return
		}

		images = append(images, statestore.ClusterImageEntry{
			Namespace: namespace,
			ImageRef:  imageRef,
			Tag:       strings.TrimSpace(image.Tag),
			Digest:    strings.TrimSpace(image.Digest),
		})
	}

	if err := s.clusterInventory.RecordClusterInventory(r.Context(), clusterName, images, time.Now().UTC()); err != nil {
		s.logger.Error("failed to record cluster inventory",
			"cluster", clusterName,
			"error", err.Error())
		s.respondError(w, http.StatusInternalServerError, "failed to record cluster inventory")
		return
	}

	observability.GetMetrics().ClusterLastSync.WithLabelValues(clusterName).Set(float64(time.Now().Unix()))

	s.respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "ok",
		"cluster":         clusterName,
		"images_recorded": len(images),
	})
}

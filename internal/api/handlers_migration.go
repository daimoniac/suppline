package api

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/daimoniac/suppline/internal/integration"
)

// mirrorFromRequest returns the registry (with path prefix) the cluster will
// pull from: the mirror query parameter, else SUPPLINE_REGISTRY_URL. The second
// result is true when the caller named it, so a literal target is written
// instead of the environment template.
func mirrorFromRequest(r *http.Request) (mirror string, explicit bool) {
	if mirror = strings.TrimSpace(r.URL.Query().Get("mirror")); mirror != "" {
		return strings.Trim(mirror, "/"), true
	}
	return strings.Trim(strings.TrimSpace(os.Getenv("SUPPLINE_REGISTRY_URL")), "/"), false
}

// handleGetClusterMigration plans moving one cluster onto the mirror.
// @Summary Plan a cluster's move onto the mirror
// @Description Turn the images a cluster agent reports as running into sync entries for suppline.yml. Images already copied by a sync entry, and images that already come from the mirror, are left out. The response is a commented YAML snippet to paste under `sync:`; pods are pointed at the mirror by the policy from /integration/kyverno/mirror-rewrite.
// @Tags Integration
// @Produce plain
// @Param name path string true "Cluster name"
// @Param mirror query string false "Mirror registry with path prefix, as in a sync target. Defaults to SUPPLINE_REGISTRY_URL; without either, entries use the {{ env \"SUPPLINE_REGISTRY_URL\" }} template."
// @Param exclude query string false "Comma-separated registries to leave out, for images you build yourself"
// @Success 200 {string} string "YAML snippet"
// @Failure 400 {object} map[string]string "Invalid cluster name"
// @Failure 404 {object} map[string]string "Unknown cluster"
// @Failure 501 {object} map[string]string "Cluster inventory not configured"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security BearerAuth
// @Router /integration/kubernetes/clusters/{name}/migration [get]
func (s *APIServer) handleGetClusterMigration(w http.ResponseWriter, r *http.Request) {
	if s.clusterInventory == nil {
		s.respondError(w, http.StatusNotImplemented, "cluster inventory storage is not configured")
		return
	}

	const prefix = "/api/v1/integration/kubernetes/clusters/"
	encoded := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/migration"), "/")
	name, err := url.PathUnescape(encoded)
	name = strings.TrimSpace(name)
	if err != nil || name == "" {
		s.respondError(w, http.StatusBadRequest, "Invalid cluster name")
		return
	}

	summaries, err := s.clusterInventory.ListClusterSummaries(r.Context())
	if err != nil {
		s.respondStoreError(w, err, fmt.Sprintf("Failed to list cluster summaries: %v", err))
		return
	}
	known := false
	for _, summary := range summaries {
		if summary.Name == name {
			known = true
			break
		}
	}
	if !known {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("cluster %q has not reported an inventory", name))
		return
	}

	reported, err := s.clusterInventory.ListClusterImages(r.Context(), name)
	if err != nil {
		s.respondStoreError(w, err, fmt.Sprintf("Failed to list cluster images: %v", err))
		return
	}
	images := make([]integration.RunningImage, 0, len(reported))
	for _, image := range reported {
		images = append(images, integration.RunningImage{ImageRef: image.ImageRef, Tag: image.Tag, Digest: image.Digest})
	}

	if raw := strings.TrimSpace(r.URL.Query().Get("exclude")); raw != "" {
		images = integration.ExcludeRegistries(images, strings.Split(raw, ","))
	}

	var configured []integration.ConfiguredSource
	if cfg := s.runningConfig(); cfg != nil {
		_ = cfg.ForEachActive(func(i int) error {
			entry := cfg.Sync[i]
			configured = append(configured, integration.ConfiguredSource{Source: entry.Source, Type: entry.Type})
			return nil
		})
	}

	mirror, explicit := mirrorFromRequest(r)
	targetPrefix := ""
	if explicit {
		targetPrefix = mirror
	}
	plan := integration.PlanMigration(images, mirror, targetPrefix, configured)

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(plan.YAML(name)))
}

// handleGenerateMirrorRewritePolicy generates the Kyverno policy that points pods at the mirror.
// @Summary Generate Kyverno mirror rewrite policy
// @Description Generate a Kyverno MutatingPolicy that rewrites pod images from the given registries to the mirror, using the names the migration plan syncs them under. Only namespaces labeled suppline.cloud/mirror=true are affected unless scope=all. The policy fails open and mutates pods only, so GitOps tools see no drift. Apply it after the images are synced.
// @Tags Integration
// @Produce plain
// @Param mirror query string false "Mirror registry with path prefix, as in a sync target. Defaults to SUPPLINE_REGISTRY_URL."
// @Param registries query string false "Comma-separated source registries to redirect (default docker.io)"
// @Param scope query string false "labeled (default): only namespaces labeled suppline.cloud/mirror=true; all: every non-system namespace" Enums(labeled,all)
// @Success 200 {string} string "Kyverno MutatingPolicy YAML"
// @Failure 400 {object} map[string]string "Invalid mirror, registries or scope"
// @Failure 401 {object} map[string]string "Unauthorized"
// @Security BearerAuth
// @Router /integration/kyverno/mirror-rewrite [get]
func (s *APIServer) handleGenerateMirrorRewritePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	mirror, _ := mirrorFromRequest(r)
	if mirror == "" {
		s.respondError(w, http.StatusBadRequest, "mirror is required: pass ?mirror= or set SUPPLINE_REGISTRY_URL")
		return
	}

	var registries []string
	if raw := strings.TrimSpace(r.URL.Query().Get("registries")); raw != "" {
		registries = strings.Split(raw, ",")
	}

	allNamespaces := false
	switch scope := r.URL.Query().Get("scope"); scope {
	case "", "labeled":
	case "all":
		allNamespaces = true
	default:
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("scope %q must be labeled or all", scope))
		return
	}

	policy, err := integration.GenerateMirrorRewritePolicy(integration.RewriteOptions{
		Mirror:        mirror,
		Registries:    registries,
		AllNamespaces: allNamespaces,
	})
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(policy))
}

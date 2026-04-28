// Package mcp exposes suppline's REST API to MCP clients.
//
// It contains a minimal HTTP client for the suppline API and an MCP server
// that registers one tool per user-facing question.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client is a small typed client for the suppline REST API.
//
// It is deliberately narrow: each method maps 1:1 to an API endpoint used by
// an MCP tool. Responses are returned as json.RawMessage so the MCP server can
// pass them back to the LLM without repeated marshal/unmarshal round-trips.
type Client struct {
	baseURL    *url.URL
	apiKey     string
	httpClient *http.Client
}

// ClientConfig configures a Client.
type ClientConfig struct {
	// BaseURL is the suppline API base, e.g. "http://localhost:8080". Required.
	BaseURL string
	// APIKey, if non-empty, is sent as "Authorization: Bearer <APIKey>".
	APIKey string
	// Timeout for each HTTP request. Defaults to 30s when zero.
	Timeout time.Duration
	// HTTPClient allows injecting a custom transport (tests). Optional.
	HTTPClient *http.Client
}

// NewClient constructs a Client from cfg.
func NewClient(cfg ClientConfig) (*Client, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return nil, fmt.Errorf("mcp: client base url is required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("mcp: parse base url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("mcp: base url must be absolute, got %q", cfg.BaseURL)
	}

	hc := cfg.HTTPClient
	if hc == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		hc = &http.Client{Timeout: timeout}
	}

	return &Client{
		baseURL:    u,
		apiKey:     cfg.APIKey,
		httpClient: hc,
	}, nil
}

// APIError represents a non-2xx response from the suppline API.
type APIError struct {
	StatusCode int
	Body       string
	URL        string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("mcp: suppline API %s returned %d: %s", e.URL, e.StatusCode, e.Body)
}

func (c *Client) endpoint(path string) string {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String()
}

func (c *Client) doJSON(ctx context.Context, method, path string, query url.Values, body any) (json.RawMessage, error) {
	target := c.endpoint(path)
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("mcp: marshal request body: %w", err)
		}
		bodyReader = strings.NewReader(string(data))
	}

	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("mcp: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if bodyReader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcp: http request: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("mcp: read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Body:       strings.TrimSpace(string(raw)),
			URL:        target,
		}
	}

	// Some endpoints (e.g. 204 DELETE) return no content.
	if len(raw) == 0 {
		return nil, nil
	}
	return json.RawMessage(raw), nil
}

// --- Query helpers -------------------------------------------------------

func addNonEmpty(q url.Values, key, value string) {
	if strings.TrimSpace(value) != "" {
		q.Set(key, value)
	}
}

func addIntIfSet(q url.Values, key string, value int) {
	if value > 0 {
		q.Set(key, strconv.Itoa(value))
	}
}

func addBoolIfSet(q url.Values, key string, value *bool) {
	if value != nil {
		q.Set(key, strconv.FormatBool(*value))
	}
}

// --- Scans ---------------------------------------------------------------

// ListScansParams filters for GET /api/v1/scans.
type ListScansParams struct {
	Repository   string
	PolicyStatus string // "passed", "failed", "pending"
	InUseMode    string // "all", "in_use", "not_in_use", "in_use_newer"
	MaxAge       int    // seconds
	SortBy       string
	Limit        int
	Offset       int
}

// ListScans returns /api/v1/scans with the given filters applied.
func (c *Client) ListScans(ctx context.Context, p ListScansParams) (json.RawMessage, error) {
	q := url.Values{}
	addNonEmpty(q, "repository", p.Repository)
	addNonEmpty(q, "policy_status", p.PolicyStatus)
	addNonEmpty(q, "in_use_mode", p.InUseMode)
	addIntIfSet(q, "max_age", p.MaxAge)
	addNonEmpty(q, "sort_by", p.SortBy)
	addIntIfSet(q, "limit", p.Limit)
	addIntIfSet(q, "offset", p.Offset)
	return c.doJSON(ctx, http.MethodGet, "/api/v1/scans", q, nil)
}

// GetScan fetches /api/v1/scans/{digest}.
func (c *Client) GetScan(ctx context.Context, digest string) (json.RawMessage, error) {
	if strings.TrimSpace(digest) == "" {
		return nil, fmt.Errorf("mcp: digest is required")
	}
	return c.doJSON(ctx, http.MethodGet, "/api/v1/scans/"+url.PathEscape(digest), nil, nil)
}

// ListFailedImages fetches /api/v1/images/failed.
func (c *Client) ListFailedImages(ctx context.Context, limit int) (json.RawMessage, error) {
	q := url.Values{}
	addIntIfSet(q, "limit", limit)
	return c.doJSON(ctx, http.MethodGet, "/api/v1/images/failed", q, nil)
}

// --- VEX -----------------------------------------------------------------

// ListVEXParams filters for GET /api/v1/vex.
type ListVEXParams struct {
	CVEID         string
	Repository    string
	ExpiringSoon  *bool
	Expired       *bool
}

// ListVEX fetches /api/v1/vex.
func (c *Client) ListVEX(ctx context.Context, p ListVEXParams) (json.RawMessage, error) {
	q := url.Values{}
	addNonEmpty(q, "cve_id", p.CVEID)
	addNonEmpty(q, "repository", p.Repository)
	addBoolIfSet(q, "expiring_soon", p.ExpiringSoon)
	addBoolIfSet(q, "expired", p.Expired)
	return c.doJSON(ctx, http.MethodGet, "/api/v1/vex", q, nil)
}

// ListInactiveVEX fetches /api/v1/vex/inactive.
func (c *Client) ListInactiveVEX(ctx context.Context) (json.RawMessage, error) {
	return c.doJSON(ctx, http.MethodGet, "/api/v1/vex/inactive", nil, nil)
}

// --- Vulnerabilities -----------------------------------------------------

// QueryVulnerabilitiesParams filters for GET /api/v1/vulnerabilities.
type QueryVulnerabilitiesParams struct {
	CVEID          string
	Severity       string // CRITICAL|HIGH|MEDIUM|LOW
	PackageName    string
	Repository     string
	SortBy         string // images (default), cve_id, severity
	SortDir        string // asc|desc
	Limit          int
	Offset         int
	IncludeDigests *bool
	MaxDigests     int
}

// QueryVulnerabilities fetches /api/v1/vulnerabilities.
func (c *Client) QueryVulnerabilities(ctx context.Context, p QueryVulnerabilitiesParams) (json.RawMessage, error) {
	q := url.Values{}
	addNonEmpty(q, "cve_id", p.CVEID)
	addNonEmpty(q, "severity", p.Severity)
	addNonEmpty(q, "package_name", p.PackageName)
	addNonEmpty(q, "repository", p.Repository)
	addNonEmpty(q, "sort_by", p.SortBy)
	addNonEmpty(q, "sort_dir", p.SortDir)
	addIntIfSet(q, "limit", p.Limit)
	addIntIfSet(q, "offset", p.Offset)
	addBoolIfSet(q, "include_digests", p.IncludeDigests)
	addIntIfSet(q, "max_digests", p.MaxDigests)
	return c.doJSON(ctx, http.MethodGet, "/api/v1/vulnerabilities", q, nil)
}

// GetVulnerability fetches /api/v1/vulnerabilities/{cve_id}.
func (c *Client) GetVulnerability(ctx context.Context, cveID string, repository, severity, packageName string, maxDigests int) (json.RawMessage, error) {
	if strings.TrimSpace(cveID) == "" {
		return nil, fmt.Errorf("mcp: cve_id is required")
	}
	q := url.Values{}
	addNonEmpty(q, "repository", repository)
	addNonEmpty(q, "severity", severity)
	addNonEmpty(q, "package_name", packageName)
	addIntIfSet(q, "max_digests", maxDigests)
	return c.doJSON(ctx, http.MethodGet, "/api/v1/vulnerabilities/"+url.PathEscape(cveID), q, nil)
}

// GetVulnerabilityStats fetches /api/v1/vulnerabilities/stats.
func (c *Client) GetVulnerabilityStats(ctx context.Context) (json.RawMessage, error) {
	return c.doJSON(ctx, http.MethodGet, "/api/v1/vulnerabilities/stats", nil, nil)
}

// --- Repositories --------------------------------------------------------

// ListRepositoriesParams filters for GET /api/v1/repositories.
type ListRepositoriesParams struct {
	Search       string
	PolicyStatus string
	InUseMode    string
	MaxAge       int
	SortBy       string
	Limit        int
	Offset       int
}

// ListRepositories fetches /api/v1/repositories.
func (c *Client) ListRepositories(ctx context.Context, p ListRepositoriesParams) (json.RawMessage, error) {
	q := url.Values{}
	addNonEmpty(q, "search", p.Search)
	addNonEmpty(q, "policy_status", p.PolicyStatus)
	addNonEmpty(q, "in_use_mode", p.InUseMode)
	addIntIfSet(q, "max_age", p.MaxAge)
	addNonEmpty(q, "sort_by", p.SortBy)
	addIntIfSet(q, "limit", p.Limit)
	addIntIfSet(q, "offset", p.Offset)
	return c.doJSON(ctx, http.MethodGet, "/api/v1/repositories", q, nil)
}

// GetRepositoryParams filters for GET /api/v1/repositories/{name}.
type GetRepositoryParams struct {
	Search    string
	InUseMode string
	Limit     int
	Offset    int
}

// GetRepository fetches /api/v1/repositories/{name}.
func (c *Client) GetRepository(ctx context.Context, name string, p GetRepositoryParams) (json.RawMessage, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("mcp: repository name is required")
	}
	q := url.Values{}
	addNonEmpty(q, "search", p.Search)
	addNonEmpty(q, "in_use_mode", p.InUseMode)
	addIntIfSet(q, "limit", p.Limit)
	addIntIfSet(q, "offset", p.Offset)
	return c.doJSON(ctx, http.MethodGet, "/api/v1/repositories/"+escapeRepoPath(name), q, nil)
}

// escapeRepoPath percent-encodes a repository name while preserving the
// slashes that separate path components (e.g. "kubernetes/pause").
func escapeRepoPath(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// --- Kubernetes integration ---------------------------------------------

// ListKubernetesClusters fetches /api/v1/integration/kubernetes/clusters.
func (c *Client) ListKubernetesClusters(ctx context.Context) (json.RawMessage, error) {
	return c.doJSON(ctx, http.MethodGet, "/api/v1/integration/kubernetes/clusters", nil, nil)
}

// GetClusterImages fetches /api/v1/integration/kubernetes/clusters/{name}/images.
func (c *Client) GetClusterImages(ctx context.Context, name string) (json.RawMessage, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("mcp: cluster name is required")
	}
	path := "/api/v1/integration/kubernetes/clusters/" + url.PathEscape(name) + "/images"
	return c.doJSON(ctx, http.MethodGet, path, nil, nil)
}

// --- Write operations ----------------------------------------------------

// TriggerScanRequest mirrors api.TriggerScanRequest.
type TriggerScanRequest struct {
	Digest     string `json:"digest,omitempty"`
	Repository string `json:"repository,omitempty"`
}

// TriggerScan posts to /api/v1/scans/trigger.
func (c *Client) TriggerScan(ctx context.Context, req TriggerScanRequest) (json.RawMessage, error) {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/scans/trigger", nil, req)
}

// ReevaluatePolicyRequest mirrors api.ReevaluatePolicyRequest.
type ReevaluatePolicyRequest struct {
	Repository string `json:"repository,omitempty"`
}

// ReevaluatePolicy posts to /api/v1/policy/reevaluate.
func (c *Client) ReevaluatePolicy(ctx context.Context, req ReevaluatePolicyRequest) (json.RawMessage, error) {
	return c.doJSON(ctx, http.MethodPost, "/api/v1/policy/reevaluate", nil, req)
}

// --- Tasks ----------------------------------------------------------------

// GetSemverUpdateTasks fetches /api/v1/tasks/semver-updates.
// For each suppline.yml sync entry with tags.semverRange, the API compares
// constraints to cluster runtime and returns suggested_ranges and status
// (e.g. tighten, out_of_bounds, no_runtime_data).
func (c *Client) GetSemverUpdateTasks(ctx context.Context) (json.RawMessage, error) {
	return c.doJSON(ctx, http.MethodGet, "/api/v1/tasks/semver-updates", nil, nil)
}

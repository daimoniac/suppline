package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerTools attaches all suppline tools to srv. Write tools are only
// registered when allowWrites is true.
func registerTools(srv *mcpsdk.Server, c *Client, allowWrites bool, logger *slog.Logger) {
	registerReadOnlyTools(srv, c, logger)
	if allowWrites {
		registerWriteTools(srv, c, logger)
	}
}

// --- Inputs --------------------------------------------------------------

// ListScansInput is the schema for the list_scans tool.
type ListScansInput struct {
	Repository   string `json:"repository,omitempty" jsonschema:"filter by repository (target mirror name, e.g. myregistry.com/nginx)"`
	PolicyStatus string `json:"policy_status,omitempty" jsonschema:"policy status filter: 'passed', 'failed', or 'pending'"`
	InUseMode    string `json:"in_use_mode,omitempty" jsonschema:"runtime usage filter: 'all' (default), 'in_use', 'not_in_use', 'in_use_newer'"`
	MaxAge       int    `json:"max_age,omitempty" jsonschema:"maximum age of last scan in seconds (0 = no limit)"`
	SortBy       string `json:"sort_by,omitempty" jsonschema:"sort order, e.g. 'scanned_at_desc' (default)"`
	Limit        int    `json:"limit,omitempty" jsonschema:"maximum results to return (default 100)"`
	Offset       int    `json:"offset,omitempty" jsonschema:"pagination offset"`
}

// GetScanInput is the schema for the get_scan tool.
type GetScanInput struct {
	Digest string `json:"digest" jsonschema:"image digest, e.g. 'sha256:abc123...'"`
}

// ListFailedImagesInput is the schema for the list_failed_images tool.
type ListFailedImagesInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"maximum results to return (default 100)"`
}

// ListVEXInput is the schema for the list_vex_statements tool.
type ListVEXInput struct {
	CVEID        string `json:"cve_id,omitempty" jsonschema:"filter by CVE ID (partial match)"`
	Repository   string `json:"repository,omitempty" jsonschema:"filter by repository (partial match)"`
	ExpiringSoon *bool  `json:"expiring_soon,omitempty" jsonschema:"when true, only VEX statements expiring within 7 days"`
	Expired      *bool  `json:"expired,omitempty" jsonschema:"when true, only VEX statements whose expires_at has passed"`
}

// Empty is an empty-object input for tools with no parameters.
type Empty struct{}

// QueryVulnerabilitiesInput is the schema for the query_vulnerabilities tool.
type QueryVulnerabilitiesInput struct {
	CVEID          string `json:"cve_id,omitempty" jsonschema:"filter by CVE ID"`
	Severity       string `json:"severity,omitempty" jsonschema:"severity filter: CRITICAL, HIGH, MEDIUM, or LOW"`
	PackageName    string `json:"package_name,omitempty" jsonschema:"filter by package name"`
	Repository     string `json:"repository,omitempty" jsonschema:"filter by repository"`
	SortBy         string `json:"sort_by,omitempty" jsonschema:"sort: 'images' (default), 'cve_id', 'severity'"`
	SortDir        string `json:"sort_dir,omitempty" jsonschema:"sort direction: 'desc' (default) or 'asc'"`
	Limit          int    `json:"limit,omitempty" jsonschema:"maximum CVE groups returned (default 10)"`
	Offset         int    `json:"offset,omitempty" jsonschema:"pagination offset"`
	IncludeDigests *bool  `json:"include_digests,omitempty" jsonschema:"when true, include per-digest details; otherwise return summaries only"`
	MaxDigests     int    `json:"max_digests,omitempty" jsonschema:"cap on total returned digests per CVE (default 200)"`
}

// GetVulnerabilityInput is the schema for the get_vulnerability tool.
type GetVulnerabilityInput struct {
	CVEID       string `json:"cve_id" jsonschema:"CVE ID to fetch details for, e.g. 'CVE-2024-56171'"`
	Repository  string `json:"repository,omitempty" jsonschema:"optional repository filter"`
	Severity    string `json:"severity,omitempty" jsonschema:"optional severity filter"`
	PackageName string `json:"package_name,omitempty" jsonschema:"optional package-name filter"`
	MaxDigests  int    `json:"max_digests,omitempty" jsonschema:"cap on total returned digests (default 500)"`
}

// ListRepositoriesInput is the schema for the list_repositories tool.
type ListRepositoriesInput struct {
	Search       string `json:"search,omitempty" jsonschema:"filter by repository name (partial match)"`
	PolicyStatus string `json:"policy_status,omitempty" jsonschema:"policy status filter: 'passed', 'failed', or 'pending'"`
	InUseMode    string `json:"in_use_mode,omitempty" jsonschema:"runtime usage filter: 'all' (default), 'in_use', 'not_in_use', 'in_use_newer'"`
	MaxAge       int    `json:"max_age,omitempty" jsonschema:"maximum age of last scan in seconds (0 = no limit)"`
	SortBy       string `json:"sort_by,omitempty" jsonschema:"sort order, e.g. 'age_desc' (default)"`
	Limit        int    `json:"limit,omitempty" jsonschema:"maximum results to return (default 100)"`
	Offset       int    `json:"offset,omitempty" jsonschema:"pagination offset"`
}

// GetRepositoryInput is the schema for the get_repository tool.
type GetRepositoryInput struct {
	Name      string `json:"name" jsonschema:"repository name (as configured in suppline.yml sync target)"`
	Search    string `json:"search,omitempty" jsonschema:"filter tags by name (partial match)"`
	InUseMode string `json:"in_use_mode,omitempty" jsonschema:"tag list filter: 'all', 'in_use', 'not_in_use', 'in_use_newer'"`
	Limit     int    `json:"limit,omitempty" jsonschema:"maximum tag results (default 100)"`
	Offset    int    `json:"offset,omitempty" jsonschema:"pagination offset"`
}

// GetClusterImagesInput is the schema for the get_cluster_images tool.
type GetClusterImagesInput struct {
	Name string `json:"name" jsonschema:"Kubernetes cluster name as reported to suppline"`
}

// TriggerRescanInput is the schema for the trigger_rescan tool.
type TriggerRescanInput struct {
	Digest     string `json:"digest,omitempty" jsonschema:"specific digest to rescan (mutually exclusive with repository)"`
	Repository string `json:"repository,omitempty" jsonschema:"rescan all images in this repository (mutually exclusive with digest)"`
}

// ReevaluatePolicyInput is the schema for the reevaluate_policy tool.
type ReevaluatePolicyInput struct {
	Repository string `json:"repository,omitempty" jsonschema:"optional repository filter; omit to re-evaluate policy for all scans"`
}

// --- Registration --------------------------------------------------------

func registerReadOnlyTools(srv *mcpsdk.Server, c *Client, logger *slog.Logger) {
	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "list_scans",
		Title:       "List scans",
		Description: "List image scans with optional filters. Combine policy_status='failed' and in_use_mode='in_use' to find policy failures for images currently deployed to runtime.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in ListScansInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.ListScans(ctx, ListScansParams{
			Repository:   in.Repository,
			PolicyStatus: in.PolicyStatus,
			InUseMode:    in.InUseMode,
			MaxAge:       in.MaxAge,
			SortBy:       in.SortBy,
			Limit:        in.Limit,
			Offset:       in.Offset,
		})
		return wrapResult(logger, "list_scans", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "get_scan",
		Title:       "Get scan",
		Description: "Fetch the most recent scan record for a specific image digest, including vulnerabilities, applied VEX, policy status, and runtime usage.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in GetScanInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.GetScan(ctx, in.Digest)
		return wrapResult(logger, "get_scan", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "list_failed_images",
		Title:       "List failed images",
		Description: "List images whose most recent scan failed policy evaluation. Equivalent to list_scans with policy_status='failed'.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in ListFailedImagesInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.ListFailedImages(ctx, in.Limit)
		return wrapResult(logger, "list_failed_images", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "list_vex_statements",
		Title:       "List VEX statements",
		Description: "List configured VEX statements, grouped by CVE with affected repositories. Set expired=true to find expired statements, expiring_soon=true for the next 7 days.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in ListVEXInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.ListVEX(ctx, ListVEXParams{
			CVEID:        in.CVEID,
			Repository:   in.Repository,
			ExpiringSoon: in.ExpiringSoon,
			Expired:      in.Expired,
		})
		return wrapResult(logger, "list_vex_statements", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "list_inactive_vex",
		Title:       "List inactive VEX statements",
		Description: "List VEX statements defined in suppline.yml that have never been applied to any scanned image.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ Empty) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.ListInactiveVEX(ctx)
		return wrapResult(logger, "list_inactive_vex", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "query_vulnerabilities",
		Title:       "Query vulnerabilities",
		Description: "Search vulnerabilities across all latest scans, grouped by CVE with affected image counts.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in QueryVulnerabilitiesInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.QueryVulnerabilities(ctx, QueryVulnerabilitiesParams{
			CVEID:          in.CVEID,
			Severity:       in.Severity,
			PackageName:    in.PackageName,
			Repository:     in.Repository,
			SortBy:         in.SortBy,
			SortDir:        in.SortDir,
			Limit:          in.Limit,
			Offset:         in.Offset,
			IncludeDigests: in.IncludeDigests,
			MaxDigests:     in.MaxDigests,
		})
		return wrapResult(logger, "query_vulnerabilities", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "get_vulnerability",
		Title:       "Get vulnerability",
		Description: "Fetch the affected repositories and digests for a single CVE.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in GetVulnerabilityInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.GetVulnerability(ctx, in.CVEID, in.Repository, in.Severity, in.PackageName, in.MaxDigests)
		return wrapResult(logger, "get_vulnerability", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "vulnerability_stats",
		Title:       "Vulnerability stats",
		Description: "Counts of unique CVE IDs by severity across all latest scans.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ Empty) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.GetVulnerabilityStats(ctx)
		return wrapResult(logger, "vulnerability_stats", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "list_repositories",
		Title:       "List repositories",
		Description: "List mirrored repositories with aggregated vulnerability and policy status.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in ListRepositoriesInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.ListRepositories(ctx, ListRepositoriesParams{
			Search:       in.Search,
			PolicyStatus: in.PolicyStatus,
			InUseMode:    in.InUseMode,
			MaxAge:       in.MaxAge,
			SortBy:       in.SortBy,
			Limit:        in.Limit,
			Offset:       in.Offset,
		})
		return wrapResult(logger, "list_repositories", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "get_repository",
		Title:       "Get repository",
		Description: "Fetch a repository with its tags, scan results, and runtime usage.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in GetRepositoryInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.GetRepository(ctx, in.Name, GetRepositoryParams{
			Search:    in.Search,
			InUseMode: in.InUseMode,
			Limit:     in.Limit,
			Offset:    in.Offset,
		})
		return wrapResult(logger, "get_repository", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "list_kubernetes_clusters",
		Title:       "List Kubernetes clusters",
		Description: "List Kubernetes clusters that have reported runtime image inventory, with their latest sync time and image count.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ Empty) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.ListKubernetesClusters(ctx)
		return wrapResult(logger, "list_kubernetes_clusters", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "get_cluster_images",
		Title:       "Get cluster images",
		Description: "List runtime image references currently reported by a specific Kubernetes cluster.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in GetClusterImagesInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.GetClusterImages(ctx, in.Name)
		return wrapResult(logger, "get_cluster_images", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:  "get_semver_updates",
		Title: "Get semver range update tasks",
		Description: "Fetch server-computed suggestions for suppline.yml sync entries that use tags.semverRange: " +
			"compare configured ranges to versions running in connected clusters and return " +
			"current_ranges, suggested_ranges, runtime_versions, and per-entry status (e.g. tighten, out_of_bounds, " +
			"no_runtime_data). " +
			"Use this when the user wants to tighten semver ranges, remove or narrow old image version pins, " +
			"or align sync mirror tags with what is actually deployed at runtime. " +
			"Prefer this response (including the ai_agent_prompt field) over inventing version changes.",
		Annotations: &mcpsdk.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, _ Empty) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.GetSemverUpdateTasks(ctx)
		return wrapResult(logger, "get_semver_updates", raw, err)
	})
}

func registerWriteTools(srv *mcpsdk.Server, c *Client, logger *slog.Logger) {
	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "trigger_rescan",
		Title:       "Trigger rescan",
		Description: "Queue a rescan for a specific digest or all images in a repository. Provide exactly one of 'digest' or 'repository'.",
		Annotations: &mcpsdk.ToolAnnotations{
			DestructiveHint: ptr(false),
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in TriggerRescanInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.TriggerScan(ctx, TriggerScanRequest{
			Digest:     in.Digest,
			Repository: in.Repository,
		})
		return wrapResult(logger, "trigger_rescan", raw, err)
	})

	mcpsdk.AddTool(srv, &mcpsdk.Tool{
		Name:        "reevaluate_policy",
		Title:       "Re-evaluate policy",
		Description: "Re-apply the current suppline.yml policy and VEX configuration to existing scans. Optionally scoped to a single repository.",
		Annotations: &mcpsdk.ToolAnnotations{
			DestructiveHint: ptr(false),
			IdempotentHint:  false,
		},
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in ReevaluatePolicyInput) (*mcpsdk.CallToolResult, any, error) {
		raw, err := c.ReevaluatePolicy(ctx, ReevaluatePolicyRequest{Repository: in.Repository})
		return wrapResult(logger, "reevaluate_policy", raw, err)
	})
}

// wrapResult unmarshals a raw JSON response into a generic any value, so the
// SDK can serve it as both structured content (json-compatible) and text
// content (pretty-printed) to the LLM.
func wrapResult(logger *slog.Logger, tool string, raw json.RawMessage, err error) (*mcpsdk.CallToolResult, any, error) {
	if err != nil {
		logger.Error("mcp tool call failed", "tool", tool, "error", err)
		return nil, nil, fmt.Errorf("%s: %w", tool, err)
	}
	if len(raw) == 0 {
		// 204 / empty: return a small structured ack so the LLM sees success.
		return nil, map[string]any{"ok": true}, nil
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		logger.Error("mcp tool response not valid JSON", "tool", tool, "error", err)
		return nil, nil, fmt.Errorf("%s: decode response: %w", tool, err)
	}
	// If the API returned a top-level JSON array or primitive, wrap it so the
	// structured output is still a JSON object per MCP expectations.
	if _, ok := out.(map[string]any); !ok {
		out = map[string]any{"result": out}
	}
	return nil, out, nil
}

func ptr[T any](v T) *T { return &v }

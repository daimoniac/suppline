package mcp

import (
	"context"
	"log/slog"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Version is the advertised version of the suppline-mcp server. It is
// exported so that cmd/suppline-mcp can override it at link time via
// -ldflags "-X github.com/daimoniac/suppline/internal/mcp.Version=...".
var Version = "dev"

// serverInstructions is shown to the LLM on session initialize, giving it
// the domain vocabulary it needs to pick the right tool for a user question.
const serverInstructions = `You are connected to suppline, a self-hosted container supply-chain gateway.

suppline mirrors images from public registries into a local registry, scans them
with Trivy, evaluates CEL-based policies, applies VEX exemptions, and publishes
Sigstore attestations. Clusters report their runtime image inventory back to
suppline so it knows which images are actually deployed.

Key terms:
- Policy failure: an image whose most recent scan did not satisfy the
  configured CEL expression (typically because of critical or high CVEs that
  are not exempted via VEX).
- Runtime / in-use: an image reported by a connected Kubernetes cluster in its
  latest inventory sync, or seen within the configured runtime-in-use window.
- VEX statement: a CycloneDX Vulnerability Exploitability Exchange record that
  exempts a specific CVE from policy with an analysis state, justification,
  optional detail, and optional expiry.
- Expired VEX: a VEX statement whose expires_at has passed; expired statements
  no longer exempt their CVE.
- Inactive VEX: a VEX statement defined in suppline.yml but never applied to
  any scanned digest.

Use the available tools to answer questions about scans, images, repositories,
vulnerabilities, VEX, and runtime deployments. Prefer filtering at the tool
level (policy_status, in_use_mode, expired, expiring_soon, repository, etc.)
rather than fetching everything and filtering after the fact.

For questions about tightening semver ranges in suppline.yml, removing or
trimming old mirrored tag ranges, or making sync entries match what clusters
run in production, use the get_semver_updates tool. It calls GET
/api/v1/tasks/semver-updates and returns ready-made suggested_ranges and an
ai_agent_prompt; do not guess version constraints without it when that endpoint
is available.`

// overviewResource is served at suppline://overview so the LLM can retrieve
// the same context as a resource when instructions are not surfaced.
const overviewResource = serverInstructions

// Config configures the MCP server.
type Config struct {
	// Client is used to talk to the suppline REST API. Required.
	Client *Client
	// AllowWrites enables write tools (trigger_rescan, reevaluate_policy).
	AllowWrites bool
	// Logger receives server-side logs. Optional; defaults to slog.Default().
	Logger *slog.Logger
}

// NewServer builds a ready-to-connect MCP server for the given configuration.
// The caller is responsible for running it over a transport (e.g. stdio or
// streamable HTTP).
func NewServer(cfg Config) (*mcpsdk.Server, error) {
	if cfg.Client == nil {
		return nil, errMissingClient
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	srv := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    "suppline-mcp",
		Title:   "suppline supply-chain",
		Version: Version,
	}, &mcpsdk.ServerOptions{
		Instructions: serverInstructions,
		Logger:       logger,
	})

	srv.AddResource(&mcpsdk.Resource{
		URI:         "suppline://overview",
		Name:        "suppline overview",
		Title:       "suppline overview and terminology",
		Description: "Domain model and vocabulary for suppline supply-chain data.",
		MIMEType:    "text/markdown",
	}, func(_ context.Context, req *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
		return &mcpsdk.ReadResourceResult{
			Contents: []*mcpsdk.ResourceContents{
				{
					URI:      req.Params.URI,
					MIMEType: "text/markdown",
					Text:     overviewResource,
				},
			},
		}, nil
	})

	registerTools(srv, cfg.Client, cfg.AllowWrites, logger)

	return srv, nil
}

// errMissingClient is returned by NewServer when Config.Client is nil.
var errMissingClient = &configError{msg: "mcp: Config.Client is required"}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

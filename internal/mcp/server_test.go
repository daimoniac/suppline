package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	supplinemcp "github.com/daimoniac/suppline/internal/mcp"
)

// TestMCPServer_HeadlineQueries exercises the two questions the MCP server
// was designed to answer end-to-end: policy failures for images currently
// deployed to runtime, and expired VEX statements.
func TestMCPServer_HeadlineQueries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		gotScansQuery string
		gotVEXQuery   string
		gotAuth       string
	)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/v1/scans":
			gotScansQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Total-Count", "1")
			_, _ = w.Write([]byte(`[{"Digest":"sha256:deadbeef","Repository":"myregistry.com/nginx","Tag":"1.27","PolicyPassed":false,"PolicyStatus":"failed","RuntimeUsed":true}]`))
		case "/api/v1/vex":
			gotVEXQuery = r.URL.RawQuery
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"CVEID":"CVE-2024-00001","State":"not_affected","ExpiresAt":1700000000,"Repositories":[{"Repository":"myregistry.com/nginx","AppliedAt":0}]}]`))
		default:
			http.Error(w, "not mocked: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer backend.Close()

	client, err := supplinemcp.NewClient(supplinemcp.ClientConfig{
		BaseURL: backend.URL,
		APIKey:  "secret-token",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	srv, err := supplinemcp.NewServer(supplinemcp.Config{Client: client})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	serverTransport, clientTransport := mcpsdk.NewInMemoryTransports()
	serverSession, err := srv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer serverSession.Close()

	mcpClient := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	session, err := mcpClient.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer session.Close()

	// --- Question 1: policy failures for images currently deployed to runtime.
	res, err := session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "list_scans",
		Arguments: map[string]any{
			"policy_status": "failed",
			"in_use_mode":   "in_use",
		},
	})
	if err != nil {
		t.Fatalf("list_scans call: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_scans returned tool error: %+v", res)
	}
	if got, want := gotScansQuery, "in_use_mode=in_use&policy_status=failed"; got != want {
		t.Errorf("unexpected /api/v1/scans query: got %q want %q", got, want)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("missing or wrong auth header: %q", gotAuth)
	}
	if sc := res.StructuredContent; sc == nil {
		t.Errorf("expected structured content from list_scans, got nil")
	} else {
		// Marshal round-trip so we can assert on shape without depending on
		// the concrete decoded type.
		data, err := json.Marshal(sc)
		if err != nil {
			t.Fatalf("marshal list_scans structured content: %v", err)
		}
		var decoded struct {
			Result []struct {
				Digest       string `json:"Digest"`
				PolicyStatus string `json:"PolicyStatus"`
				RuntimeUsed  bool   `json:"RuntimeUsed"`
			} `json:"result"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal list_scans structured content: %v (raw=%s)", err, string(data))
		}
		if len(decoded.Result) != 1 {
			t.Fatalf("expected 1 scan, got %d (raw=%s)", len(decoded.Result), string(data))
		}
		if decoded.Result[0].PolicyStatus != "failed" || !decoded.Result[0].RuntimeUsed {
			t.Errorf("unexpected scan payload: %+v", decoded.Result[0])
		}
	}

	// --- Question 2: expired VEX statements.
	res, err = session.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      "list_vex_statements",
		Arguments: map[string]any{"expired": true},
	})
	if err != nil {
		t.Fatalf("list_vex_statements call: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_vex_statements returned tool error: %+v", res)
	}
	if got, want := gotVEXQuery, "expired=true"; got != want {
		t.Errorf("unexpected /api/v1/vex query: got %q want %q", got, want)
	}
	if sc := res.StructuredContent; sc == nil {
		t.Errorf("expected structured content from list_vex_statements, got nil")
	} else {
		data, err := json.Marshal(sc)
		if err != nil {
			t.Fatalf("marshal list_vex structured content: %v", err)
		}
		var decoded struct {
			Result []struct {
				CVEID     string `json:"CVEID"`
				ExpiresAt int64  `json:"ExpiresAt"`
			} `json:"result"`
		}
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal list_vex structured content: %v (raw=%s)", err, string(data))
		}
		if len(decoded.Result) != 1 || decoded.Result[0].CVEID != "CVE-2024-00001" {
			t.Errorf("unexpected VEX payload: %+v", decoded.Result)
		}
	}
}

// TestMCPServer_ToolListing verifies that read-only tools are always
// registered, and write tools only when AllowWrites is set.
func TestMCPServer_ToolListing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer backend.Close()

	client, err := supplinemcp.NewClient(supplinemcp.ClientConfig{BaseURL: backend.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	listTools := func(allowWrites bool) map[string]bool {
		srv, err := supplinemcp.NewServer(supplinemcp.Config{Client: client, AllowWrites: allowWrites})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		st, ct := mcpsdk.NewInMemoryTransports()
		ss, err := srv.Connect(ctx, st, nil)
		if err != nil {
			t.Fatalf("server connect: %v", err)
		}
		defer ss.Close()
		mcpClient := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "c", Version: "v0"}, nil)
		session, err := mcpClient.Connect(ctx, ct, nil)
		if err != nil {
			t.Fatalf("client connect: %v", err)
		}
		defer session.Close()

		names := make(map[string]bool)
		for tool, err := range session.Tools(ctx, nil) {
			if err != nil {
				t.Fatalf("list tools: %v", err)
			}
			names[tool.Name] = true
		}
		return names
	}

	readOnly := listTools(false)
	writable := listTools(true)

	mustExist := []string{
		"list_scans", "get_scan", "list_failed_images",
		"list_vex_statements", "list_inactive_vex",
		"query_vulnerabilities", "get_vulnerability", "vulnerability_stats",
		"list_repositories", "get_repository",
		"list_kubernetes_clusters", "get_cluster_images",
		"get_semver_updates",
	}
	for _, n := range mustExist {
		if !readOnly[n] {
			t.Errorf("read-only server missing tool %q", n)
		}
	}

	for _, n := range []string{"trigger_rescan", "reevaluate_policy"} {
		if readOnly[n] {
			t.Errorf("write tool %q registered without --allow-writes", n)
		}
		if !writable[n] {
			t.Errorf("write tool %q missing with --allow-writes", n)
		}
	}
}

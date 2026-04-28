// Command suppline-mcp is a Model Context Protocol server for suppline.
//
// It exposes suppline's REST API (scans, vulnerabilities, VEX, repositories,
// runtime inventory) as MCP tools so LLMs can answer supply-chain questions
// such as "policy failures for images currently deployed to runtime" or
// "are there any expired VEX statements?".
//
// The server can run over stdio (for local IDE integrations such as Cursor
// and Claude Desktop) or as a Streamable HTTP endpoint (for team-shared
// deployments). It never touches the suppline database directly; instead it
// speaks HTTP to a running suppline API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	supplinemcp "github.com/daimoniac/suppline/internal/mcp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "suppline-mcp: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	_ = godotenv.Load()

	var (
		transport   string
		addr        string
		mountPath   string
		allowWrites bool
		logLevel    string
		timeout     time.Duration
	)

	defaultURL := envOr("SUPPLINE_URL", "http://localhost:8080")
	defaultAPIKey := os.Getenv("SUPPLINE_API_KEY")

	baseURL := defaultURL
	apiKey := defaultAPIKey

	flag.StringVar(&transport, "transport", "stdio", "MCP transport: 'stdio' or 'http'")
	flag.StringVar(&addr, "addr", ":8082", "Listen address for --transport=http")
	flag.StringVar(&mountPath, "mount", "/mcp", "URL path to mount the streamable HTTP handler on")
	flag.StringVar(&baseURL, "suppline-url", defaultURL, "suppline REST API base URL (env SUPPLINE_URL)")
	flag.StringVar(&apiKey, "suppline-api-key", defaultAPIKey, "Bearer token for the suppline REST API (env SUPPLINE_API_KEY)")
	flag.BoolVar(&allowWrites, "allow-writes", false, "Enable write tools (trigger_rescan, reevaluate_policy)")
	flag.StringVar(&logLevel, "log-level", envOr("LOG_LEVEL", "info"), "Log level: debug, info, warn, error")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "Per-request timeout for calls to the suppline API")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: suppline-mcp [flags]\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Environment:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  SUPPLINE_URL       suppline REST API base URL (default http://localhost:8080)\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  SUPPLINE_API_KEY   optional bearer token for the suppline REST API\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  LOG_LEVEL          log level (default info)\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	logger := buildLogger(logLevel, transport)

	client, err := supplinemcp.NewClient(supplinemcp.ClientConfig{
		BaseURL: baseURL,
		APIKey:  apiKey,
		Timeout: timeout,
	})
	if err != nil {
		return err
	}

	srv, err := supplinemcp.NewServer(supplinemcp.Config{
		Client:      client,
		AllowWrites: allowWrites,
		Logger:      logger,
	})
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	switch strings.ToLower(transport) {
	case "stdio", "":
		logger.Info("suppline-mcp starting",
			"transport", "stdio",
			"suppline_url", baseURL,
			"allow_writes", allowWrites,
		)
		if err := srv.Run(ctx, &mcpsdk.StdioTransport{}); err != nil {
			return fmt.Errorf("stdio server: %w", err)
		}
		return nil
	case "http", "streamable-http":
		return runHTTP(ctx, logger, srv, addr, mountPath, baseURL, allowWrites)
	default:
		return fmt.Errorf("unsupported transport %q (expected 'stdio' or 'http')", transport)
	}
}

func runHTTP(ctx context.Context, logger *slog.Logger, srv *mcpsdk.Server, addr, mountPath, baseURL string, allowWrites bool) error {
	if mountPath == "" {
		mountPath = "/mcp"
	}
	if !strings.HasPrefix(mountPath, "/") {
		mountPath = "/" + mountPath
	}

	handler := mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server {
		return srv
	}, nil)

	mux := http.NewServeMux()
	mux.Handle(mountPath, handler)
	mux.Handle(mountPath+"/", handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("suppline-mcp starting",
			"transport", "http",
			"addr", addr,
			"mount", mountPath,
			"suppline_url", baseURL,
			"allow_writes", allowWrites,
		)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http server: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		logger.Info("suppline-mcp shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

// buildLogger returns a logger that writes to stderr. Anything written to
// stdout would corrupt the MCP JSON-RPC stream in stdio mode, so we always
// route logs through stderr regardless of transport. The format mirrors the
// suppline service logger (JSON, UTC RFC3339Nano timestamps).
func buildLogger(level, _ string) *slog.Logger {
	var slogLevel slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn", "warning":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slogLevel,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{
					Key:   a.Key,
					Value: slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano)),
				}
			}
			return a
		},
	})
	return slog.New(handler)
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

package cosign

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"
)

// Client wraps cosign CLI operations
type Client struct {
	keyPath     string
	keyPassword string
	logger      *slog.Logger
}

// NewClient creates a new cosign CLI client
func NewClient(keyPath, keyPassword string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	
	return &Client{
		keyPath:     keyPath,
		keyPassword: keyPassword,
		logger:      logger,
	}
}

// AttestOptions contains options for attestation operations
type AttestOptions struct {
	ImageRef      string
	PredicatePath string
	PredicateType string
	Replace       bool
	TlogUpload    bool
}

// Attest creates an attestation using cosign CLI
func (c *Client) Attest(ctx context.Context, opts AttestOptions) error {
	startTime := time.Now()
	c.logger.Debug("invoking cosign attest",
		"image_ref", opts.ImageRef,
		"predicate_type", opts.PredicateType)

	args := []string{
		"attest",
		"--key", c.keyPath,
		"--type", opts.PredicateType,
		"--predicate", opts.PredicatePath,
		"--yes",
	}

	if opts.Replace {
		args = append(args, "--replace=true")
	}

	if !opts.TlogUpload {
		args = append(args, "--tlog-upload=false")
	}

	args = append(args, opts.ImageRef)

	cmd := exec.CommandContext(ctx, "cosign", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", c.keyPassword))

	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	if err != nil {
		c.logger.Error("cosign attest failed",
			"image_ref", opts.ImageRef,
			"predicate_type", opts.PredicateType,
			"duration", duration,
			"error", err,
			"output", string(output))
		return fmt.Errorf("cosign attest failed: %w (output: %s)", err, string(output))
	}

	c.logger.Debug("cosign attest completed",
		"image_ref", opts.ImageRef,
		"predicate_type", opts.PredicateType,
		"duration", duration)

	return nil
}

// SignOptions contains options for signing operations
type SignOptions struct {
	ImageRef          string
	TlogUpload        bool
	AllowInsecure     bool
}

// Sign signs an image using cosign CLI
func (c *Client) Sign(ctx context.Context, opts SignOptions) error {
	startTime := time.Now()
	c.logger.Debug("invoking cosign sign", "image_ref", opts.ImageRef)

	args := []string{
		"sign",
		"--key", c.keyPath,
		"--yes",
	}

	if !opts.TlogUpload {
		args = append(args, "--tlog-upload=false")
	}

	if opts.AllowInsecure {
		args = append(args, "--allow-insecure-registry")
	}

	args = append(args, opts.ImageRef)

	cmd := exec.CommandContext(ctx, "cosign", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("COSIGN_PASSWORD=%s", c.keyPassword))

	output, err := cmd.CombinedOutput()
	duration := time.Since(startTime)

	if err != nil {
		c.logger.Error("cosign sign failed",
			"image_ref", opts.ImageRef,
			"duration", duration,
			"error", err,
			"output", string(output))
		return fmt.Errorf("cosign sign failed: %w (output: %s)", err, string(output))
	}

	c.logger.Debug("cosign sign completed",
		"image_ref", opts.ImageRef,
		"duration", duration)

	return nil
}

// LoginOptions contains options for registry login
type LoginOptions struct {
	Registry string
	Username string
	Password string
}

// Login authenticates cosign with a registry
func (c *Client) Login(ctx context.Context, opts LoginOptions) error {
	c.logger.Info("authenticating cosign with registry", "registry", opts.Registry)

	cmd := exec.CommandContext(ctx, "cosign", "login", opts.Registry,
		"--username", opts.Username,
		"--password", opts.Password)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		c.logger.Error("cosign login failed",
			"registry", opts.Registry,
			"error", err,
			"stderr", stderr.String())
		return fmt.Errorf("cosign login to %s failed: %w", opts.Registry, err)
	}

	c.logger.Info("cosign authenticated with registry", "registry", opts.Registry)
	return nil
}

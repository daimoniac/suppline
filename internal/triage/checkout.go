package triage

import (
	"context"
	"fmt"
)

// checkouts is the files a triage can read: gitops, a public commit, and the scanned image.
// Grep, read, and list go through it so the agent loop does not branch on checkout kind.
type checkouts struct {
	roots  *Roots
	ledger *publicSource
	job    Job
}

func (c checkouts) List(ctx context.Context, repo, rel string) (string, error) {
	if err := c.prepare(ctx, repo); err != nil {
		return "", err
	}
	return c.roots.ListDir(repo, rel)
}

func (c checkouts) Read(ctx context.Context, repo, rel string, start, end int) (string, error) {
	if err := c.prepare(ctx, repo); err != nil {
		return "", err
	}
	out, err := c.roots.ReadFile(repo, rel, start, end)
	if err == nil && c.ledger != nil && c.roots.public(repo) {
		c.ledger.remember(repo, rel, out)
	}
	return out, err
}

func (c checkouts) Grep(ctx context.Context, repo, pattern, rel string) (string, error) {
	if c.roots == nil {
		c.roots = &Roots{}
	}
	if repo == imageCheckoutName {
		return imageGrep(ctx, c.roots, c.ledger, c.job, pattern, rel)
	}
	if c.ledger != nil && c.roots.public(repo) {
		return publicGrep(c.roots, c.ledger, repo, pattern, rel)
	}
	return c.roots.Grep(repo, pattern, rel)
}

func (c checkouts) prepare(ctx context.Context, repo string) error {
	if repo != imageCheckoutName {
		return nil
	}
	if c.roots == nil {
		return fmt.Errorf("image checkout is unavailable")
	}
	return c.roots.mountImage(ctx)
}

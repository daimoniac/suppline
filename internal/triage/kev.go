package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	kevUserAgent = "suppline-triage/1.0 (+https://github.com/daimoniac/suppline)"
	// kevFallbackURL is CISA's own GitHub copy. cisa.gov is behind Akamai, which
	// rejects many cloud egress addresses with 403.
	kevFallbackURL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
)

// KEVCache caches the CISA Known Exploited Vulnerabilities feed.
type KEVCache struct {
	URL         string
	FallbackURL string
	TTL         time.Duration
	Client      *http.Client
	Now         func() time.Time

	mu    sync.Mutex
	until time.Time
	ids   map[string]struct{}
}

func (c *KEVCache) Contains(ctx context.Context, cve string) (bool, error) {
	if c == nil || c.URL == "" {
		return false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	if c.ids != nil && now.Before(c.until) {
		_, ok := c.ids[cve]
		return ok, nil
	}
	ids, err := c.fetch(ctx)
	if err != nil {
		c.ids = nil
		c.until = time.Time{}
		return false, err
	}
	c.ids = ids
	ttl := c.TTL
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	c.until = now.Add(ttl)
	_, ok := c.ids[cve]
	return ok, nil
}

func (c *KEVCache) fetch(ctx context.Context) (map[string]struct{}, error) {
	fallbackURL := c.FallbackURL
	if fallbackURL == "" {
		fallbackURL = kevFallbackURL
	}
	ids, err := c.fetchURL(ctx, c.URL)
	if err == nil || c.URL == fallbackURL {
		return ids, err
	}
	fallback, fallbackErr := c.fetchURL(ctx, fallbackURL)
	if fallbackErr != nil {
		return nil, fmt.Errorf("%v; fallback: %w", err, fallbackErr)
	}
	return fallback, nil
}

func (c *KEVCache) fetchURL(ctx context.Context, feedURL string) (map[string]struct{}, error) {
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", kevUserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch CISA KEV feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CISA KEV feed status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	var feed struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("decode CISA KEV feed: %w", err)
	}
	ids := make(map[string]struct{}, len(feed.Vulnerabilities))
	for _, item := range feed.Vulnerabilities {
		if item.CVEID != "" {
			ids[item.CVEID] = struct{}{}
		}
	}
	return ids, nil
}

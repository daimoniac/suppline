package config

import (
	"fmt"
	"strings"
	"time"
)

// Defaults for the kev block.
const (
	DefaultKEVFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// DefaultKEVFallbackURL is CISA's own GitHub copy. cisa.gov is behind
	// Akamai, which rejects many cloud egress addresses with 403.
	DefaultKEVFallbackURL  = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
	DefaultKEVSyncInterval = 6 * time.Hour
	DefaultKEVStaleAfter   = 48 * time.Hour
)

// KEVConfig is the kev block: the CISA Known Exploited Vulnerabilities
// catalog. It is read at startup only. A missing block means enabled with
// every default, except that triage.kev_feed_url and triage.kev_cache_ttl
// still apply when the block is absent.
type KEVConfig struct {
	Enabled      *bool  `yaml:"enabled,omitempty"`
	FeedURL      string `yaml:"feed_url,omitempty"`
	FallbackURL  string `yaml:"fallback_url,omitempty"`
	SyncInterval string `yaml:"sync_interval,omitempty"`
	StaleAfter   string `yaml:"stale_after,omitempty"`
}

// KEVSettings is the resolved kev configuration.
type KEVSettings struct {
	Enabled      bool
	FeedURL      string
	FallbackURL  string
	SyncInterval time.Duration
	StaleAfter   time.Duration
	// FromTriage is true when the feed URL or interval came from the older
	// triage.kev_feed_url / triage.kev_cache_ttl keys.
	FromTriage bool
}

// ResolveKEV returns the kev settings. Without a kev block, the older triage
// keys still set the feed URL and the sync interval.
func ResolveKEV(k *KEVConfig, triage *TriageConfig) KEVSettings {
	settings := KEVSettings{
		Enabled:      true,
		FeedURL:      DefaultKEVFeedURL,
		FallbackURL:  DefaultKEVFallbackURL,
		SyncInterval: DefaultKEVSyncInterval,
		StaleAfter:   DefaultKEVStaleAfter,
	}
	if k == nil {
		if triage != nil {
			if url := strings.TrimSpace(triage.KEVFeedURL); url != "" {
				settings.FeedURL = url
				settings.FromTriage = true
			}
			if ttl := durationOr(triage.KEVCacheTTL, 0); ttl > 0 {
				settings.SyncInterval = ttl
				settings.FromTriage = true
				if settings.StaleAfter < ttl {
					settings.StaleAfter = ttl
				}
			}
		}
		return settings
	}
	if k.Enabled != nil {
		settings.Enabled = *k.Enabled
	}
	if url := strings.TrimSpace(k.FeedURL); url != "" {
		settings.FeedURL = url
	}
	if url := strings.TrimSpace(k.FallbackURL); url != "" {
		settings.FallbackURL = url
	}
	settings.SyncInterval = durationOr(k.SyncInterval, DefaultKEVSyncInterval)
	settings.StaleAfter = durationOr(k.StaleAfter, DefaultKEVStaleAfter)
	return settings
}

// Validate reports configuration errors.
func (k *KEVConfig) Validate() error {
	if k == nil || (k.Enabled != nil && !*k.Enabled) {
		return nil
	}
	for _, field := range []struct{ name, value string }{
		{"sync_interval", k.SyncInterval},
		{"stale_after", k.StaleAfter},
	} {
		if strings.TrimSpace(field.value) == "" {
			continue
		}
		parsed, err := ParseFlexibleDuration(field.value)
		if err != nil {
			return fmt.Errorf("kev.%s: %w", field.name, err)
		}
		if parsed <= 0 {
			return fmt.Errorf("kev.%s must be positive", field.name)
		}
	}
	settings := ResolveKEV(k, nil)
	if settings.StaleAfter < settings.SyncInterval {
		return fmt.Errorf("kev.stale_after must be at least sync_interval")
	}
	return nil
}

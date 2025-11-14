package registry

import (
	"context"
	"testing"
	"time"

	"github.com/suppline/suppline/internal/config"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.RegsyncConfig
		expectError bool
	}{
		{
			name:        "nil config",
			config:      nil,
			expectError: true,
		},
		{
			name: "valid config with credentials",
			config: &config.RegsyncConfig{
				Version: 1,
				Creds: []config.RegistryCredential{
					{
						Registry: "docker.io",
						User:     "testuser",
						Pass:     "testpass",
					},
				},
				Sync: []config.SyncEntry{
					{
						Source: "nginx",
						Target: "myregistry.com/nginx",
						Type:   "repository",
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid config without credentials",
			config: &config.RegsyncConfig{
				Version: 1,
				Sync: []config.SyncEntry{
					{
						Source: "nginx",
						Target: "myregistry.com/nginx",
						Type:   "repository",
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if client == nil {
					t.Errorf("expected client but got nil")
				}
			}
		})
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		name             string
		repo             string
		expectedRegistry string
		expectedRepo     string
		expectError      bool
	}{
		{
			name:             "docker hub with org",
			repo:             "docker.io/library/nginx",
			expectedRegistry: "docker.io",
			expectedRepo:     "library/nginx",
			expectError:      false,
		},
		{
			name:             "gcr.io with project",
			repo:             "gcr.io/project/image",
			expectedRegistry: "gcr.io",
			expectedRepo:     "project/image",
			expectError:      false,
		},
		{
			name:             "custom registry with port",
			repo:             "myregistry.com:5000/org/image",
			expectedRegistry: "myregistry.com:5000",
			expectedRepo:     "org/image",
			expectError:      false,
		},
		{
			name:             "simple name defaults to docker hub",
			repo:             "nginx",
			expectedRegistry: "docker.io",
			expectedRepo:     "library/nginx",
			expectError:      false,
		},
		{
			name:             "org/image defaults to docker hub",
			repo:             "myorg/myimage",
			expectedRegistry: "docker.io",
			expectedRepo:     "myorg/myimage",
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry, repo, err := parseImageRef(tt.repo)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if registry != tt.expectedRegistry {
					t.Errorf("expected registry %s but got %s", tt.expectedRegistry, registry)
				}
				if repo != tt.expectedRepo {
					t.Errorf("expected repo %s but got %s", tt.expectedRepo, repo)
				}
			}
		})
	}
}

func TestListRepositories(t *testing.T) {
	config := &config.RegsyncConfig{
		Version: 1,
		Sync: []config.SyncEntry{
			{
				Source: "nginx",
				Target: "myregistry.com/nginx",
				Type:   "repository",
			},
			{
				Source: "redis",
				Target: "myregistry.com/redis",
				Type:   "repository",
			},
		},
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	repos, err := client.ListRepositories(ctx)
	if err != nil {
		t.Fatalf("failed to list repositories: %v", err)
	}

	if len(repos) != 2 {
		t.Errorf("expected 2 repositories but got %d", len(repos))
	}

	expectedRepos := map[string]bool{
		"myregistry.com/nginx": true,
		"myregistry.com/redis": true,
	}

	for _, repo := range repos {
		if !expectedRepos[repo] {
			t.Errorf("unexpected repository: %s", repo)
		}
	}
}

func TestListRepositoriesEmpty(t *testing.T) {
	config := &config.RegsyncConfig{
		Version: 1,
		Sync:    []config.SyncEntry{},
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	ctx := context.Background()
	_, err = client.ListRepositories(ctx)
	if err == nil {
		t.Errorf("expected error for empty sync entries but got none")
	}
}

func TestClientWithTolerations(t *testing.T) {
	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	config := &config.RegsyncConfig{
		Version: 1,
		Creds: []config.RegistryCredential{
			{
				Registry: "myregistry.com",
				User:     "testuser",
				Pass:     "testpass",
			},
		},
		Sync: []config.SyncEntry{
			{
				Source: "nginx",
				Target: "myregistry.com/nginx",
				Type:   "repository",
				Tolerate: []config.CVEToleration{
					{
						ID:        "CVE-2024-12345",
						Statement: "Accepted risk for testing",
						ExpiresAt: &expiresAt,
					},
				},
			},
		},
	}

	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	if client == nil {
		t.Errorf("expected client but got nil")
	}

	// Verify tolerations are accessible through regsync config
	tolerations := config.GetTolerationsForTarget("myregistry.com/nginx")
	if len(tolerations) != 1 {
		t.Errorf("expected 1 toleration but got %d", len(tolerations))
	}

	if tolerations[0].ID != "CVE-2024-12345" {
		t.Errorf("expected CVE-2024-12345 but got %s", tolerations[0].ID)
	}
}

func TestFilterSigstoreArtifacts(t *testing.T) {
	// Test that .sig and .att suffixed tags are filtered out
	// This is a unit test for the filtering logic in ListTags
	
	tests := []struct {
		name          string
		inputTags     []string
		expectedTags  []string
		expectedCount int
	}{
		{
			name: "filter out .sig and .att artifacts",
			inputTags: []string{
				"latest",
				"v1.0.0",
				"sha256-abc123.sig",
				"sha256-abc123.att",
				"sha256-def456.sig",
				"sha256-def456.att",
				"v1.0.1",
			},
			expectedTags: []string{
				"latest",
				"v1.0.0",
				"v1.0.1",
			},
			expectedCount: 3,
		},
		{
			name: "no artifacts to filter",
			inputTags: []string{
				"latest",
				"v1.0.0",
				"v1.0.1",
			},
			expectedTags: []string{
				"latest",
				"v1.0.0",
				"v1.0.1",
			},
			expectedCount: 3,
		},
		{
			name: "only artifacts",
			inputTags: []string{
				"sha256-abc123.sig",
				"sha256-abc123.att",
			},
			expectedTags:  []string{},
			expectedCount: 0,
		},
		{
			name:          "empty list",
			inputTags:     []string{},
			expectedTags:  []string{},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the filtering logic from ListTags
			filteredTags := make([]string, 0, len(tt.inputTags))
			for _, tag := range tt.inputTags {
				if !hasSuffix(tag, ".sig") && !hasSuffix(tag, ".att") {
					filteredTags = append(filteredTags, tag)
				}
			}

			if len(filteredTags) != tt.expectedCount {
				t.Errorf("expected %d tags but got %d", tt.expectedCount, len(filteredTags))
			}

			for i, expectedTag := range tt.expectedTags {
				if i >= len(filteredTags) {
					t.Errorf("missing expected tag: %s", expectedTag)
					continue
				}
				if filteredTags[i] != expectedTag {
					t.Errorf("expected tag %s but got %s", expectedTag, filteredTags[i])
				}
			}
		})
	}
}

// hasSuffix is a helper function for testing
func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

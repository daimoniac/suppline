package triage

import (
	"context"
	"strings"
	"time"
)

// GitopsRepo is one configured checkout and the last commit suppline pushed to it.
type GitopsRepo struct {
	Name            string
	URL             string
	Branch          string
	Roles           []string
	Cloned          bool
	HeadSHA         string
	HeadAt          time.Time
	LastSupplineSHA string
	LastSupplineAt  time.Time
}

// GitopsStatus reads local checkouts. It does not fetch.
func (s *Service) GitopsStatus(ctx context.Context) ([]GitopsRepo, error) {
	if s == nil {
		return nil, nil
	}
	order := make([]string, 0)
	byURL := map[string]*GitopsRepo{}
	add := func(url, name, branch, role string) {
		url = strings.TrimSpace(url)
		if url == "" {
			return
		}
		repo, ok := byURL[url]
		if !ok {
			repo = &GitopsRepo{Name: name, URL: url, Branch: branch}
			byURL[url] = repo
			order = append(order, url)
		}
		if repo.Name == "" {
			repo.Name = name
		}
		if repo.Branch == "" {
			repo.Branch = branch
		}
		for _, existing := range repo.Roles {
			if existing == role {
				return
			}
		}
		repo.Roles = append(repo.Roles, role)
	}
	for _, repo := range s.settings.Context {
		add(repo.URL, repo.Name, repo.Branch, "context")
	}
	if s.settings.ConfigRepo != nil {
		add(s.settings.ConfigRepo.URL, "", s.settings.ConfigRepo.Branch, "config")
	}

	var lastSHA string
	var lastAt time.Time
	if s.runs != nil {
		run, err := s.runs.LatestTriageCommit(ctx)
		if err != nil {
			return nil, err
		}
		if run != nil {
			lastSHA = run.CommitSHA
			lastAt = run.CreatedAt
		}
	}

	repos := make([]GitopsRepo, 0, len(order))
	for _, url := range order {
		repo := *byURL[url]
		if repo.Name == "" {
			repo.Name = nameFromRepoURL(url)
		}
		if s.git != nil {
			snap, err := s.git.Snapshot(url)
			if err != nil {
				return nil, err
			}
			repo.Cloned = snap.Cloned
			repo.HeadSHA = snap.SHA
			repo.HeadAt = snap.When
			if repo.Branch == "" {
				repo.Branch = snap.Branch
			}
		}
		if lastSHA != "" && hasRole(repo.Roles, "config") {
			repo.LastSupplineSHA = lastSHA
			repo.LastSupplineAt = lastAt
			if s.git != nil {
				if when, ok := s.git.CommitTime(url, lastSHA); ok {
					repo.LastSupplineAt = when
				}
			}
		}
		repos = append(repos, repo)
	}
	return repos, nil
}

func hasRole(roles []string, role string) bool {
	for _, existing := range roles {
		if existing == role {
			return true
		}
	}
	return false
}

func nameFromRepoURL(rawURL string) string {
	trimmed := strings.TrimSuffix(strings.TrimSpace(rawURL), ".git")
	trimmed = strings.TrimRight(trimmed, "/")
	if i := strings.LastIndex(trimmed, "/"); i >= 0 {
		trimmed = trimmed[i+1:]
	}
	if trimmed == "" {
		return "repo"
	}
	return trimmed
}

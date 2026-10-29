package mirror

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	dockerHubAPIBase = "https://hub.docker.com/v2"
	dockerHubTimeout = 60 * time.Second
)

// hubRepoAPI is the subset of Docker Hub operations cleanupRepos needs.
type hubRepoAPI interface {
	listRepositories(ctx context.Context, namespace string) ([]string, error)
	deleteRepository(ctx context.Context, namespace, name string) error
}

type dockerHubClient struct {
	httpClient *http.Client
	baseURL    string
	user       string
	pass       string
	token      string
	userAgent  string
}

type dockerHubLoginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type dockerHubLoginResp struct {
	Token string `json:"token"`
}

type dockerHubRepoListResp struct {
	Next    string               `json:"next"`
	Results []dockerHubRepoEntry `json:"results"`
}

type dockerHubRepoEntry struct {
	Name string `json:"name"`
}

func newDockerHubClient(user, pass, userAgent string) *dockerHubClient {
	return &dockerHubClient{
		httpClient: &http.Client{Timeout: dockerHubTimeout},
		baseURL:    dockerHubAPIBase,
		user:       user,
		pass:       pass,
		userAgent:  userAgent,
	}
}

func (c *dockerHubClient) login(ctx context.Context) error {
	body, err := json.Marshal(dockerHubLoginReq{Username: c.user, Password: c.pass})
	if err != nil {
		return fmt.Errorf("marshal hub login: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/users/login/", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create hub login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("hub login request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read hub login response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hub login failed: status %d: %s", resp.StatusCode, string(respBody))
	}
	var parsed dockerHubLoginResp
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return fmt.Errorf("parse hub login response: %w", err)
	}
	if parsed.Token == "" {
		return fmt.Errorf("hub login returned empty token")
	}
	c.token = parsed.Token
	return nil
}

func (c *dockerHubClient) ensureToken(ctx context.Context) error {
	if c.token != "" {
		return nil
	}
	return c.login(ctx)
}

func (c *dockerHubClient) doAuthed(ctx context.Context, method, rawURL string) (*http.Response, []byte, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, nil, err
	}
	doOnce := func() (*http.Response, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("create hub request: %w", err)
		}
		req.Header.Set("Authorization", "JWT "+c.token)
		req.Header.Set("Accept", "application/json")
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, nil, fmt.Errorf("hub request: %w", err)
		}
		respBody, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("read hub response: %w", err)
		}
		return resp, respBody, nil
	}
	resp, respBody, err := doOnce()
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		c.token = ""
		if err := c.login(ctx); err != nil {
			return nil, nil, err
		}
		return doOnce()
	}
	return resp, respBody, nil
}

func (c *dockerHubClient) listRepositories(ctx context.Context, namespace string) ([]string, error) {
	var names []string
	next := c.baseURL + "/repositories/" + url.PathEscape(namespace) + "/?page_size=100"
	for next != "" {
		resp, respBody, err := c.doAuthed(ctx, http.MethodGet, next)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("hub list failed: status %d: %s", resp.StatusCode, string(respBody))
		}
		var parsed dockerHubRepoListResp
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return nil, fmt.Errorf("parse hub list response: %w", err)
		}
		for _, r := range parsed.Results {
			if r.Name != "" {
				names = append(names, r.Name)
			}
		}
		next = parsed.Next
	}
	return names, nil
}

func (c *dockerHubClient) deleteRepository(ctx context.Context, namespace, name string) error {
	u := c.baseURL + "/repositories/" + url.PathEscape(namespace) + "/" + url.PathEscape(name) + "/"
	resp, respBody, err := c.doAuthed(ctx, http.MethodDelete, u)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("hub delete failed: status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

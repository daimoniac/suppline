package triage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const publicUserAgent = "suppline-triage/1.0 (+https://github.com/daimoniac/suppline)"

var (
	advisoryIDPattern = regexp.MustCompile(`^(?i)(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$`)
	githubNamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$`)
	githubRefPattern  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]{0,127}$`)
	githubPathPattern = regexp.MustCompile(`^[A-Za-z0-9_.@+-]{1,200}$`)
)

// publicSource fetches vulnerability advisories and public GitHub files.
// Requests stay on an allowlist of hosts and on public IP addresses.
type publicSource struct {
	client   *http.Client
	hosts    map[string]struct{}
	insecure bool
	osv      string
	github   string
}

func newPublicSource() *publicSource {
	hosts := map[string]struct{}{
		"api.osv.dev":               {},
		"api.github.com":            {},
		"raw.githubusercontent.com": {},
	}
	return &publicSource{
		client: &http.Client{
			Timeout:   20 * time.Second,
			Transport: publicTransport(),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				if _, ok := hosts[req.URL.Hostname()]; !ok || req.URL.Scheme != "https" {
					return fmt.Errorf("redirect host %s is not allowed", req.URL.Host)
				}
				return nil
			},
		},
		hosts:  hosts,
		osv:    "https://api.osv.dev",
		github: "https://api.github.com",
	}
}

func publicTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var last error
			for _, ip := range ips {
				if !isPublicIP(ip.IP) {
					last = fmt.Errorf("address %s is not public", ip.IP)
					continue
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
				if err == nil {
					return conn, nil
				}
				last = err
			}
			if last == nil {
				last = fmt.Errorf("no address for %s", host)
			}
			return nil, last
		},
	}
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	return true
}

func (p *publicSource) Advisory(ctx context.Context, id string) (string, error) {
	if p == nil {
		p = newPublicSource()
	}
	id = strings.TrimSpace(id)
	if !advisoryIDPattern.MatchString(id) {
		return "", fmt.Errorf("advisory id must be a CVE or GHSA")
	}
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		id = strings.ToUpper(id)
	}
	body, status, err := p.get(ctx, p.osv+"/v1/vulns/"+url.PathEscape(id))
	if err != nil {
		return "", err
	}
	if status == http.StatusOK {
		return formatOSV(body)
	}
	ghBody, ghStatus, ghErr := p.get(ctx, p.githubAdvisoryURL(id))
	if ghErr != nil {
		return "", fmt.Errorf("OSV status %d; GitHub advisory: %w", status, ghErr)
	}
	if ghStatus != http.StatusOK {
		return "", fmt.Errorf("advisory %s not found (OSV %d, GitHub %d)", id, status, ghStatus)
	}
	return formatGitHubAdvisory(ghBody)
}

func (p *publicSource) githubAdvisoryURL(id string) string {
	base := strings.TrimRight(p.github, "/")
	if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
		return base + "/advisories?cve_id=" + url.QueryEscape(strings.ToUpper(id))
	}
	return base + "/advisories/" + url.PathEscape(id)
}

func (p *publicSource) GitHubFile(ctx context.Context, owner, repo, ref, rel string, start, end int) (string, error) {
	if p == nil {
		p = newPublicSource()
	}
	owner, repo, ref, rel, err := cleanGitHubPath(owner, repo, ref, rel)
	if err != nil {
		return "", err
	}
	rawURL := strings.TrimRight(p.github, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/contents/" + pathEscapeSlash(rel)
	if ref != "" {
		rawURL += "?ref=" + url.QueryEscape(ref)
	}
	body, status, err := p.get(ctx, rawURL)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("GitHub contents status %d", status)
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		return formatGitHubDir(body)
	}
	var file struct {
		Type        string `json:"type"`
		Encoding    string `json:"encoding"`
		Content     string `json:"content"`
		Size        int    `json:"size"`
		DownloadURL string `json:"download_url"`
		Message     string `json:"message"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		return "", fmt.Errorf("decode GitHub contents: %w", err)
	}
	if file.Message != "" && file.Type == "" {
		return "", fmt.Errorf("GitHub: %s", file.Message)
	}
	if file.Type == "dir" {
		return formatGitHubDir(body)
	}
	if file.Type != "file" && file.Type != "" {
		return "", fmt.Errorf("GitHub path is a %s", file.Type)
	}
	if file.Size > 256*1024 {
		return "", fmt.Errorf("file exceeds 256KiB")
	}
	var text string
	if file.Encoding == "base64" && strings.TrimSpace(file.Content) != "" {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
		if err != nil {
			return "", fmt.Errorf("decode file: %w", err)
		}
		text = string(decoded)
	} else if file.DownloadURL != "" {
		raw, rawStatus, err := p.get(ctx, file.DownloadURL)
		if err != nil {
			return "", err
		}
		if rawStatus != http.StatusOK {
			return "", fmt.Errorf("GitHub raw status %d", rawStatus)
		}
		text = string(raw)
	} else {
		return "", fmt.Errorf("GitHub returned no file content")
	}
	redacted, err := Redact(rel, text)
	if err != nil {
		return "", err
	}
	return numberedLines(redacted, start, end), nil
}

func (p *publicSource) get(ctx context.Context, rawURL string) ([]byte, int, error) {
	if p == nil {
		p = newPublicSource()
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, 0, err
	}
	if parsed.Scheme != "https" && !(p.insecure && parsed.Scheme == "http") {
		return nil, 0, fmt.Errorf("only https URLs are allowed")
	}
	if _, ok := p.hosts[parsed.Hostname()]; !ok {
		return nil, 0, fmt.Errorf("host %s is not allowed", parsed.Hostname())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", publicUserAgent)
	req.Header.Set("Accept", "application/vnd.github+json, application/json")
	if token := githubToken(); token != "" && (parsed.Hostname() == "api.github.com" || parsed.Hostname() == "raw.githubusercontent.com") {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := p.client
	if client == nil {
		client = newPublicSource().client
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func githubToken() string {
	if value := strings.TrimSpace(os.Getenv("SUPPLINE_GITHUB_TOKEN")); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
}

func cleanGitHubPath(owner, repo, ref, rel string) (string, string, string, string, error) {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSuffix(strings.TrimSpace(repo), ".git")
	ref = strings.TrimSpace(ref)
	rel = strings.Trim(strings.TrimSpace(rel), "/")
	if !githubNamePattern.MatchString(owner) || !githubNamePattern.MatchString(repo) {
		return "", "", "", "", fmt.Errorf("owner and repo must be GitHub names")
	}
	if ref != "" && (!githubRefPattern.MatchString(ref) || strings.Contains(ref, "..")) {
		return "", "", "", "", fmt.Errorf("ref is not a branch, tag, or commit")
	}
	if rel != "" {
		for _, part := range strings.Split(rel, "/") {
			if part == "" || part == "." || part == ".." || !githubPathPattern.MatchString(part) {
				return "", "", "", "", fmt.Errorf("path is not allowed")
			}
		}
	}
	return owner, repo, ref, rel, nil
}

func pathEscapeSlash(rel string) string {
	if rel == "" {
		return ""
	}
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func numberedLines(text string, start, end int) string {
	lines := strings.Split(text, "\n")
	if start < 1 {
		start = 1
	}
	if end < start {
		end = start + 199
	}
	if end-start > 199 {
		end = start + 199
	}
	if start > len(lines) {
		return fmt.Sprintf("start line %d is past end of file (%d)", start, len(lines))
	}
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i := start; i <= end; i++ {
		fmt.Fprintf(&b, "%d|%s\n", i, lines[i-1])
	}
	return b.String()
}

func formatOSV(body []byte) (string, error) {
	var vuln struct {
		ID       string   `json:"id"`
		Summary  string   `json:"summary"`
		Details  string   `json:"details"`
		Aliases  []string `json:"aliases"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		References []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"references"`
		Affected []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Ranges []struct {
				Type   string              `json:"type"`
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(body, &vuln); err != nil {
		return "", fmt.Errorf("decode OSV advisory: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "id: %s\n", vuln.ID)
	if len(vuln.Aliases) > 0 {
		fmt.Fprintf(&b, "aliases: %s\n", strings.Join(vuln.Aliases, ", "))
	}
	if vuln.Summary != "" {
		fmt.Fprintf(&b, "summary: %s\n", oneLine(vuln.Summary, 400))
	}
	for _, severity := range vuln.Severity {
		fmt.Fprintf(&b, "severity: %s %s\n", severity.Type, oneLine(severity.Score, 200))
	}
	for _, affected := range vuln.Affected {
		if affected.Package.Name == "" {
			continue
		}
		fmt.Fprintf(&b, "package: %s %s\n", affected.Package.Ecosystem, affected.Package.Name)
		for _, rng := range affected.Ranges {
			var events []string
			for _, event := range rng.Events {
				for key, value := range event {
					events = append(events, key+" "+value)
				}
			}
			if len(events) > 0 {
				fmt.Fprintf(&b, "range: %s %s\n", rng.Type, strings.Join(events, ", "))
			}
		}
	}
	for _, ref := range vuln.References {
		if ref.URL != "" {
			fmt.Fprintf(&b, "reference: %s %s\n", ref.Type, ref.URL)
		}
	}
	if vuln.Details != "" {
		fmt.Fprintf(&b, "details:\n%s\n", oneLine(vuln.Details, 4000))
	}
	return b.String(), nil
}

func formatGitHubAdvisory(body []byte) (string, error) {
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "[") {
		var list []json.RawMessage
		if err := json.Unmarshal(body, &list); err != nil {
			return "", fmt.Errorf("decode GitHub advisory list: %w", err)
		}
		if len(list) == 0 {
			return "", fmt.Errorf("GitHub advisory list is empty")
		}
		body = list[0]
	}
	var adv struct {
		GHSAID      string   `json:"ghsa_id"`
		CVEID       string   `json:"cve_id"`
		Summary     string   `json:"summary"`
		Description string   `json:"description"`
		Severity    string   `json:"severity"`
		References  []string `json:"references"`
		Vulns       []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			VulnerableRange string `json:"vulnerable_version_range"`
			Patched         string `json:"patched_versions"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &adv); err != nil {
		return "", fmt.Errorf("decode GitHub advisory: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "id: %s\n", firstNonEmpty(adv.GHSAID, adv.CVEID))
	if adv.CVEID != "" && adv.GHSAID != "" {
		fmt.Fprintf(&b, "aliases: %s\n", adv.CVEID)
	}
	if adv.Summary != "" {
		fmt.Fprintf(&b, "summary: %s\n", oneLine(adv.Summary, 400))
	}
	if adv.Severity != "" {
		fmt.Fprintf(&b, "severity: %s\n", adv.Severity)
	}
	for _, vuln := range adv.Vulns {
		fmt.Fprintf(&b, "package: %s %s\n", vuln.Package.Ecosystem, vuln.Package.Name)
		if vuln.VulnerableRange != "" {
			fmt.Fprintf(&b, "range: %s\n", vuln.VulnerableRange)
		}
		if vuln.Patched != "" {
			fmt.Fprintf(&b, "patched: %s\n", vuln.Patched)
		}
	}
	for _, ref := range adv.References {
		fmt.Fprintf(&b, "reference: %s\n", ref)
	}
	if adv.Description != "" {
		fmt.Fprintf(&b, "details:\n%s\n", oneLine(adv.Description, 4000))
	}
	return b.String(), nil
}

func formatGitHubDir(body []byte) (string, error) {
	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return "", fmt.Errorf("decode GitHub directory: %w", err)
	}
	var b strings.Builder
	for i, entry := range entries {
		if i >= maxToolMatches {
			b.WriteString("... truncated\n")
			break
		}
		name := entry.Name
		if entry.Type == "dir" {
			name += "/"
		}
		b.WriteString(name + "\n")
	}
	return b.String(), nil
}

func oneLine(value string, max int) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\r\n", "\n"))
	if len(value) > max {
		value = value[:max] + "…"
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

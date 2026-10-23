package triage

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/detect"
)

var pemPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`)

var (
	detectorOnce sync.Once
	detector     *detect.Detector
	detectorErr  error
)

func secretDetector() (*detect.Detector, error) {
	detectorOnce.Do(func() {
		detector, detectorErr = detect.NewDetectorDefaultConfig()
	})
	return detector, detectorErr
}

// Redact removes secrets from text that may be sent to an LLM.
// Detection uses gitleaks, plus PEM blocks and Kubernetes Secret data values.
func Redact(path, content string) (string, error) {
	content = redactSecretManifest(content)
	content = pemPattern.ReplaceAllString(content, "[REDACTED]")

	found, err := secretDetector()
	if err != nil {
		return "", err
	}
	var secrets []string
	for _, finding := range found.Detect(detect.Fragment{Raw: content, FilePath: path}) {
		if finding.Secret != "" {
			secrets = append(secrets, finding.Secret)
		}
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	for _, secret := range secrets {
		content = strings.ReplaceAll(content, secret, "[REDACTED]")
	}
	return content, nil
}

func redactSecretManifest(content string) string {
	if !strings.Contains(content, "kind: Secret") && !strings.Contains(content, "kind: SealedSecret") {
		return content
	}
	lines := strings.Split(content, "\n")
	inData := false
	dataIndent := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if trimmed == "data:" || trimmed == "stringData:" || strings.HasPrefix(trimmed, "data:") || strings.HasPrefix(trimmed, "stringData:") {
			inData = true
			dataIndent = indent
			if strings.Contains(trimmed, ":") && !strings.HasSuffix(trimmed, ":") {
				colon := strings.Index(line, ":")
				lines[i] = line[:colon+1] + " [REDACTED]"
				inData = false
			}
			continue
		}
		if !inData {
			continue
		}
		if trimmed != "" && indent <= dataIndent {
			inData = false
			continue
		}
		if colon := strings.Index(line, ":"); colon > 0 {
			lines[i] = line[:colon+1] + " [REDACTED]"
		}
	}
	return strings.Join(lines, "\n")
}

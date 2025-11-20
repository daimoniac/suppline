package integration

import (
	"fmt"
	"strings"
	"text/template"
)

// GenerateKyvernoPolicy generates a Kyverno ClusterPolicy YAML for SCAI attestation verification
func GenerateKyvernoPolicy(publicKey string) (string, error) {
	if publicKey == "" {
		return "", fmt.Errorf("public key is required")
	}

	tmpl, err := template.New("kyverno").Parse(kyvernoPolicyTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var result strings.Builder
	err = tmpl.Execute(&result, map[string]string{
		"PublicKey": publicKey,
	})
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return result.String(), nil
}

const kyvernoPolicyTemplate = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: suppline-policy
spec:
  validationFailureAction: Audit
  background: false
  webhookTimeoutSeconds: 30
  failurePolicy: Fail
  rules:
  - name: verify-scai-attestation
    match:
      any:
      - resources:
          kinds:
          - Pod
    verifyImages:
    - imageReferences:
      - "*"
      verifyDigest: false
      mutateDigest: false
      attestations:
      - type: https://in-toto.io/attestation/scai/attribute-report/v0.3
        conditions:
        - all:
          # validUntil must be in the future
          - key: "{{ predicate.evidence.validUntil }}"
            operator: GreaterThan
            value: "{{ time_now() }}"
          # scanStatus must be acceptable
          - any:
            - key: "{{ predicate.evidence.scanStatus }}"
              operator: Equals
              value: "passed"
            - key: "{{ predicate.evidence.scanStatus }}"
              operator: Equals
              value: "passed-with-exceptions"
        attestors:
        - count: 1
          entries:
          - keys:
              publicKeys: |
{{.PublicKey}}
              rekor:
                ignoreTlog: true
                url: https://rekor.sigstore.dev
`

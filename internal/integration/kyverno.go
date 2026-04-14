package integration

import (
	"fmt"
	"strings"
)

// GenerateKyvernoPolicy generates a Kyverno ClusterPolicy YAML for SCAI attestation verification
func GenerateKyvernoPolicy(publicKey string) (string, error) {
	if publicKey == "" {
		return "", fmt.Errorf("public key is required")
	}

	// Indent the public key for proper YAML formatting
	indentedKey := indentString(strings.TrimSpace(publicKey), "                ")

	// Build the policy by string replacement to avoid template parsing issues with Kyverno syntax
	policy := kyvernoPolicyTemplate
	policy = strings.ReplaceAll(policy, "{{.PublicKey}}", indentedKey)

	return policy, nil
}

// indentString adds indentation to each line of a string
func indentString(s, indent string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = indent + line
		}
	}
	return strings.Join(lines, "\n")
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
    exclude:
      any:
      - resources:
          namespaces:
          - kube-system
          - cattle-fleet-system
          - cattle-system
          - kyverno
          - suppline
    verifyImages:
    - imageReferences:
      - "*"
      verifyDigest: false
      mutateDigest: false
      attestations:
      - type: https://in-toto.io/attestation/scai/attribute-report/v0.3
        conditions:
        - all:
          - key: '{{ time_since('''',''{{ evidence.validUntil }}'', '''') }}'
            operator: LessThan
            value: 0h
          - key: "{{ evidence.scanStatus }}"
            operator: AnyIn
            value: ["passed", "passed-with-exceptions"]
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

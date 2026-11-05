package integration

import (
	"fmt"
	"strings"
)

// GenerateKyvernoPolicy generates a Kyverno ImageValidatingPolicy YAML for SCAI attestation verification.
// ClusterPolicy (kyverno.io/v1) is deprecated as of Kyverno 1.19; image verification lives on
// ImageValidatingPolicy (policies.kyverno.io/v1).
func GenerateKyvernoPolicy(publicKey string) (string, error) {
	if publicKey == "" {
		return "", fmt.Errorf("public key is required")
	}

	// Indent the public key for proper YAML formatting under the cosign key block.
	indentedKey := indentString(strings.TrimSpace(publicKey), "          ")

	// Build the policy by string replacement to avoid template parsing issues with CEL syntax.
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

// kyvernoPolicyTemplate is an ImageValidatingPolicy equivalent of the previous verifyImages ClusterPolicy:
// every pod image (including init and ephemeral containers) must carry a SCAI attestation signed by the
// suppline key, with scanStatus passed or passed-with-exceptions, and validUntil still in the future.
// Attestations are produced with cosign --tlog-upload=false, so transparency-log checks stay disabled.
// validationActions starts at Audit; switch it to Deny to enforce.
const kyvernoPolicyTemplate = `apiVersion: policies.kyverno.io/v1
kind: ImageValidatingPolicy
metadata:
  name: suppline-policy
spec:
  validationActions:
  - Audit
  failurePolicy: Fail
  webhookConfiguration:
    timeoutSeconds: 30
  evaluation:
    background:
      enabled: false
  matchConstraints:
    resourceRules:
    - apiGroups:
      - ""
      apiVersions:
      - v1
      operations:
      - CREATE
      - UPDATE
      resources:
      - pods
  matchConditions:
  - name: exclude-system-namespaces
    expression: "!(object.metadata.namespace in ['kube-system', 'cattle-fleet-system', 'cattle-system', 'kyverno', 'suppline'])"
  matchImageReferences:
  - expression: "true"
  validationConfigurations:
    mutateDigest: false
    verifyDigest: false
    required: true
  attestors:
  - name: suppline
    cosign:
      key:
        data: |
{{.PublicKey}}
      ctlog:
        insecureIgnoreTlog: true
        url: https://rekor.sigstore.dev
  attestations:
  - name: scai
    intoto:
      type: https://in-toto.io/attestation/scai/attribute-report/v0.3
  validations:
  - expression: >-
      (images.containers + images.?initContainers.orValue([]) + images.?ephemeralContainers.orValue([])).map(image, verifyAttestationSignatures(image, attestations.scai, [attestors.suppline]) > 0 ? extractPayload(image, attestations.scai) : dyn(null)).all(payload, payload != null && string(payload.predicate.evidence.scanStatus) in ['passed', 'passed-with-exceptions'] && timestamp(string(payload.predicate.evidence.validUntil)) > time.now())
    message: "SCAI attestation must be signed by the suppline key, scanStatus must be passed or passed-with-exceptions, and validUntil must be in the future"
`

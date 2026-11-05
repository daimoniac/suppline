package integration

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerateKyvernoPolicyRequiresKey(t *testing.T) {
	if _, err := GenerateKyvernoPolicy(""); err == nil {
		t.Fatal("expected error when public key is empty")
	}
}

func TestGenerateKyvernoPolicyImageValidatingPolicy(t *testing.T) {
	const publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
-----END PUBLIC KEY-----`

	raw, err := GenerateKyvernoPolicy(publicKey)
	if err != nil {
		t.Fatalf("generate policy: %v", err)
	}
	if strings.Contains(raw, "apiVersion: kyverno.io/v1") || strings.Contains(raw, "kind: ClusterPolicy") {
		t.Fatalf("policy still uses deprecated ClusterPolicy:\n%s", raw)
	}

	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("policy is not valid YAML: %v\n%s", err, raw)
	}
	if doc["apiVersion"] != "policies.kyverno.io/v1" || doc["kind"] != "ImageValidatingPolicy" {
		t.Fatalf("apiVersion/kind = %v %v", doc["apiVersion"], doc["kind"])
	}

	spec := asMap(t, doc["spec"])
	actions := asSlice(t, spec["validationActions"])
	if len(actions) != 1 || actions[0] != "Audit" {
		t.Fatalf("validationActions = %#v", actions)
	}
	if spec["failurePolicy"] != "Fail" {
		t.Fatalf("failurePolicy = %#v", spec["failurePolicy"])
	}

	configs := asMap(t, spec["validationConfigurations"])
	if configs["mutateDigest"] != false || configs["verifyDigest"] != false || configs["required"] != true {
		t.Fatalf("validationConfigurations = %#v", configs)
	}

	attestors := asSlice(t, spec["attestors"])
	cosign := asMap(t, asMap(t, attestors[0])["cosign"])
	key := asMap(t, cosign["key"])
	if strings.TrimSpace(key["data"].(string)) != publicKey {
		t.Fatalf("public key not embedded:\n%q", key["data"])
	}
	ctlog := asMap(t, cosign["ctlog"])
	if ctlog["insecureIgnoreTlog"] != true || ctlog["url"] != "https://rekor.sigstore.dev" {
		t.Fatalf("ctlog = %#v", ctlog)
	}

	attestations := asSlice(t, spec["attestations"])
	intoto := asMap(t, asMap(t, attestations[0])["intoto"])
	if intoto["type"] != "https://in-toto.io/attestation/scai/attribute-report/v0.3" {
		t.Fatalf("attestation type = %#v", intoto["type"])
	}

	expr := asMap(t, asSlice(t, spec["validations"])[0])["expression"].(string)
	for _, want := range []string{
		"verifyAttestationSignatures",
		"payload.predicate.evidence.scanStatus",
		"passed-with-exceptions",
		"payload.predicate.evidence.validUntil",
		"time.now()",
		"images.?initContainers.orValue([])",
		"images.?ephemeralContainers.orValue([])",
	} {
		if !strings.Contains(expr, want) {
			t.Errorf("validation expression missing %q:\n%s", want, expr)
		}
	}

	match := asMap(t, asSlice(t, spec["matchConditions"])[0])["expression"].(string)
	for _, ns := range []string{"kube-system", "cattle-fleet-system", "cattle-system", "kyverno", "suppline"} {
		if !strings.Contains(match, ns) {
			t.Errorf("namespace exclusion missing %s: %s", ns, match)
		}
	}
}

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected map, got %T", v)
	}
	return m
}

func asSlice(t *testing.T, v any) []any {
	t.Helper()
	s, ok := v.([]any)
	if !ok {
		t.Fatalf("expected slice, got %T", v)
	}
	return s
}

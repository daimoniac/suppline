package integration

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type rewritePolicy struct {
	Kind string `yaml:"kind"`
	Spec struct {
		FailurePolicy    string `yaml:"failurePolicy"`
		MatchConstraints struct {
			NamespaceSelector struct {
				MatchLabels map[string]string `yaml:"matchLabels"`
			} `yaml:"namespaceSelector"`
		} `yaml:"matchConstraints"`
		Variables []struct {
			Name       string `yaml:"name"`
			Expression string `yaml:"expression"`
		} `yaml:"variables"`
		Mutations []struct {
			ApplyConfiguration struct {
				Expression string `yaml:"expression"`
			} `yaml:"applyConfiguration"`
		} `yaml:"mutations"`
	} `yaml:"spec"`
}

func parseRewrite(t *testing.T, opts RewriteOptions) rewritePolicy {
	t.Helper()
	out, err := GenerateMirrorRewritePolicy(opts)
	if err != nil {
		t.Fatalf("GenerateMirrorRewritePolicy: %v", err)
	}
	var policy rewritePolicy
	if err := yaml.Unmarshal([]byte(out), &policy); err != nil {
		t.Fatalf("generated policy is not YAML: %v\n%s", err, out)
	}
	return policy
}

func variable(p rewritePolicy, name string) string {
	for _, v := range p.Spec.Variables {
		if v.Name == name {
			return v.Expression
		}
	}
	return ""
}

func TestGenerateMirrorRewritePolicyDefaults(t *testing.T) {
	policy := parseRewrite(t, RewriteOptions{Mirror: "/harbor.example.com/mirror/"})

	if policy.Kind != "MutatingPolicy" || policy.Spec.FailurePolicy != "Ignore" {
		t.Errorf("kind=%q failurePolicy=%q", policy.Kind, policy.Spec.FailurePolicy)
	}
	if got := variable(policy, "mirror"); got != "'harbor.example.com/mirror'" {
		t.Errorf("mirror = %q", got)
	}
	if got := variable(policy, "sources"); got != "['index.docker.io']" {
		t.Errorf("sources = %q", got)
	}
	if policy.Spec.MatchConstraints.NamespaceSelector.MatchLabels[MirrorLabel] != "true" {
		t.Errorf("default scope must be opt-in by label: %+v", policy.Spec.MatchConstraints)
	}
	expr := policy.Spec.Mutations[0].ApplyConfiguration.Expression
	for _, want := range []string{
		"object.spec.containers.map(",
		"object.spec.?initContainers.orValue([]).map(",
		`.replace("/", "_")`,
		`startsWith("library/")`,
		"containsDigest()",
	} {
		if !strings.Contains(expr, want) {
			t.Errorf("expression missing %q:\n%s", want, expr)
		}
	}
}

func TestGenerateMirrorRewritePolicyScopeAndRegistries(t *testing.T) {
	policy := parseRewrite(t, RewriteOptions{
		Mirror:        "harbor.example.com",
		Registries:    []string{"GHCR.io", "docker.io", "registry-1.docker.io", "quay.io", " "},
		AllNamespaces: true,
	})
	if got := variable(policy, "sources"); got != "['ghcr.io', 'index.docker.io', 'quay.io']" {
		t.Errorf("sources = %q", got)
	}
	if len(policy.Spec.MatchConstraints.NamespaceSelector.MatchLabels) != 0 {
		t.Errorf("scope=all must not select by label: %+v", policy.Spec.MatchConstraints)
	}
}

func TestGenerateMirrorRewritePolicyRejectsBadInput(t *testing.T) {
	cases := map[string]RewriteOptions{
		"no mirror":          {},
		"quote in mirror":    {Mirror: "evil'.com"},
		"space in mirror":    {Mirror: "a b"},
		"quote in registry":  {Mirror: "m.example.com", Registries: []string{"a'b"}},
		"mirror as source":   {Mirror: "m.example.com/x", Registries: []string{"m.example.com"}},
		"only empty sources": {Mirror: "m.example.com", Registries: []string{" ", ""}},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := GenerateMirrorRewritePolicy(opts); err == nil {
				t.Errorf("expected an error for %+v", opts)
			}
		})
	}
}

func TestMirrorRewriteAgreesWithMigrationNames(t *testing.T) {
	// The policy's rename is "strip library/ on Docker Hub, then / -> _". FlatName plus splitImage is the plan's.
	for ref, want := range map[string]string{
		"nginx":                       "nginx",
		"docker.io/library/redis":     "redis",
		"grafana/grafana":             "grafana_grafana",
		"ghcr.io/foo/bar/baz":         "foo_bar_baz",
		"index.docker.io/bitnami/pg":  "bitnami_pg",
		"registry.k8s.io/pause/amd64": "pause_amd64",
	} {
		if got := FlatName(splitImage(ref, "", "").path); got != want {
			t.Errorf("FlatName(%q) = %q, want %q", ref, got, want)
		}
	}
}

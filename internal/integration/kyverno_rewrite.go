package integration

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// DefaultRewriteRegistries are the registries the rewrite policy redirects when the caller names none.
var DefaultRewriteRegistries = []string{"docker.io"}

// MirrorLabel is the namespace label that opts a namespace into the rewrite policy when it is generated in
// labeled scope.
const MirrorLabel = "suppline.cloud/mirror"

var (
	mirrorRE   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]*[a-zA-Z0-9]$`)
	registryRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]*$`)
)

// RewriteOptions configures GenerateMirrorRewritePolicy.
type RewriteOptions struct {
	// Mirror is the registry with its path prefix, as in a sync target: "harbor.example.com/mirror".
	Mirror string
	// Registries are the source registries whose images are redirected. Default: DefaultRewriteRegistries.
	Registries []string
	// AllNamespaces applies the policy to every namespace. By default only namespaces carrying MirrorLabel
	// are affected, so a rollout can start with one of them.
	AllNamespaces bool
}

// GenerateMirrorRewritePolicy generates a Kyverno MutatingPolicy that points pods at the mirror.
//
// An image from a listed registry becomes <mirror>/<flat name>:<tag>, with the flat name the sync entries from
// the migration plan use (FlatName). A digest stays. Images from other registries are left alone. The policy
// mutates pods only, not Deployments, so a GitOps tool never sees a difference from what it applied. It fails
// open: if Kyverno is down a pod keeps its upstream image, the attestation policy is what denies.
func GenerateMirrorRewritePolicy(opts RewriteOptions) (string, error) {
	mirror := strings.Trim(strings.TrimSpace(opts.Mirror), "/")
	if mirror == "" {
		return "", fmt.Errorf("mirror registry is required")
	}
	if !mirrorRE.MatchString(mirror) {
		return "", fmt.Errorf("mirror %q is not a registry with an optional path", mirror)
	}

	registries := opts.Registries
	if len(registries) == 0 {
		registries = DefaultRewriteRegistries
	}
	seen := make(map[string]struct{})
	var normalized []string
	for _, registry := range registries {
		registry = strings.ToLower(strings.TrimSpace(registry))
		if registry == "" {
			continue
		}
		if !registryRE.MatchString(registry) {
			return "", fmt.Errorf("registry %q is not a registry host", registry)
		}
		switch registry {
		case "docker.io", "registry-1.docker.io":
			registry = "index.docker.io"
		}
		if registry == mirrorHost(mirror) {
			return "", fmt.Errorf("registry %q is the mirror itself", registry)
		}
		if _, ok := seen[registry]; ok {
			continue
		}
		seen[registry] = struct{}{}
		normalized = append(normalized, registry)
	}
	if len(normalized) == 0 {
		return "", fmt.Errorf("at least one registry is required")
	}
	sort.Strings(normalized)
	quoted := make([]string, len(normalized))
	for i, registry := range normalized {
		quoted[i] = "'" + registry + "'"
	}

	selector := fmt.Sprintf(`    namespaceSelector:
      matchLabels:
        %s: "true"
`, MirrorLabel)
	scope := fmt.Sprintf("Only namespaces labeled %s=true are affected.", MirrorLabel)
	if opts.AllNamespaces {
		selector = ""
		scope = "Every namespace is affected except the system ones."
	}

	policy := mirrorRewriteTemplate
	policy = strings.ReplaceAll(policy, "{{.Scope}}", scope)
	policy = strings.ReplaceAll(policy, "{{.Selector}}", selector)
	policy = strings.ReplaceAll(policy, "{{.Mirror}}", mirror)
	policy = strings.ReplaceAll(policy, "{{.Sources}}", strings.Join(quoted, ", "))
	policy = strings.ReplaceAll(policy, "{{.Containers}}", rewriteListExpression("object.spec.containers", "Object.spec.containers"))
	policy = strings.ReplaceAll(policy, "{{.InitContainers}}", rewriteListExpression("object.spec.?initContainers.orValue([])", "Object.spec.initContainers"))
	return policy, nil
}

func mirrorHost(mirror string) string {
	host, _, _ := strings.Cut(mirror, "/")
	return strings.ToLower(host)
}

// rewriteListExpression is the CEL that maps one list of containers to apply-configuration entries. A merge
// by container name leaves everything but the image alone.
func rewriteListExpression(list, entry string) string {
	const ref = "c.image"
	return fmt.Sprintf(`%[1]s.map(c, %[2]s{
              name: c.name,
              image: image(%[3]s).registry() in variables.sources
                ? variables.mirror + "/"
                  + (image(%[3]s).registry() == "index.docker.io" && image(%[3]s).repository().startsWith("library/")
                      ? image(%[3]s).repository().substring(8) : image(%[3]s).repository()).replace("/", "_")
                  + (image(%[3]s).tag() != "" ? ":" + image(%[3]s).tag() : "")
                  + (image(%[3]s).containsDigest() ? "@" + image(%[3]s).digest() : "")
                : %[3]s
            })`, list, entry, ref)
}

// mirrorRewriteTemplate is a MutatingPolicy (policies.kyverno.io/v1; ClusterPolicy mutation is deprecated).
const mirrorRewriteTemplate = `apiVersion: policies.kyverno.io/v1
kind: MutatingPolicy
metadata:
  name: suppline-mirror-rewrite
  annotations:
    suppline.cloud/description: >-
      Pull images from the suppline mirror instead of their upstream registry. {{.Scope}}
spec:
  failurePolicy: Ignore
  autogen:
    podControllers:
      controllers: []
  evaluation:
    admission:
      enabled: true
  matchConstraints:
{{.Selector}}    resourceRules:
    - apiGroups:
      - ""
      apiVersions:
      - v1
      operations:
      - CREATE
      resources:
      - pods
  matchConditions:
  - name: exclude-system-namespaces
    expression: "!(object.metadata.namespace in ['kube-system', 'cattle-fleet-system', 'cattle-system', 'kyverno', 'suppline'])"
  variables:
  - name: mirror
    expression: "'{{.Mirror}}'"
  - name: sources
    expression: "[{{.Sources}}]"
  mutations:
  - patchType: ApplyConfiguration
    applyConfiguration:
      expression: >-
        Object{
          spec: Object.spec{
            containers: {{.Containers}},
            initContainers: {{.InitContainers}}
          }
        }
`

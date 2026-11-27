package integration

import (
	"fmt"
	"sort"
	"strings"
)

// SyncTargetTemplate is how a generated sync entry names the mirror when the
// caller gave none: the registry the install is already configured with.
const SyncTargetTemplate = `{{ env "SUPPLINE_REGISTRY_URL" }}`

// RunningImage is one image a cluster agent reported.
type RunningImage struct {
	ImageRef string
	Tag      string
	Digest   string
}

// ConfiguredSource is the source of a sync entry that already exists.
type ConfiguredSource struct {
	Source string
	// Type is the entry's type: "image", "repository", or empty.
	Type string
}

// SyncSuggestion is a sync entry to add.
type SyncSuggestion struct {
	Source string
	Target string
}

// MigrationPlan is what moving a cluster onto the mirror needs.
type MigrationPlan struct {
	// Mirror is the registry (with path prefix) the cluster will pull from.
	Mirror string
	// Sync lists the entries to add, sorted by source.
	Sync []SyncSuggestion
	// Covered lists running images that a sync entry already mirrors.
	Covered []string
	// Mirrored lists running images that already come from the mirror.
	Mirrored []string
	// Warnings lists what the plan could not decide.
	Warnings []string
}

type imageName struct {
	registry string
	path     string
	tag      string
	digest   string
}

func (n imageName) repository() string { return n.registry + "/" + n.path }

func (n imageName) String() string {
	out := n.repository()
	if n.tag != "" {
		out += ":" + n.tag
	}
	if n.digest != "" {
		out += "@" + n.digest
	}
	return out
}

// FlatName is the repository name the mirror uses for an image: the registry
// is dropped, a Docker Hub "library/" prefix is dropped, and "/" becomes "_".
// It is what the generated sync entries and the rewrite policy agree on, and
// it matches the hand-written entries of existing installs.
func FlatName(path string) string {
	return strings.ReplaceAll(path, "/", "_")
}

// splitImage reads a reference as Kubernetes or the cluster agent writes it:
// the agent reports the repository, tag and digest separately, a pod spec
// carries them in one string. Docker Hub is the default registry.
func splitImage(ref, tag, digest string) imageName {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		if digest == "" {
			digest = ref[i+1:]
		}
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		if tag == "" {
			tag = ref[i+1:]
		}
		ref = ref[:i]
	}

	registry, path := "docker.io", ref
	if i := strings.Index(ref, "/"); i >= 0 {
		first := ref[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			registry, path = first, ref[i+1:]
		}
	}
	switch registry {
	case "index.docker.io", "registry-1.docker.io":
		registry = "docker.io"
	}
	if registry == "docker.io" {
		path = strings.TrimPrefix(path, "library/")
	}
	return imageName{registry: registry, path: path, tag: strings.TrimSpace(tag), digest: strings.TrimSpace(digest)}
}

// ExcludeRegistries drops the images that come from one of the given registries,
// for images a team builds itself and has no reason to mirror. Docker Hub is
// matched by "docker.io" however the image names it.
func ExcludeRegistries(images []RunningImage, registries []string) []RunningImage {
	skip := make(map[string]struct{}, len(registries))
	for _, registry := range registries {
		registry = strings.ToLower(strings.TrimSpace(registry))
		switch registry {
		case "":
			continue
		case "index.docker.io", "registry-1.docker.io":
			registry = "docker.io"
		}
		skip[registry] = struct{}{}
	}
	if len(skip) == 0 {
		return images
	}
	kept := make([]RunningImage, 0, len(images))
	for _, image := range images {
		if _, drop := skip[strings.ToLower(splitImage(image.ImageRef, image.Tag, image.Digest).registry)]; !drop {
			kept = append(kept, image)
		}
	}
	return kept
}

// PlanMigration works out the sync entries a cluster's running images need.
//
// An image is skipped when it already comes from the mirror, or when a
// configured entry already copies it: a repository entry copies every tag, an
// image entry only its own. A tag filter on a repository entry is not
// evaluated, so a filtered entry counts as covering. mirror is the registry
// with its path prefix, as in a sync target. When targetPrefix is empty the
// entries name the mirror through SyncTargetTemplate.
func PlanMigration(images []RunningImage, mirror, targetPrefix string, configured []ConfiguredSource) MigrationPlan {
	mirror = strings.Trim(strings.TrimSpace(mirror), "/")
	if targetPrefix == "" {
		targetPrefix = SyncTargetTemplate
	}
	plan := MigrationPlan{Mirror: mirror}

	type coverage struct {
		allTags bool
		tags    map[string]struct{}
	}
	covers := make(map[string]*coverage)
	for _, source := range configured {
		name := splitImage(source.Source, "", "")
		entry := covers[name.repository()]
		if entry == nil {
			entry = &coverage{tags: make(map[string]struct{})}
			covers[name.repository()] = entry
		}
		if name.tag == "" && source.Type != "image" {
			entry.allTags = true
		} else if name.tag != "" {
			entry.tags[name.tag] = struct{}{}
		}
	}

	suggested := make(map[string]SyncSuggestion)
	covered := make(map[string]struct{})
	mirrored := make(map[string]struct{})
	flatOwners := make(map[string]map[string]struct{})
	noTag := make(map[string]struct{})

	for _, image := range images {
		name := splitImage(image.ImageRef, image.Tag, image.Digest)
		if name.path == "" {
			continue
		}
		if mirror != "" && strings.HasPrefix(name.repository()+"/", mirror+"/") {
			mirrored[name.repository()] = struct{}{}
			continue
		}
		if name.tag == "" {
			// Only a digest is known. A sync entry copies by tag.
			noTag[name.String()] = struct{}{}
			continue
		}
		if entry := covers[name.repository()]; entry != nil {
			if _, ok := entry.tags[name.tag]; ok || entry.allTags {
				covered[name.repository()+":"+name.tag] = struct{}{}
				continue
			}
		}
		key := name.repository() + ":" + name.tag
		source := name.repository()
		if name.registry == "docker.io" && !strings.Contains(name.path, "/") {
			source = "docker.io/library/" + name.path
		}
		flat := FlatName(name.path)
		suggested[key] = SyncSuggestion{
			Source: source + ":" + name.tag,
			Target: targetPrefix + "/" + flat + ":" + name.tag,
		}
		if flatOwners[flat] == nil {
			flatOwners[flat] = make(map[string]struct{})
		}
		flatOwners[flat][name.repository()] = struct{}{}
	}

	for _, suggestion := range suggested {
		plan.Sync = append(plan.Sync, suggestion)
	}
	sort.Slice(plan.Sync, func(i, j int) bool { return plan.Sync[i].Source < plan.Sync[j].Source })
	plan.Covered = sortedSet(covered)
	plan.Mirrored = sortedSet(mirrored)

	for _, flat := range sortedKeysOf(flatOwners) {
		owners := sortedSet(flatOwners[flat])
		if len(owners) > 1 {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf(
				"%s would all be mirrored as %q and overwrite each other: give all but one a hand-written target", strings.Join(owners, ", "), flat))
		}
	}
	for _, ref := range sortedSet(noTag) {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf(
			"%s is pinned by digest and no tag is known: add a sync entry for it with the tag it was built from", ref))
	}
	return plan
}

func sortedSet(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sortedKeysOf(m map[string]map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// YAML renders the plan as a commented snippet to paste into suppline.yml.
func (p MigrationPlan) YAML(cluster string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# suppline migration plan for cluster %q\n", cluster)
	if p.Mirror != "" {
		fmt.Fprintf(&b, "# Mirror: %s\n", p.Mirror)
	}
	b.WriteString("#\n# Review the list first: images you build yourself belong in your own registry,\n")
	b.WriteString("# not in the mirror (re-fetch with ?exclude=<registry>[,<registry>] to drop them).\n")
	b.WriteString("#\n# Add these entries under `sync:` in suppline.yml. Each copies one running tag\n")
	b.WriteString("# into the mirror and puts it through the same scan, policy and attestation as\n")
	b.WriteString("# every other image. Then apply the rewrite policy so pods pull from the mirror:\n")
	b.WriteString("#   GET /api/v1/integration/kyverno/mirror-rewrite\n")
	fmt.Fprintf(&b, "#\n# %d to add, %d already synced, %d already pulled from the mirror.\n", len(p.Sync), len(p.Covered), len(p.Mirrored))
	for _, warning := range p.Warnings {
		fmt.Fprintf(&b, "# WARNING: %s\n", warning)
	}
	if len(p.Sync) == 0 {
		b.WriteString("sync: []\n")
		return b.String()
	}
	b.WriteString("sync:\n")
	for _, suggestion := range p.Sync {
		fmt.Fprintf(&b, "  - source: %s\n", suggestion.Source)
		fmt.Fprintf(&b, "    target: '%s'\n", suggestion.Target)
		b.WriteString("    type: image\n")
	}
	return b.String()
}

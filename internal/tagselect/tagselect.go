// Package tagselect decides which tags of a repository an entry covers:
// anchored allow/deny regexes, semver ranges, and a newest-N window by build
// time. The mirror uses it to pick what to copy; the watcher uses it to pick
// which tags of an in-place repository to scan.
package tagselect

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/semverutil"
)

func Sets(s config.SyncEntry) []config.TagFilter {
	sets := append([]config.TagFilter{}, s.TagSets...)
	tags := config.TagFilter{}
	if s.Tags != nil {
		tags = *s.Tags
	}
	if len(tags.Allow) > 0 || len(tags.Deny) > 0 || len(tags.SemverRange) > 0 || tags.Newest > 0 {
		sets = append(sets, tags)
	}
	return sets
}

func Filter(tags config.TagFilter, in []string) ([]string, error) {
	result := in
	if len(tags.SemverRange) > 0 {
		filtered, err := filterSemver(tags.SemverRange, result)
		if err != nil {
			return nil, err
		}
		result = filtered
	}
	var err error
	if len(tags.Allow) > 0 {
		result, err = FilterRegexAllow(tags.Allow, result)
		if err != nil {
			return nil, err
		}
	}
	return FilterRegexDeny(tags.Deny, result)
}

func filterSemver(ranges, in []string) ([]string, error) {
	constraints := make([]*semverutil.Constraint, 0, len(ranges))
	for _, rangeStr := range ranges {
		if rangeStr == "" {
			continue
		}
		constraint, err := semverutil.NewConstraint(rangeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid semver range %q: %w", rangeStr, err)
		}
		constraints = append(constraints, constraint)
	}
	if len(constraints) == 0 {
		return in, nil
	}
	filtered := make([]string, 0, len(in))
	for _, tag := range in {
		version, ok := semverutil.ParseVersion(tag)
		if !ok {
			continue
		}
		for _, constraint := range constraints {
			if semverutil.Satisfies(constraint, version) {
				filtered = append(filtered, tag)
				break
			}
		}
	}
	return filtered, nil
}

func FilterRegexAllow(patterns, in []string) ([]string, error) {
	if len(patterns) == 0 {
		return in, nil
	}
	exps, err := compileAnchored(patterns, "allow")
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(in))
	for _, item := range in {
		for _, exp := range exps {
			if exp.MatchString(item) {
				result = append(result, item)
				break
			}
		}
	}
	return result, nil
}

func FilterRegexDeny(patterns, in []string) ([]string, error) {
	if len(patterns) == 0 {
		return in, nil
	}
	exps, err := compileAnchored(patterns, "deny")
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(in))
	for _, item := range in {
		denied := false
		for _, exp := range exps {
			if exp.MatchString(item) {
				denied = true
				break
			}
		}
		if !denied {
			result = append(result, item)
		}
	}
	return result, nil
}

func compileAnchored(patterns []string, kind string) ([]*regexp.Regexp, error) {
	exps := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		exp, err := regexp.Compile("^" + pattern + "$")
		if err != nil {
			return nil, fmt.Errorf("invalid %s pattern %q: %w", kind, pattern, err)
		}
		exps = append(exps, exp)
	}
	return exps, nil
}

// Newest keeps the n tags built last. Ties, including images whose
// created field is unset or fixed by a reproducible build, go to the higher
// tag name. n <= 0 keeps every tag. The result is newest first.
func Newest(tags []string, n int, created func(tag string) (time.Time, error)) ([]string, error) {
	if n <= 0 || len(tags) <= n {
		return tags, nil
	}
	type dated struct {
		tag     string
		created time.Time
	}
	all := make([]dated, 0, len(tags))
	for _, tag := range tags {
		at, err := created(tag)
		if err != nil {
			return nil, err
		}
		all = append(all, dated{tag: tag, created: at})
	}
	slices.SortFunc(all, func(a, b dated) int {
		if c := b.created.Compare(a.created); c != 0 {
			return c
		}
		return strings.Compare(b.tag, a.tag)
	})
	out := make([]string, 0, n)
	for _, d := range all[:n] {
		out = append(out, d.tag)
	}
	return out, nil
}

// Allowed reports whether any of the entry's tag sets lets tag through,
// ignoring newest windows. Without tag sets every tag is allowed.
func Allowed(entry config.SyncEntry, tag string) (bool, error) {
	sets := Sets(entry)
	if len(sets) == 0 {
		return true, nil
	}
	for _, set := range sets {
		got, err := Filter(set, []string{tag})
		if err != nil {
			return false, err
		}
		if len(got) == 1 {
			return true, nil
		}
	}
	return false, nil
}

// Select returns the tags any of the entry's tag sets selects, newest windows
// included. created reports when the image behind a tag was built; it is only
// called for sets with a newest window. Without tag sets every tag is selected.
func Select(entry config.SyncEntry, tags []string, created func(tag string) (time.Time, error)) ([]string, error) {
	sets := Sets(entry)
	if len(sets) == 0 {
		return tags, nil
	}
	selected := []string{}
	for _, set := range sets {
		filtered, err := Filter(set, tags)
		if err != nil {
			return nil, err
		}
		filtered, err = Newest(filtered, set.Newest, created)
		if err != nil {
			return nil, err
		}
		for _, tag := range filtered {
			if !slices.Contains(selected, tag) {
				selected = append(selected, tag)
			}
		}
	}
	return selected, nil
}

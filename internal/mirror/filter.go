package mirror

import (
	"fmt"
	"regexp"

	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/semverutil"
)

func entryTagSets(s config.SyncEntry) []config.TagFilter {
	sets := append([]config.TagFilter{}, s.TagSets...)
	tags := config.TagFilter{}
	if s.Tags != nil {
		tags = *s.Tags
	}
	if len(tags.Allow) > 0 || len(tags.Deny) > 0 || len(tags.SemverRange) > 0 {
		sets = append(sets, tags)
	}
	return sets
}

func filterTagList(tags config.TagFilter, in []string) ([]string, error) {
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
		result, err = filterRegexAllow(tags.Allow, result)
		if err != nil {
			return nil, err
		}
	}
	return filterRegexDeny(tags.Deny, result)
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

func filterRepoList(repos config.RepoFilter, in []string) ([]string, error) {
	result, err := filterRegexAllow(repos.Allow, in)
	if err != nil {
		return nil, err
	}
	return filterRegexDeny(repos.Deny, result)
}

func filterRegexAllow(patterns, in []string) ([]string, error) {
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

func filterRegexDeny(patterns, in []string) ([]string, error) {
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

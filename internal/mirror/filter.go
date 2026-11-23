package mirror

import (
	"github.com/daimoniac/suppline/internal/config"
	"github.com/daimoniac/suppline/internal/tagselect"
)

func entryTagSets(s config.SyncEntry) []config.TagFilter { return tagselect.Sets(s) }

func filterTagList(tags config.TagFilter, in []string) ([]string, error) {
	return tagselect.Filter(tags, in)
}

func filterRepoList(repos config.RepoFilter, in []string) ([]string, error) {
	result, err := tagselect.FilterRegexAllow(repos.Allow, in)
	if err != nil {
		return nil, err
	}
	return tagselect.FilterRegexDeny(repos.Deny, result)
}

package mirror

import (
	"slices"
	"testing"

	"github.com/daimoniac/suppline/internal/config"
)

func TestFilterTagList_Order(t *testing.T) {
	got, err := filterTagList(config.TagFilter{
		SemverRange: []string{">=1.2.0"},
		Allow:       []string{`1\..*`},
		Deny:        []string{`.*-debian`},
	}, []string{"1.2.3", "1.0.0", "latest", "1.2.3-debian", "alpine-v1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"1.2.3"}) {
		t.Fatalf("filtered = %#v", got)
	}
}

func TestFilterTagList_SemverRangesAreOR(t *testing.T) {
	got, err := filterTagList(config.TagFilter{
		SemverRange: []string{">=1.2.0 <1.3.0", "2.0.0"},
	}, []string{"1.2.5", "1.4.0", "2.0.0", "alpine-v0.9.0"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"1.2.5", "2.0.0"}) {
		t.Fatalf("filtered = %#v", got)
	}
}

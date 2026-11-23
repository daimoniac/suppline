package tagselect

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/config"
)

func TestSelectNewest(t *testing.T) {
	day := func(d int) time.Time { return time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC) }
	created := map[string]time.Time{
		"shaaaa": day(3),
		"shabbb": day(1),
		"shaccc": day(5),
		"shaddd": day(5), // same time as shaccc: higher name wins
		"shaeee": {},     // unset created sorts last
	}
	lookup := func(tag string) (time.Time, error) { return created[tag], nil }
	tags := []string{"shaaaa", "shabbb", "shaccc", "shaddd", "shaeee"}

	got, err := Newest(tags, 3, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"shaddd", "shaccc", "shaaaa"}; !slices.Equal(got, want) {
		t.Fatalf("newest 3 = %#v, want %#v", got, want)
	}

	for _, n := range []int{0, 5, 9} {
		got, err := Newest(tags, n, func(string) (time.Time, error) {
			t.Fatalf("n=%d must not read build times", n)
			return time.Time{}, nil
		})
		if err != nil || !slices.Equal(got, tags) {
			t.Fatalf("n=%d: got %#v, %v", n, got, err)
		}
	}

	boom := errors.New("registry down")
	if _, err := Newest(tags, 2, func(string) (time.Time, error) { return time.Time{}, boom }); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
}

func TestSelectUnionsSetsAndAllowedIgnoresNewest(t *testing.T) {
	entry := config.SyncEntry{
		Tags: &config.TagFilter{Allow: []string{"sha[0-9a-f]{8,}"}, Newest: 2},
	}
	day := func(d int) time.Time { return time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC) }
	created := map[string]time.Time{"sha11111111": day(1), "sha22222222": day(2), "sha33333333": day(3)}
	tags := []string{"sha11111111", "sha22222222", "sha33333333", "latest", "sha1"}
	got, err := Select(entry, tags, func(tag string) (time.Time, error) { return created[tag], nil })
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"sha33333333", "sha22222222"}; !slices.Equal(got, want) {
		t.Fatalf("Select = %#v, want %#v", got, want)
	}
	for tag, want := range map[string]bool{"sha11111111": true, "latest": false, "sha1": false} {
		ok, err := Allowed(entry, tag)
		if err != nil || ok != want {
			t.Errorf("Allowed(%q) = %t, %v; want %t", tag, ok, err, want)
		}
	}
	if ok, _ := Allowed(config.SyncEntry{}, "anything"); !ok {
		t.Error("an entry without tag sets allows every tag")
	}
}

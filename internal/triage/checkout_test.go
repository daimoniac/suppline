package triage

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDispatchGrepGoesThroughCheckouts(t *testing.T) {
	cache := filepath.Join(os.TempDir(), "suppline-image", "sha256_dispatch")
	if err := os.RemoveAll(cache); err != nil {
		t.Fatal(err)
	}
	roots := &Roots{Image: newImageFS(&copyUnpacker{src: imageFixture(t)}, "example/app", "sha256:dispatch")}
	pub := newPublicSource()
	job := Job{Repository: "example/app", PackageName: "github.com/labstack/echo/v4", Digest: "sha256:dispatch"}
	imageCall := toolCall{}
	imageCall.Function.Name = "grep"
	imageCall.Function.Arguments = `{"repo":"image","pattern":"Proxy","path":"."}`
	out := dispatchTool(context.Background(), roots, nil, pub, nil, nil, nil, job, imageCall)
	if !strings.Contains(out, "citable: absence") || strings.Contains(out, "error:") {
		t.Fatalf("image grep via dispatch: %s", out)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "values.yaml"), []byte("image: example/app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitops := &Roots{Checkouts: []CheckoutRoot{{Name: "infra", Dir: dir}}}
	gitopsCall := toolCall{}
	gitopsCall.Function.Name = "grep"
	gitopsCall.Function.Arguments = `{"repo":"infra","pattern":"example/app","path":"."}`
	gitopsOut := dispatchTool(context.Background(), gitops, nil, pub, nil, nil, nil, job, gitopsCall)
	if strings.Contains(gitopsOut, "grep_id:") || !strings.Contains(gitopsOut, "image: example/app") {
		t.Fatalf("gitops grep: %s", gitopsOut)
	}
}

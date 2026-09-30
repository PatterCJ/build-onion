package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/tagsig"
)

// A tag fetched the way `trust add` fetches it verifies against the key that
// signed it, and a lightweight tag is refused.
func TestFetchTag(t *testing.T) {
	for _, tool := range []string{"git", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	host := t.TempDir()
	repo := filepath.Join(host, "acme", "builder.git")
	key := filepath.Join(t.TempDir(), "key")
	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	run(host, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	os.MkdirAll(repo, 0o755)
	run(repo, "git", "init", "-q")
	g := []string{"git", "-c", "user.name=m", "-c", "user.email=m@example.com", "-c", "gpg.format=ssh", "-c", "user.signingkey=" + key}
	run(repo, append(g, "commit", "-q", "--allow-empty", "-m", "init")...)
	run(repo, append(g, "tag", "-s", "v1.0.0", "-m", "v1.0.0")...)
	run(repo, append(g, "tag", "v1.0.1")...)

	old := gitHost
	gitHost = "file://" + host + "/"
	defer func() { gitHost = old }()

	raw, err := fetchTag("acme/builder", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := os.ReadFile(key + ".pub")
	keys, _ := tagsig.Keys([]string{strings.TrimSpace(string(pub))})
	tag, err := tagsig.Verify(raw, keys)
	if err != nil || tag.Name != "v1.0.0" || len(tag.Object) != 40 {
		t.Fatalf("fetched tag doesn't verify: %+v %v", tag, err)
	}
	if _, err := fetchTag("acme/builder", "v1.0.1"); err == nil || !strings.Contains(err.Error(), "not an annotated tag") {
		t.Errorf("lightweight tag: %v", err)
	}
}

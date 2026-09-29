package peel

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/PatterCJ/build-onion/internal/builder"
	"github.com/PatterCJ/build-onion/internal/manifest"
)

// Rebuild exports the committed tree at HEAD of dir into a scratch directory,
// runs the manifest's fetch and hermetic build, and returns the digest of the
// named output file. Uncommitted changes in dir never reach the rebuild.
func Rebuild(dir string, m *manifest.Manifest, output string) (string, error) {
	tmp, err := os.MkdirTemp("", "onion-rebuild-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(tmp, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		return "", err
	}
	archive := exec.Command("sh", "-c", `git -C "$1" archive --format=tar HEAD | tar -x -C "$2"`, "sh", dir, src)
	if out, err := archive.CombinedOutput(); err != nil {
		return "", fmt.Errorf("export source: %v: %s", err, out)
	}
	r := builder.Runner{Stdout: os.Stderr, Stderr: os.Stderr}
	cache := filepath.Join(tmp, "cache")
	if _, err := r.Fetch(src, cache, m); err != nil {
		return "", err
	}
	if err := r.Build(src, cache, m); err != nil {
		return "", err
	}
	digests, err := builder.Collect(src, filepath.Join(tmp, "out"), m)
	if err != nil {
		return "", err
	}
	d, ok := digests[output]
	if !ok {
		return "", fmt.Errorf("manifest does not declare output %s", output)
	}
	return d, nil
}

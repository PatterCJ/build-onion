package peel

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/PatterCJ/build-onion/internal/builder"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/source"
)

// Rebuild stages the manifest's declared inputs from the clean checkout at
// dir into a scratch directory, exactly as the pipeline does, runs the fetch
// and hermetic build there, and returns the digest of the named output file.
// Uncommitted changes and undeclared files never reach the rebuild.
func Rebuild(dir, manifestPath string, m *manifest.Manifest, output string) (string, error) {
	snap, err := source.Take(dir)
	if err != nil {
		return "", err
	}
	inputs, err := snap.Subset(m.Build.Inputs, m.AlwaysInputs(manifestPath))
	if err != nil {
		return "", err
	}
	tmp, err := os.MkdirTemp("", "onion-rebuild-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(tmp, "src")
	if err := source.Stage(dir, src, inputs); err != nil {
		return "", err
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

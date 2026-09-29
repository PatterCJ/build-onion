// Package builder runs a manifest's fetch and build steps in its pinned
// builder image. The pipeline's build job and `onion peel --rebuild` both go
// through here, so there is exactly one definition of "the build".
package builder

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/manifest"
)

type Runner struct {
	Docker string // container CLI; "docker" when empty
	Stdout io.Writer
	Stderr io.Writer
}

// Fetch populates cacheDir with dependencies, with network access.
func (r Runner) Fetch(srcDir, cacheDir string, m *manifest.Manifest) error {
	if m.Dependencies.Fetch == "" {
		return nil
	}
	return r.run(srcDir, cacheDir, m, m.Dependencies.Fetch, true)
}

// Build runs the build step with no network. Only srcDir and the fetched
// cache are visible to it.
func (r Runner) Build(srcDir, cacheDir string, m *manifest.Manifest) error {
	return r.run(srcDir, cacheDir, m, m.Build.Run, false)
}

func (r Runner) run(srcDir, cacheDir string, m *manifest.Manifest, script string, network bool) error {
	src, err := filepath.Abs(srcDir)
	if err != nil {
		return err
	}
	args := []string{"run", "--rm",
		"--user", strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid()),
		"-v", src + ":/src", "-w", "/src",
		"-e", "HOME=/tmp",
	}
	if !network {
		args = append(args, "--network", "none")
	}
	if m.Dependencies.Cache != "" {
		cache, err := filepath.Abs(cacheDir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(cache, 0o755); err != nil {
			return err
		}
		args = append(args, "-v", cache+":"+m.Dependencies.Cache)
	}
	// build.env belongs to the offline build only; settings like GOPROXY=off
	// would break the fetch.
	if !network {
		keys := make([]string, 0, len(m.Build.Env))
		for k := range m.Build.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			args = append(args, "-e", k+"="+m.Build.Env[k])
		}
	}
	args = append(args, m.Builder.Image, "sh", "-euc", script)

	docker := r.Docker
	if docker == "" {
		docker = "docker"
	}
	cmd := exec.Command(docker, args...)
	cmd.Stdout, cmd.Stderr = r.Stdout, r.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s in %s: %w", map[bool]string{true: "fetch", false: "build"}[network], m.Builder.Image, err)
	}
	return nil
}

// Collect copies each declared output file into outDir by basename and
// returns their digests.
func Collect(srcDir, outDir string, m *manifest.Manifest) (map[string]string, error) {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	digests := map[string]string{}
	for _, f := range m.Outputs.Files {
		raw, err := os.ReadFile(filepath.Join(srcDir, f))
		if err != nil {
			return nil, fmt.Errorf("declared output %s was not produced: %w", f, err)
		}
		name := filepath.Base(f)
		if err := os.WriteFile(filepath.Join(outDir, name), raw, 0o755); err != nil {
			return nil, err
		}
		digests[name] = digest.Bytes(raw)
	}
	return digests, nil
}

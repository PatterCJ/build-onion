// Package lint checks a source tree against its manifest before anything runs:
// the toolchain layer of the onion. Every input the build can reach must be
// pinned to an immutable reference.
package lint

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/source"
)

var (
	// uses: owner/repo[/path]@<40 hex> | ./local | docker://…@sha256:…
	usesRe      = regexp.MustCompile(`^\s*-?\s*uses:\s*["']?([^"'\s#]+)`)
	pinnedUseRe = regexp.MustCompile(`^[^@\s]+@[a-f0-9]{40}$`)
	fromRe      = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)
)

// Repo validates the manifest against the checked-out tree at root.
func Repo(root string, m *manifest.Manifest) error {
	var errs []error
	for _, l := range m.Dependencies.Lockfiles {
		if _, err := os.Stat(filepath.Join(root, l)); err != nil {
			errs = append(errs, fmt.Errorf("lockfile %s: %w", l, err))
		}
	}
	for _, f := range m.Outputs.Files {
		if _, err := os.Stat(filepath.Join(root, f)); err == nil {
			errs = append(errs, fmt.Errorf("output %s already exists in source; outputs must be produced by the build", f))
		}
	}
	if img := m.Outputs.Image; img != nil {
		errs = append(errs, Dockerfile(filepath.Join(root, img.Dockerfile)))
	}
	errs = append(errs, Workflows(filepath.Join(root, ".github", "workflows")))
	errs = append(errs, sensitiveCoverage(root, m.Build.Sensitive))
	return errors.Join(errs...)
}

// sensitiveCoverage requires every build.sensitive pattern to match a tracked
// file, so a renamed or moved build script can't silently drop out of the list.
func sensitiveCoverage(root string, patterns []string) error {
	if len(patterns) == 0 {
		return nil
	}
	files, err := trackedFiles(root)
	if err != nil {
		return err
	}
	var errs []error
	for _, pat := range patterns {
		hit := false
		for _, f := range files {
			if source.Match(pat, f) {
				hit = true
				break
			}
		}
		if !hit {
			errs = append(errs, fmt.Errorf("build.sensitive pattern %q matches no tracked file", pat))
		}
	}
	return errors.Join(errs...)
}

// trackedFiles lists git-tracked files under root, or every file when root
// isn't a git checkout.
func trackedFiles(root string) ([]string, error) {
	if out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output(); err == nil {
		var files []string
		for _, f := range strings.Split(string(out), "\x00") {
			if f != "" {
				files = append(files, f)
			}
		}
		return files, nil
	}
	var files []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		files = append(files, filepath.ToSlash(rel))
		return err
	})
	return files, err
}

// Dockerfile requires every external FROM to be pinned by digest. Stages that
// build FROM an earlier stage name are allowed.
func Dockerfile(p string) error {
	_, err := BaseImages(p)
	return err
}

// BaseImages lists the external images a Dockerfile builds FROM, in order,
// and fails if any is not pinned by digest. Earlier stage names and scratch
// are not external.
func BaseImages(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("dockerfile: %w", err)
	}
	defer f.Close()
	var refs []string
	var errs []error
	stages := map[string]bool{"scratch": true}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		mm := fromRe.FindStringSubmatch(sc.Text())
		if mm == nil {
			continue
		}
		ref := mm[1]
		if !stages[strings.ToLower(ref)] {
			if manifest.IsPinnedImage(ref) {
				refs = append(refs, ref)
			} else {
				errs = append(errs, fmt.Errorf("%s:%d: FROM %s is not pinned by digest", filepath.Base(p), n, ref))
			}
		}
		if mm[2] != "" {
			stages[strings.ToLower(mm[2])] = true
		}
	}
	return refs, errors.Join(append(errs, sc.Err())...)
}

// Workflows requires every `uses:` in the repo's workflows to be pinned to a
// full commit SHA. Tags and branches are mutable and can be repointed.
func Workflows(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		errs = append(errs, workflowFile(filepath.Join(dir, e.Name())))
	}
	return errors.Join(errs...)
}

func workflowFile(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	var errs []error
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		mm := usesRe.FindStringSubmatch(sc.Text())
		if mm == nil {
			continue
		}
		ref := mm[1]
		switch {
		case strings.HasPrefix(ref, "./"):
		case strings.HasPrefix(ref, "docker://"):
			if !manifest.IsPinnedImage(strings.TrimPrefix(ref, "docker://")) {
				errs = append(errs, fmt.Errorf("%s:%d: %s is not pinned by digest", filepath.Base(p), n, ref))
			}
		case !pinnedUseRe.MatchString(ref):
			errs = append(errs, fmt.Errorf("%s:%d: %s is not pinned to a commit SHA", filepath.Base(p), n, ref))
		}
	}
	return errors.Join(append(errs, sc.Err())...)
}

// FinalBase returns the external image the Dockerfile's final stage builds
// on, following stage names back to their origin; "" for scratch.
func FinalBase(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", fmt.Errorf("dockerfile: %w", err)
	}
	defer f.Close()
	origin := map[string]string{"scratch": ""} // stage name → external image
	final, seen := "", false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		mm := fromRe.FindStringSubmatch(sc.Text())
		if mm == nil {
			continue
		}
		ref := mm[1]
		if o, ok := origin[strings.ToLower(ref)]; ok {
			ref = o
		}
		if mm[2] != "" {
			origin[strings.ToLower(mm[2])] = ref
		}
		final, seen = ref, true
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if !seen {
		return "", fmt.Errorf("%s: no FROM", filepath.Base(p))
	}
	return final, nil
}

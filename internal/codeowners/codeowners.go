// Package codeowners reads a GitHub CODEOWNERS file and answers who owns a
// path, following GitHub's rules: the file is taken from .github/, the root
// or docs/ (first found); patterns are gitignore-style; the last matching
// pattern wins; and a pattern with no owners leaves a path unowned.
package codeowners

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PatterCJ/build-onion/internal/source"
)

// Locations GitHub reads, in its order of precedence.
var Locations = []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}

type rule struct {
	globs  []string
	owners []string
}

// File is a parsed CODEOWNERS file.
type File struct {
	Path  string
	rules []rule
}

// Load finds and parses the repository's CODEOWNERS file. It returns nil,
// nil when the repository has none.
func Load(root string) (*File, error) {
	for _, loc := range Locations {
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(loc)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		defer f.Close()
		out := &File{Path: loc}
		sc := bufio.NewScanner(f)
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if i := strings.Index(line, " #"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			fields := strings.Fields(line)
			if strings.HasPrefix(fields[0], "!") || strings.Contains(fields[0], "[") {
				return nil, fmt.Errorf("%s:%d: %q: negation and character ranges aren't supported by CODEOWNERS", loc, n, fields[0])
			}
			out.rules = append(out.rules, rule{globs: toGlobs(fields[0]), owners: fields[1:]})
		}
		return out, sc.Err()
	}
	return nil, nil
}

// toGlobs converts a CODEOWNERS pattern into build-onion globs. A pattern
// with a slash at the start or in the middle is anchored to the root;
// otherwise it matches at any depth. A trailing slash matches only a
// directory's contents; any other pattern matches a file or everything
// under a directory of that name, unless its last segment is a wildcard.
func toGlobs(p string) []string {
	dirOnly := strings.HasSuffix(p, "/")
	p = strings.TrimSuffix(p, "/")
	anchored := strings.HasPrefix(p, "/") || strings.Contains(p, "/")
	p = strings.TrimPrefix(p, "/")
	if !anchored {
		p = "**/" + p
	}
	if dirOnly {
		return []string{p + "/**"}
	}
	// A name can also be a directory, covering everything under it; a
	// wildcard last segment (docs/*) covers only that level.
	if last := p[strings.LastIndex(p, "/")+1:]; strings.ContainsAny(last, "*?") {
		return []string{p}
	}
	return []string{p, p + "/**"}
}

// Owners returns the owners of a path; empty means unowned.
func (f *File) Owners(p string) []string {
	var owners []string
	for _, r := range f.rules {
		for _, g := range r.globs {
			if source.Match(g, p) {
				owners = r.owners
				break
			}
		}
	}
	return owners
}

// Unowned lists the paths with no owner.
func (f *File) Unowned(paths []string) []string {
	var out []string
	for _, p := range paths {
		if len(f.Owners(p)) == 0 {
			out = append(out, p)
		}
	}
	return out
}

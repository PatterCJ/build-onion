package lockfile

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

func init() {
	register("pypi", func(base string) bool {
		return base == "requirements.txt" || (strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"))
	}, parseRequirements)
	register("pypi", func(base string) bool { return base == "uv.lock" }, parseUvLock)
	register("pypi", func(base string) bool { return base == "poetry.lock" }, parsePoetryLock)
}

// requirementRe matches a fully pinned requirement: name[extras]==version.
var requirementRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;\\]+)`)

// parseRequirements reads a hash-pinned requirements file, as produced by
// `uv export`, `pip-compile --generate-hashes` or `pip freeze`. Every
// requirement must be pinned with ==; anything looser isn't a lockfile.
func parseRequirements(data []byte, _ Sibling) (Result, error) {
	var res Result
	// Join backslash continuations so each requirement is one logical line.
	joined := strings.ReplaceAll(string(data), "\\\n", " ")
	sc := bufio.NewScanner(strings.NewReader(joined))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "--index-url"), strings.HasPrefix(line, "--extra-index-url"),
			strings.HasPrefix(line, "-i "), strings.HasPrefix(line, "--find-links"), strings.HasPrefix(line, "--only-binary"),
			strings.HasPrefix(line, "--no-binary"), strings.HasPrefix(line, "--prefer-binary"), strings.HasPrefix(line, "--require-hashes"):
			continue // index and install options, not packages
		case strings.HasPrefix(line, "-"):
			return Result{}, fmt.Errorf("line %d: %q: includes, constraints and editables aren't pinned packages", n, firstField(line))
		}
		m := requirementRe.FindStringSubmatch(line)
		if m == nil {
			return Result{}, fmt.Errorf("line %d: %q is not pinned with ==", n, firstField(line))
		}
		res.Packages = append(res.Packages, Package{Name: m[1], Version: m[3]})
	}
	return res, sc.Err()
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return s
}

// parseUvLock reads uv.lock. Packages whose source is the project itself
// (editable, virtual, directory) are local.
func parseUvLock(data []byte, _ Sibling) (Result, error) {
	var lock struct {
		Package []struct {
			Name    string         `toml:"name"`
			Version string         `toml:"version"`
			Source  map[string]any `toml:"source"`
		} `toml:"package"`
	}
	if _, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&lock); err != nil {
		return Result{}, err
	}
	var res Result
	for _, p := range lock.Package {
		if isLocalSource(p.Source, "editable", "virtual", "directory") {
			res.Local = append(res.Local, Local{Name: p.Name})
			continue
		}
		if p.Version == "" {
			return Result{}, fmt.Errorf("package %s has no version", p.Name)
		}
		res.Packages = append(res.Packages, Package{Name: p.Name, Version: p.Version})
	}
	return res, nil
}

// parsePoetryLock reads poetry.lock. Packages only in non-main groups are dev.
func parsePoetryLock(data []byte, _ Sibling) (Result, error) {
	var lock struct {
		Package []struct {
			Name     string         `toml:"name"`
			Version  string         `toml:"version"`
			Category string         `toml:"category"` // poetry < 1.5
			Groups   []string       `toml:"groups"`   // poetry >= 1.5
			Source   map[string]any `toml:"source"`
		} `toml:"package"`
	}
	if _, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&lock); err != nil {
		return Result{}, err
	}
	var res Result
	for _, p := range lock.Package {
		if t, _ := p.Source["type"].(string); t == "directory" {
			res.Local = append(res.Local, Local{Name: p.Name})
			continue
		}
		dev := p.Category == "dev"
		if len(p.Groups) > 0 {
			dev = true
			for _, g := range p.Groups {
				if g == "main" {
					dev = false
				}
			}
		}
		res.Packages = append(res.Packages, Package{Name: p.Name, Version: p.Version, Dev: dev})
	}
	return res, nil
}

func isLocalSource(src map[string]any, kinds ...string) bool {
	for _, k := range kinds {
		if _, ok := src[k]; ok {
			return true
		}
	}
	return false
}

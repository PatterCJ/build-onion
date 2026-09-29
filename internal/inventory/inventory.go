// Package inventory produces the bottom-up record of everything that went into
// a build: the source tree, the manifest, the builder, every locked dependency,
// and every output. It is signed as an in-toto predicate next to the SLSA
// provenance, and `onion peel` checks each layer of it in reverse.
package inventory

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/manifest"
)

const PredicateType = "https://github.com/PatterCJ/build-onion/inventory/v1"

type Inventory struct {
	Manifest     FileRef      `json:"manifest"`
	Source       Source       `json:"source"`
	Builder      Builder      `json:"builder"`
	Lockfiles    []FileRef    `json:"lockfiles"`
	Dependencies []Dependency `json:"dependencies"`
	// MainModules are the modules built from this source (not dependencies).
	MainModules []string `json:"mainModules,omitempty"`
	Build       Build    `json:"build"`
	Outputs     []Output `json:"outputs"`
	Run         Run      `json:"run"`
}

type FileRef struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type Source struct {
	Repository string `json:"repository"` // https://github.com/owner/repo
	Commit     string `json:"commit"`
	Tree       string `json:"tree"`
}

type Builder struct {
	Image string `json:"image"`
}

type Dependency struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Hash      string `json:"hash,omitempty"`
}

type Build struct {
	Fetch   string            `json:"fetch,omitempty"`
	Run     string            `json:"run"`
	Env     map[string]string `json:"env,omitempty"`
	Network string            `json:"network"`
}

type Output struct {
	Kind   string `json:"kind"` // file | oci-image
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type Run struct {
	InvocationURL string `json:"invocationUrl,omitempty"`
}

// Params are the facts the seal job knows from outside the source tree.
type Params struct {
	SourceDir     string // checkout of the commit being built
	ManifestPath  string // relative to SourceDir
	Repository    string
	Commit        string
	Tree          string
	FilesDir      string // directory holding the declared output files by basename
	ImageArchive  string // OCI layout tarball, when the manifest declares an image
	InvocationURL string
}

// Generate builds the inventory. It hashes everything itself; it never trusts
// digests reported by the build job.
func Generate(p Params) (*Inventory, *manifest.Manifest, error) {
	m, raw, err := manifest.Load(filepath.Join(p.SourceDir, p.ManifestPath))
	if err != nil {
		return nil, nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	inv := &Inventory{
		Manifest: FileRef{Path: p.ManifestPath, Digest: manifest.Digest(raw)},
		Source:   Source{Repository: p.Repository, Commit: p.Commit, Tree: p.Tree},
		Builder:  Builder{Image: m.Builder.Image},
		Build: Build{
			Fetch:   m.Dependencies.Fetch,
			Run:     m.Build.Run,
			Env:     m.Build.Env,
			Network: "none",
		},
		Run: Run{InvocationURL: p.InvocationURL},
	}
	for _, l := range m.Dependencies.Lockfiles {
		d, err := digest.File(filepath.Join(p.SourceDir, l))
		if err != nil {
			return nil, nil, fmt.Errorf("lockfile: %w", err)
		}
		inv.Lockfiles = append(inv.Lockfiles, FileRef{Path: l, Digest: d})
		if filepath.Base(l) == "go.sum" {
			deps, err := ParseGoSum(filepath.Join(p.SourceDir, l))
			if err != nil {
				return nil, nil, err
			}
			inv.Dependencies = append(inv.Dependencies, deps...)
			mod, err := GoModulePath(filepath.Join(p.SourceDir, filepath.Dir(l), "go.mod"))
			if err != nil {
				return nil, nil, err
			}
			inv.MainModules = append(inv.MainModules, mod)
		}
	}
	for _, f := range m.Outputs.Files {
		name := filepath.Base(f)
		d, err := digest.File(filepath.Join(p.FilesDir, name))
		if err != nil {
			return nil, nil, fmt.Errorf("output %s: %w", f, err)
		}
		inv.Outputs = append(inv.Outputs, Output{Kind: "file", Name: name, Digest: d})
	}
	if img := m.Outputs.Image; img != nil {
		if p.ImageArchive == "" {
			return nil, nil, errors.New("manifest declares an image but no image archive was given")
		}
		d, err := digest.OCIArchive(p.ImageArchive)
		if err != nil {
			return nil, nil, err
		}
		inv.Outputs = append(inv.Outputs, Output{Kind: "oci-image", Name: img.Name, Digest: d})
	}
	return inv, m, nil
}

// ParseGoSum lists every module version whose content (not just go.mod) is
// locked. A module linked into a binary must appear here.
func ParseGoSum(p string) ([]Dependency, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var deps []Dependency
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 3 || strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		deps = append(deps, Dependency{Ecosystem: "go", Name: fields[0], Version: fields[1], Hash: fields[2]})
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	return deps, sc.Err()
}

// GoModulePath reads the module directive from a go.mod file.
func GoModulePath(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if fields := strings.Fields(sc.Text()); len(fields) == 2 && fields[0] == "module" {
			return strings.Trim(fields[1], `"`), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s: no module directive", p)
}

// Subject returns the output with the given digest, if the inventory has one.
func (inv *Inventory) Subject(d string) (Output, bool) {
	for _, o := range inv.Outputs {
		if o.Digest == d {
			return o, true
		}
	}
	return Output{}, false
}

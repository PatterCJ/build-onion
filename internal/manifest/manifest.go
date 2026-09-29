// Package manifest defines build-onion.yml, the declaration that kicks off a
// build. Everything the pipeline is allowed to use must be named here; anything
// not declared is treated as an undeclared input and fails the build.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const APIVersion = "build-onion/v1"

// Manifest is the parsed build-onion.yml.
type Manifest struct {
	APIVersion   string       `yaml:"apiVersion" json:"apiVersion"`
	Name         string       `yaml:"name" json:"name"`
	Builder      Builder      `yaml:"builder" json:"builder"`
	Dependencies Dependencies `yaml:"dependencies" json:"dependencies"`
	Build        Build        `yaml:"build" json:"build"`
	Outputs      Outputs      `yaml:"outputs" json:"outputs"`
}

// Builder is the container image every fetch and build step runs in.
type Builder struct {
	// Image must be pinned by digest: registry/name[:tag]@sha256:<64 hex>.
	Image string `yaml:"image" json:"image"`
}

// Dependencies are fetched in a networked step, then handed read-only to the
// hermetic build step.
type Dependencies struct {
	// Lockfiles pin every third-party input. They are hashed into the inventory.
	Lockfiles []string `yaml:"lockfiles" json:"lockfiles"`
	// Fetch runs inside the builder image with network access.
	Fetch string `yaml:"fetch" json:"fetch"`
	// Cache is the path inside the builder that Fetch populates and Build reads.
	Cache string `yaml:"cache" json:"cache"`
}

// Build runs inside the builder image with no network.
type Build struct {
	Run string            `yaml:"run" json:"run"`
	Env map[string]string `yaml:"env" json:"env,omitempty"`
}

type Outputs struct {
	// Files are paths, relative to the repo root, produced by Build.
	Files []string `yaml:"files" json:"files,omitempty"`
	// Image is an optional OCI image assembled from the build outputs.
	Image *Image `yaml:"image" json:"image,omitempty"`
}

type Image struct {
	// Name is the registry repository the image is published to, without tag.
	Name       string `yaml:"name" json:"name"`
	Dockerfile string `yaml:"dockerfile" json:"dockerfile"`
	Context    string `yaml:"context" json:"context"`
}

// Load reads and strictly decodes a manifest; unknown keys are an error.
func Load(p string) (*Manifest, []byte, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, nil, err
	}
	m, err := Parse(raw)
	return m, raw, err
}

func Parse(raw []byte) (*Manifest, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if m.Build.Env == nil {
		m.Build.Env = map[string]string{}
	}
	return &m, nil
}

// Digest is the sha256 of the manifest bytes exactly as committed.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var (
	pinnedImageRe = regexp.MustCompile(`^[a-z0-9.\-/:_]+@sha256:[a-f0-9]{64}$`)
	imageNameRe   = regexp.MustCompile(`^[a-z0-9.\-]+(:[0-9]+)?/[a-z0-9._\-/]+$`)
	nameRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9._\-]*$`)
)

// Validate checks the manifest on its own, without touching the filesystem.
func (m *Manifest) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if m.APIVersion != APIVersion {
		add("apiVersion must be %q, got %q", APIVersion, m.APIVersion)
	}
	if !nameRe.MatchString(m.Name) {
		add("name %q must be lowercase alphanumeric with . _ -", m.Name)
	}
	if !IsPinnedImage(m.Builder.Image) {
		add("builder.image %q must be pinned by digest (…@sha256:<64 hex>)", m.Builder.Image)
	}
	if len(m.Dependencies.Lockfiles) == 0 {
		add("dependencies.lockfiles must name at least one lockfile")
	}
	for _, l := range m.Dependencies.Lockfiles {
		if err := checkRelPath(l); err != nil {
			add("dependencies.lockfiles: %v", err)
		}
	}
	if (m.Dependencies.Fetch == "") != (m.Dependencies.Cache == "") {
		add("dependencies.fetch and dependencies.cache must be set together")
	}
	if m.Dependencies.Cache != "" && !path.IsAbs(m.Dependencies.Cache) {
		add("dependencies.cache %q must be an absolute path inside the builder", m.Dependencies.Cache)
	}
	if strings.TrimSpace(m.Build.Run) == "" {
		add("build.run is required")
	}
	if len(m.Outputs.Files) == 0 && m.Outputs.Image == nil {
		add("outputs must declare at least one file or an image")
	}
	seen := map[string]bool{}
	for _, f := range m.Outputs.Files {
		if err := checkRelPath(f); err != nil {
			add("outputs.files: %v", err)
		}
		if seen[path.Base(f)] {
			add("outputs.files: duplicate basename %q (subjects are named by basename)", path.Base(f))
		}
		seen[path.Base(f)] = true
	}
	if img := m.Outputs.Image; img != nil {
		if !imageNameRe.MatchString(img.Name) || strings.ContainsAny(img.Name, "@") {
			add("outputs.image.name %q must be registry/repository with no tag or digest", img.Name)
		}
		if err := checkRelPath(img.Dockerfile); err != nil {
			add("outputs.image.dockerfile: %v", err)
		}
		if img.Context == "" {
			img.Context = "."
		}
		if err := checkRelPath(img.Context); err != nil {
			add("outputs.image.context: %v", err)
		}
	}
	return errors.Join(errs...)
}

// IsPinnedImage reports whether ref names an image by immutable digest.
func IsPinnedImage(ref string) bool { return pinnedImageRe.MatchString(ref) }

func checkRelPath(p string) error {
	switch {
	case p == "":
		return errors.New("empty path")
	case path.IsAbs(p):
		return fmt.Errorf("%q must be relative to the repo root", p)
	case p != "." && path.Clean(p) != p:
		return fmt.Errorf("%q must be a clean path", p)
	case p == ".." || strings.HasPrefix(p, "../"):
		return fmt.Errorf("%q escapes the repo root", p)
	}
	return nil
}

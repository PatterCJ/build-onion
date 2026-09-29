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
	// Env configures the fetch step only, e.g. pointing a package manager at
	// an artifact store. Proxy variables are set by build-onion and can't be
	// overridden here.
	Env map[string]string `yaml:"env" json:"env,omitempty"`
	// Egress is the only network the fetch step may reach. When set, fetch
	// runs on a network with no route out except a filtering proxy, and any
	// attempt to reach another host fails the build. When empty, fetch has
	// unrestricted network and verification reports that as degraded.
	Egress []EgressRule `yaml:"egress" json:"egress,omitempty"`
}

// EgressRule allows fetch to reach one host (or a subdomain wildcard) on one port.
type EgressRule struct {
	// Host is a DNS name, or *.example.com for any subdomain of example.com.
	Host string `yaml:"host" json:"host"`
	// Port defaults to 443.
	Port int `yaml:"port" json:"port,omitempty"`
	// Private permits the host to resolve to a private-network address
	// (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7), as an internal
	// artifact store would. Loopback, link-local and metadata addresses are
	// never reachable.
	Private bool `yaml:"private" json:"private,omitempty"`
}

// EffectivePort is the rule's port, defaulting to 443.
func (r EgressRule) EffectivePort() int {
	if r.Port == 0 {
		return 443
	}
	return r.Port
}

// Build runs inside the builder image with no network.
type Build struct {
	Run string            `yaml:"run" json:"run"`
	Env map[string]string `yaml:"env" json:"env,omitempty"`
	// Scratch lists paths, besides outputs, that fetch or build may create in
	// the source tree (node_modules, build/). Any other new file fails the build.
	Scratch []string `yaml:"scratch" json:"scratch,omitempty"`
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
	if m.Dependencies.Env == nil {
		m.Dependencies.Env = map[string]string{}
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
	envNameRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	// A DNS name with at least two labels, optionally led by "*." for
	// subdomains. Digits-only final labels (IP addresses) are excluded.
	egressHostRe = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// proxyEnv are set by build-onion when fetch runs behind the egress proxy.
var proxyEnv = map[string]bool{"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "ALL_PROXY": true}

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
	if err := m.ValidateEgress(); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(m.Build.Run) == "" {
		add("build.run is required")
	}
	for _, p := range m.Build.Scratch {
		if err := checkRelPath(p); err != nil || p == "." {
			add("build.scratch: %q must be a subpath of the repo", p)
		}
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

// ValidateEgress checks the fetch environment and egress allow-list.
func (m *Manifest) ValidateEgress() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	for k := range m.Dependencies.Env {
		if !envNameRe.MatchString(k) {
			add("dependencies.env: %q is not an environment variable name", k)
		} else if proxyEnv[strings.ToUpper(k)] {
			add("dependencies.env: %s is set by build-onion's egress proxy and can't be overridden", k)
		}
	}
	if len(m.Dependencies.Egress) > 0 && m.Dependencies.Fetch == "" {
		add("dependencies.egress applies to the fetch step; set dependencies.fetch")
	}
	seenRule := map[string]bool{}
	for _, r := range m.Dependencies.Egress {
		if !egressHostRe.MatchString(r.Host) {
			add("dependencies.egress: host %q must be a lowercase DNS name or *.domain (no IP addresses, schemes or ports)", r.Host)
		}
		if r.Port < 0 || r.Port > 65535 {
			add("dependencies.egress: %s port %d out of range", r.Host, r.Port)
		}
		key := fmt.Sprintf("%s:%d", r.Host, r.EffectivePort())
		if seenRule[key] {
			add("dependencies.egress: %s listed twice", key)
		}
		seenRule[key] = true
	}
	return errors.Join(errs...)
}

// Writable lists every path the build may create: declared outputs plus
// scratch. Source verification treats any other new file as tampering.
func (m *Manifest) Writable() []string {
	return append(append([]string{}, m.Outputs.Files...), m.Build.Scratch...)
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

// Package policy is the organization-level configuration: which refs and
// events may produce releasable artifacts, and which paths are
// build-sensitive. It is deliberately separate from the per-repo build
// manifest — a platform team can pin one policy across every repo by wrapping
// the reusable workflow, and a repo cannot quietly relax its own gate.
package policy

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const APIVersion = "build-onion/policy/v1"

type Policy struct {
	APIVersion string  `yaml:"apiVersion" json:"apiVersion"`
	Release    Release `yaml:"release" json:"release"`
	// SensitivePaths are added to the built-in list (workflows, manifest,
	// lockfiles, Dockerfile, the policy itself). Globs; "dir/**" matches a subtree.
	SensitivePaths []string `yaml:"sensitivePaths" json:"sensitivePaths,omitempty"`
	// SensitivePresets add named sets of build-system files (see Presets).
	SensitivePresets []string `yaml:"sensitivePresets" json:"sensitivePresets,omitempty"`
	// RequireBuildInputs refuses to build a manifest that doesn't narrow
	// build.inputs, so no build can read the whole repository by default.
	RequireBuildInputs bool `yaml:"requireBuildInputs" json:"requireBuildInputs,omitempty"`
	// BlockOpaqueInputs refuses to build a change that adds or modifies a
	// binary file the build can read.
	BlockOpaqueInputs bool `yaml:"blockOpaqueInputs" json:"blockOpaqueInputs,omitempty"`
}

// Release says when a build may be sealed. Anything else still builds and is
// checked, but is never signed or published.
type Release struct {
	Refs   []string `yaml:"refs" json:"refs"`
	Events []string `yaml:"events" json:"events"`
}

// Default applies when no policy file is given.
func Default() *Policy {
	return &Policy{
		APIVersion: APIVersion,
		Release: Release{
			Refs:   []string{"refs/heads/main", "refs/tags/v*"},
			Events: []string{"push", "workflow_dispatch", "release"},
		},
	}
}

// Load reads a policy file; an empty path yields Default().
func Load(p string) (*Policy, []byte, error) {
	if p == "" {
		return Default(), nil, nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	pol := Default()
	pol.Release = Release{}
	if err := dec.Decode(pol); err != nil {
		return nil, nil, fmt.Errorf("decode policy: %w", err)
	}
	def := Default()
	if len(pol.Release.Refs) == 0 {
		pol.Release.Refs = def.Release.Refs
	}
	if len(pol.Release.Events) == 0 {
		pol.Release.Events = def.Release.Events
	}
	return pol, raw, pol.Validate()
}

// Events that run code from an untrusted fork with the target repo's
// privileges. build-onion never runs under them.
var forbiddenEvents = map[string]bool{"pull_request_target": true, "workflow_run": true}

func (p *Policy) Validate() error {
	var errs []error
	for _, name := range p.SensitivePresets {
		if _, ok := presets[name]; !ok {
			errs = append(errs, fmt.Errorf("sensitivePresets: unknown preset %q (known: %s)", name, strings.Join(PresetNames(), ", ")))
		}
	}
	if p.APIVersion != APIVersion {
		errs = append(errs, fmt.Errorf("apiVersion must be %q", APIVersion))
	}
	for _, e := range p.Release.Events {
		if forbiddenEvents[e] {
			errs = append(errs, fmt.Errorf("release.events: %s can never produce a release", e))
		}
	}
	for _, r := range p.Release.Refs {
		if !strings.HasPrefix(r, "refs/") {
			errs = append(errs, fmt.Errorf("release.refs: %q must be a full ref (refs/heads/…, refs/tags/…)", r))
		} else if _, err := path.Match(r, ""); err != nil {
			errs = append(errs, fmt.Errorf("release.refs: %q: %v", r, err))
		}
	}
	return errors.Join(errs...)
}

// Forbidden reports whether the pipeline must refuse to run at all.
func Forbidden(event string) bool { return forbiddenEvents[event] }

// Releasable reports whether a build for this event and ref may be sealed.
func (p *Policy) Releasable(event, ref string) (bool, string) {
	if !contains(p.Release.Events, event) {
		return false, fmt.Sprintf("event %q is not a release event (%s)", event, strings.Join(p.Release.Events, ", "))
	}
	for _, pat := range p.Release.Refs {
		if ok, _ := path.Match(pat, ref); ok {
			return true, fmt.Sprintf("%s on %s matches %s", event, ref, pat)
		}
	}
	return false, fmt.Sprintf("ref %q is not a release ref (%s)", ref, strings.Join(p.Release.Refs, ", "))
}

//go:embed presets.yaml
var presetsYAML []byte

var presets = func() map[string][]string {
	var m map[string][]string
	if err := yaml.Unmarshal(presetsYAML, &m); err != nil {
		panic("policy: presets.yaml: " + err.Error())
	}
	return m
}()

// PresetNames lists the available sensitivePresets.
func PresetNames() []string {
	names := make([]string, 0, len(presets))
	for n := range presets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// PresetPatterns expands the policy's presets into path globs.
func (p *Policy) PresetPatterns() []string {
	var out []string
	for _, n := range p.SensitivePresets {
		out = append(out, presets[n]...)
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

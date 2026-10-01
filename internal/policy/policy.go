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

	"github.com/PatterCJ/build-onion/internal/tagsig"
)

const APIVersion = "build-onion/policy/v1"

// DefaultPath is where the gate looks for a policy when none is named.
const DefaultPath = ".build-onion/policy.yml"

// Modes. In report mode the gate and the fetch step record what they would
// block instead of blocking, so a team can adopt a policy and see its gaps
// before enforcing it. peel grades what would have been blocked as findings.
const (
	ModeEnforce = "enforce"
	ModeReport  = "report"
)

type Policy struct {
	APIVersion string `yaml:"apiVersion" json:"apiVersion"`
	// Mode is enforce (the default) or report.
	Mode    string  `yaml:"mode" json:"mode,omitempty"`
	Release Release `yaml:"release" json:"release"`
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
	// Repository lists protections the repository must have before a build
	// is allowed. All are read without admin rights.
	Repository Repository `yaml:"repository" json:"repository,omitempty"`
}

// Repository requirements, checked by the gate.
type Repository struct {
	// The release branch's active rules (rulesets) must require pull
	// requests, at least MinApprovals approvals, code-owner review, and
	// block force pushes, as set.
	RequirePullRequest     bool `yaml:"requirePullRequest" json:"requirePullRequest,omitempty"`
	MinApprovals           int  `yaml:"minApprovals" json:"minApprovals,omitempty"`
	RequireCodeOwnerReview bool `yaml:"requireCodeOwnerReview" json:"requireCodeOwnerReview,omitempty"`
	BlockForcePush         bool `yaml:"blockForcePush" json:"blockForcePush,omitempty"`
	// RequireCodeOwners: CODEOWNERS must name an owner for every
	// build-configuration file.
	RequireCodeOwners bool `yaml:"requireCodeOwners" json:"requireCodeOwners,omitempty"`
	// TagsFromDefaultBranch: a tag release must point at a commit already on
	// the default branch.
	TagsFromDefaultBranch bool `yaml:"tagsFromDefaultBranch" json:"tagsFromDefaultBranch,omitempty"`
}

// Any reports whether any requirement is set.
func (r Repository) Any() bool {
	return r.NeedsRules() || r.RequireCodeOwners || r.TagsFromDefaultBranch
}

// NeedsRules reports whether the branch's rules must be read.
func (r Repository) NeedsRules() bool {
	return r.RequirePullRequest || r.MinApprovals > 0 || r.RequireCodeOwnerReview || r.BlockForcePush
}

// Release says when a build may be sealed. Anything else still builds and is
// checked, but is never signed or published.
type Release struct {
	Refs   []string `yaml:"refs" json:"refs"`
	Events []string `yaml:"events" json:"events"`
	// TagSigners, when set, are the only keys (authorized_keys form) whose
	// signed tags may release: an unsigned tag, or one signed by any other
	// key, is blocked.
	TagSigners []string `yaml:"tagSigners" json:"tagSigners,omitempty"`
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
	if p.Mode != "" && p.Mode != ModeEnforce && p.Mode != ModeReport {
		errs = append(errs, fmt.Errorf("mode %q: want %s or %s", p.Mode, ModeEnforce, ModeReport))
	}
	if p.Repository.MinApprovals < 0 {
		errs = append(errs, errors.New("repository.minApprovals can't be negative"))
	}
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
	if _, err := tagsig.Keys(p.Release.TagSigners); err != nil {
		errs = append(errs, fmt.Errorf("release.tagSigners: %w", err))
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

// Report reports whether the policy records rather than blocks.
func (p *Policy) Report() bool { return p.Mode == ModeReport }

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

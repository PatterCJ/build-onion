// Package gate decides, before anything is built, whether this commit may be
// built at all and whether its result may be released: the event and ref
// policy, and which build-sensitive files it touched.
package gate

import (
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/policy"
)

// Params are the facts the CI platform knows about this run.
type Params struct {
	SourceDir    string
	ManifestPath string
	PolicyPath   string // as given to the pipeline; itself build-sensitive
	Repository   string
	Base         string // previous build point (e.g. the push's "before"); empty if unknown
	Context      Context
	Fork         bool // the commit comes from a fork
}

// Context is what the CI platform says triggered this run.
type Context struct {
	Platform string `json:"platform"` // github-actions, aws-codebuild, local, …
	Event    string `json:"event"`
	Ref      string `json:"ref"`
	Actor    string `json:"actor,omitempty"`
	RunURL   string `json:"runUrl,omitempty"`
}

// Verdict is recorded in the inventory.
type Verdict struct {
	Releasable bool   `json:"releasable"`
	Reason     string `json:"reason"`
	// Blocked means the gate stops the pipeline outright.
	Blocked         bool     `json:"blocked"`
	BlockedBy       []string `json:"blockedBy,omitempty"`
	Base            string   `json:"base,omitempty"`
	ChangedFiles    int      `json:"changedFiles"`
	ChangeKnown     bool     `json:"changeKnown"`
	SensitiveChange []string `json:"sensitiveChange,omitempty"`
	PolicyDigest    string   `json:"policyDigest,omitempty"`
	Context         Context  `json:"context"`
}

// Evaluate runs the gate.
func Evaluate(p Params, pol *policy.Policy, m *manifest.Manifest) (*Verdict, error) {
	v := &Verdict{Base: p.Base, Context: p.Context}
	if policy.Forbidden(p.Context.Event) {
		v.Blocked = true
		v.BlockedBy = append(v.BlockedBy, fmt.Sprintf("event %s runs untrusted code with repository privileges; build-onion refuses it", p.Context.Event))
		v.Reason = "forbidden event"
		return v, nil
	}
	if pol.RequireBuildInputs && len(m.Build.Inputs) == 0 {
		v.Blocked = true
		v.BlockedBy = append(v.BlockedBy, "policy requires build.inputs: declare which files the build may read")
		v.Reason = "build inputs not declared"
		return v, nil
	}
	v.Releasable, v.Reason = pol.Releasable(p.Context.Event, p.Context.Ref)
	if v.Releasable && p.Fork {
		v.Releasable, v.Reason = false, "commit comes from a fork"
	}

	changed, known, err := changedFiles(p.SourceDir, p.Base)
	if err != nil {
		return nil, err
	}
	v.ChangeKnown, v.ChangedFiles = known, len(changed)
	patterns := SensitivePatterns(pol, m, p.ManifestPath, p.PolicyPath)
	for _, f := range changed {
		for _, pat := range patterns {
			if policy.MatchGlob(pat, f) {
				v.SensitiveChange = append(v.SensitiveChange, f)
				break
			}
		}
	}

	return v, nil
}

// SensitivePatterns are paths whose change alters how the build runs rather
// than what it builds.
func SensitivePatterns(pol *policy.Policy, m *manifest.Manifest, manifestPath, policyPath string) []string {
	pats := []string{".github/**", manifestPath}
	if policyPath != "" {
		pats = append(pats, policyPath)
	}
	pats = append(pats, m.Dependencies.Lockfiles...)
	if m.Outputs.Image != nil {
		pats = append(pats, m.Outputs.Image.Dockerfile)
	}
	return append(pats, pol.SensitivePaths...)
}

// changedFiles lists paths that differ between base and HEAD. An empty or
// all-zero base (first push of a branch) or a base the checkout does not have
// means the change is unknown, which is reported rather than guessed.
func changedFiles(dir, base string) ([]string, bool, error) {
	if base == "" || strings.Trim(base, "0") == "" {
		return nil, false, nil
	}
	if err := exec.Command("git", "-C", dir, "cat-file", "-e", base+"^{commit}").Run(); err != nil {
		return nil, false, nil
	}
	out, err := exec.Command("git", "-C", dir, "diff", "--name-only", "--no-renames", "-z", base, "HEAD").Output()
	if err != nil {
		return nil, false, fmt.Errorf("git diff %s: %w", base, err)
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	sort.Strings(files)
	return files, true, nil
}

// Package gate decides, before anything is built, whether this commit may be
// built at all and whether its result may be released: the event and ref
// policy, which build-sensitive files it touched, and the verdicts of any
// gate plugins (for example a model-based commit risk score).
package gate

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/plugin"
	"github.com/PatterCJ/build-onion/internal/policy"
	"github.com/PatterCJ/build-onion/internal/source"
)

// Params are the facts the CI platform knows about this run.
type Params struct {
	SourceDir    string
	ManifestPath string
	PolicyPath   string // as given to the pipeline; itself build-sensitive
	Repository   string
	Base         string // previous build point (e.g. the push's "before"); empty if unknown
	Context      plugin.Context
	Fork         bool // the commit comes from a fork
}

// Verdict is recorded in the inventory.
type Verdict struct {
	Releasable bool   `json:"releasable"`
	Reason     string `json:"reason"`
	// Blocked means the gate stops the pipeline outright.
	Blocked         bool            `json:"blocked"`
	BlockedBy       []string        `json:"blockedBy,omitempty"`
	Base            string          `json:"base,omitempty"`
	ChangedFiles    int             `json:"changedFiles"`
	ChangeKnown     bool            `json:"changeKnown"`
	SensitiveChange []string        `json:"sensitiveChange,omitempty"`
	Plugins         []plugin.Record `json:"plugins,omitempty"`
	PolicyDigest    string          `json:"policyDigest,omitempty"`
}

// Evaluate runs the gate. snap is the source snapshot the build will use.
func Evaluate(ctx context.Context, p Params, pol *policy.Policy, m *manifest.Manifest, snap *source.Snapshot, run plugin.Runner) (*Verdict, error) {
	v := &Verdict{Base: p.Base}
	if policy.Forbidden(p.Context.Event) {
		v.Blocked = true
		v.BlockedBy = append(v.BlockedBy, fmt.Sprintf("event %s runs untrusted code with repository privileges; build-onion refuses it", p.Context.Event))
		v.Reason = "forbidden event"
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

	req := plugin.Request{
		Source:  plugin.Source{Repository: p.Repository, Commit: snap.Commit, Tree: snap.Tree, SnapshotDigest: snap.Digest},
		Change:  &plugin.Change{Base: p.Base, Files: changed, Sensitive: v.SensitiveChange},
		Context: p.Context,
	}
	if !known {
		req.Change = nil
	}
	for _, spec := range pol.Plugins {
		if spec.Hook != plugin.HookGate {
			continue
		}
		rec := run.Run(ctx, spec, p.SourceDir, req)
		v.Plugins = append(v.Plugins, rec)
		if rec.Blocking {
			v.Blocked = true
			v.BlockedBy = append(v.BlockedBy, fmt.Sprintf("plugin %s: %s: %s", rec.Name, rec.Verdict, rec.Summary))
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

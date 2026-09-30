// Package gate decides, before anything is built, whether this commit may be
// built at all and whether its result may be released: the event and ref
// policy, and which build-sensitive files it touched.
package gate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/PatterCJ/build-onion/internal/manifest"
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
	Context      Context
	Fork         bool // the commit comes from a fork
	// BranchRules is GitHub's "rules for a branch" response (JSON) for the
	// branch being released, read with a read-only token. Needed only when
	// the policy has repository requirements.
	BranchRules []byte
	// DefaultBranch is the repository's default branch, for tag releases.
	DefaultBranch string
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
	// OpaqueChange lists changed files that are binary by content; the
	// subset the build can read is OpaqueInputs.
	OpaqueChange []string `json:"opaqueChange,omitempty"`
	OpaqueInputs []string `json:"opaqueInputs,omitempty"`
	// Repository is the result of the policy's repository requirements.
	Repository   *RepoCheck `json:"repository,omitempty"`
	PolicyDigest string     `json:"policyDigest,omitempty"`
	Context      Context    `json:"context"`
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
	always := m.AlwaysInputs(p.ManifestPath)
	for _, f := range changed {
		if matchAny(patterns, f) {
			v.SensitiveChange = append(v.SensitiveChange, f)
		}
		opaque, err := IsOpaque(filepath.Join(p.SourceDir, filepath.FromSlash(f)))
		if err != nil {
			return nil, err
		}
		if opaque {
			v.OpaqueChange = append(v.OpaqueChange, f)
			if len(m.Build.Inputs) == 0 || matchAny(m.Build.Inputs, f) || matchAny(always, f) {
				v.OpaqueInputs = append(v.OpaqueInputs, f)
			}
		}
	}
	if v.Repository = checkRepository(p, pol, m); v.Repository != nil && len(v.Repository.Problems) > 0 {
		v.Blocked = true
		for _, prob := range v.Repository.Problems {
			v.BlockedBy = append(v.BlockedBy, "repository: "+prob)
		}
	}
	if pol.BlockOpaqueInputs && len(v.OpaqueInputs) > 0 {
		v.Blocked = true
		v.BlockedBy = append(v.BlockedBy, fmt.Sprintf("policy blocks binary changes the build can read: %s", strings.Join(v.OpaqueInputs, ", ")))
	}
	return v, nil
}

// SensitivePatterns are paths whose change alters how the build runs rather
// than what it builds. The built-in set comes from the repo's own
// configuration (workflows, CODEOWNERS, manifest, policy, lockfiles,
// Dockerfile); the repo adds its build scripts in build.sensitive, and a
// policy can add paths and presets.
func SensitivePatterns(pol *policy.Policy, m *manifest.Manifest, manifestPath, policyPath string) []string {
	pats := []string{".github/**", "CODEOWNERS", "docs/CODEOWNERS", manifestPath}
	if policyPath != "" {
		pats = append(pats, policyPath)
	}
	pats = append(pats, m.Dependencies.Lockfiles...)
	if m.Outputs.Image != nil {
		pats = append(pats, m.Outputs.Image.Dockerfile)
	}
	pats = append(pats, m.Build.Sensitive...)
	pats = append(pats, pol.SensitivePaths...)
	return append(pats, pol.PresetPatterns()...)
}

func matchAny(patterns []string, p string) bool {
	for _, pat := range patterns {
		if source.Match(pat, p) {
			return true
		}
	}
	return false
}

// IsOpaque reports whether a file is binary by its content: a NUL byte or
// invalid UTF-8 in its first 8 KiB. A file that no longer exists (deleted in
// the change) is not opaque.
func IsOpaque(p string) (bool, error) {
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return false, err
	}
	buf := make([]byte, 8<<10)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false, err
	}
	b := buf[:n]
	if bytes.IndexByte(b, 0) >= 0 {
		return true, nil
	}
	if n == len(buf) {
		// The read may have split a multi-byte character at the end.
		for i := 0; i < utf8.UTFMax-1 && len(b) > 0 && !utf8.Valid(b); i++ {
			b = b[:len(b)-1]
		}
	}
	return !utf8.Valid(b), nil
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

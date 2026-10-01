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

	"github.com/PatterCJ/build-onion/internal/lockfile"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/policy"
	"github.com/PatterCJ/build-onion/internal/source"
	"github.com/PatterCJ/build-onion/internal/tagsig"
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
	// TagSigner is the allowed key that signed the release tag, when the
	// policy requires signed tags.
	TagSigner string `json:"tagSigner,omitempty"`
	// Mode is the policy's mode. In report mode, what would have blocked the
	// build is in WouldBlock and Blocked stays false.
	Mode       string   `json:"mode,omitempty"`
	WouldBlock []string `json:"wouldBlock,omitempty"`
	Context    Context  `json:"context"`
}

// Evaluate runs the gate.
func Evaluate(p Params, pol *policy.Policy, m *manifest.Manifest) (*Verdict, error) {
	v := &Verdict{Base: p.Base, Context: p.Context, Mode: pol.Mode}
	// Refused in every mode: report mode never runs under these events.
	if policy.Forbidden(p.Context.Event) {
		v.Blocked = true
		v.BlockedBy = append(v.BlockedBy, fmt.Sprintf("event %s runs untrusted code with repository privileges; build-onion refuses it", p.Context.Event))
		v.Reason = "forbidden event"
		return v, nil
	}
	if err := evaluate(v, p, pol, m); err != nil {
		return nil, err
	}
	if pol.Report() && v.Blocked {
		v.WouldBlock, v.Blocked, v.BlockedBy = v.BlockedBy, false, nil
	}
	return v, nil
}

func evaluate(v *Verdict, p Params, pol *policy.Policy, m *manifest.Manifest) error {
	if pol.RequireBuildInputs && len(m.Build.Inputs) == 0 {
		v.Blocked = true
		v.BlockedBy = append(v.BlockedBy, "policy requires build.inputs: declare which files the build may read")
		if !pol.Report() {
			v.Reason = "build inputs not declared"
			return nil
		}
	}
	v.Releasable, v.Reason = pol.Releasable(p.Context.Event, p.Context.Ref)
	if v.Releasable && p.Fork {
		v.Releasable, v.Reason = false, "commit comes from a fork"
	}

	if ref, ok := strings.CutPrefix(p.Context.Ref, "refs/tags/"); ok && len(pol.Release.TagSigners) > 0 {
		signer, err := checkTagSignature(p.SourceDir, ref, pol.Release.TagSigners)
		if err != nil {
			v.Blocked = true
			v.BlockedBy = append(v.BlockedBy, fmt.Sprintf("release tag %s: %v", ref, err))
		}
		v.TagSigner = signer
	}

	changed, known, err := changedFiles(p.SourceDir, p.Base)
	if err != nil {
		return err
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
			return err
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
	// The fetch step turns install scripts off itself (enforce mode); a
	// command that explicitly turns them back on would win, so it is
	// refused. In report mode nothing is turned off, and what the policy
	// would refuse is recorded.
	if pol.BlockInstallScripts && !pol.Report() && lockfile.ScriptsReenabled(m.Dependencies.Fetch, m.Dependencies.Env) {
		v.Blocked = true
		v.BlockedBy = append(v.BlockedBy, "policy blocks dependency install scripts, but the fetch step turns them back on (an ignore-scripts=false flag or setting); remove it")
	}
	if pol.BlockInstallScripts && pol.Report() && !lockfile.ScriptsDisabled(m.Dependencies.Fetch, m.Dependencies.Env) {
		scripts, err := installScripts(p.SourceDir, m)
		if err != nil {
			return err
		}
		if len(scripts) > 0 {
			v.Blocked = true
			v.BlockedBy = append(v.BlockedBy, fmt.Sprintf("policy blocks dependency install scripts during fetch: %s run code when installed; fetch with --ignore-scripts or set npm_config_ignore_scripts=true in dependencies.env",
				strings.Join(scripts, ", ")))
		}
	}
	if pol.BlockOpaqueInputs && len(v.OpaqueInputs) > 0 {
		v.Blocked = true
		v.BlockedBy = append(v.BlockedBy, fmt.Sprintf("policy blocks binary changes the build can read: %s", strings.Join(v.OpaqueInputs, ", ")))
	}
	return nil
}

// SensitivePatterns are paths whose change alters how the build runs rather
// than what it builds. The built-in set comes from the repo's own
// configuration (workflows, CODEOWNERS, manifest, policy, lockfiles,
// Dockerfile); the repo adds its build scripts in build.sensitive, and a
// policy can add paths and presets.
func SensitivePatterns(pol *policy.Policy, m *manifest.Manifest, manifestPath, policyPath string) []string {
	pats := []string{".github/**", ".gitlab-ci.yml", ".gitlab/**", "CODEOWNERS", "docs/CODEOWNERS", manifestPath}
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

// checkTagSignature requires the release tag to be signed by an allowed key
// and to point at the commit being built.
func checkTagSignature(dir, tag string, signers []string) (string, error) {
	raw, err := exec.Command("git", "-C", dir, "cat-file", "tag", "refs/tags/"+tag).Output()
	if err != nil {
		return "", errors.New("not an annotated tag in this checkout; release tags must be signed (git tag -s)")
	}
	keys, err := tagsig.Keys(signers)
	if err != nil {
		return "", err
	}
	t, err := tagsig.Verify(raw, keys)
	if err != nil {
		return "", err
	}
	head, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	if t.Name != tag || t.Object != strings.TrimSpace(string(head)) {
		return "", fmt.Errorf("signed tag names %s at %s, but this build is %s at %s", t.Name, t.Object, tag, strings.TrimSpace(string(head)))
	}
	return t.Key, nil
}

// installScripts lists the locked packages that run install scripts.
func installScripts(dir string, m *manifest.Manifest) ([]string, error) {
	var out []string
	for _, l := range m.Dependencies.Lockfiles {
		full := filepath.Join(dir, filepath.FromSlash(l))
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("lockfile: %w", err)
		}
		sibling := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(filepath.Dir(full), name)) }
		res, _, err := lockfile.Parse(l, data, sibling)
		if err != nil {
			return nil, err
		}
		out = append(out, lockfile.InstallScripts(res.Packages)...)
	}
	return out, nil
}

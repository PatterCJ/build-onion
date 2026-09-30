package gate

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/policy"
	"github.com/PatterCJ/build-onion/internal/source"
)

type fixture struct {
	dir  string
	base string
	m    *manifest.Manifest
}

func setup(t *testing.T) *fixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitc := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(p, body string) {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644)
	}
	write("main.go", "package main\n")
	write("go.sum", "a v1 h1:x\n")
	gitc("init", "-q")
	gitc("add", ".")
	gitc("commit", "-qm", "base")
	base := gitc("rev-parse", "HEAD")
	write("main.go", "package main // changed\n")
	write("go.sum", "a v2 h1:y\n")
	write(".github/workflows/ci.yml", "on: push\n")
	gitc("add", ".")
	gitc("commit", "-qm", "head")
	m := &manifest.Manifest{Dependencies: manifest.Dependencies{Lockfiles: []string{"go.sum"}}}
	return &fixture{dir: dir, base: base, m: m}
}

func (f *fixture) eval(t *testing.T, event, ref, base string, pol *policy.Policy) *Verdict {
	t.Helper()
	v, err := Evaluate(Params{
		SourceDir: f.dir, ManifestPath: "build-onion.yml", Base: base,
		Context: Context{Platform: "test", Event: event, Ref: ref},
	}, pol, f.m)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReleasable(t *testing.T) {
	f := setup(t)
	pol := policy.Default()
	cases := []struct {
		event, ref string
		want       bool
	}{
		{"push", "refs/heads/main", true},
		{"push", "refs/tags/v1.2.0", true},
		{"push", "refs/heads/feature/x", false},
		{"pull_request", "refs/pull/7/merge", false},
		{"schedule", "refs/heads/main", false},
	}
	for _, tc := range cases {
		v := f.eval(t, tc.event, tc.ref, "", pol)
		if v.Releasable != tc.want || v.Blocked {
			t.Errorf("%s %s: releasable=%v blocked=%v (%s)", tc.event, tc.ref, v.Releasable, v.Blocked, v.Reason)
		}
	}
}

func TestForbiddenEventBlocks(t *testing.T) {
	f := setup(t)
	v := f.eval(t, "pull_request_target", "refs/heads/main", "", policy.Default())
	if !v.Blocked || v.Releasable {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestSensitiveChanges(t *testing.T) {
	f := setup(t)
	v := f.eval(t, "push", "refs/heads/main", f.base, policy.Default())
	if !v.ChangeKnown || v.ChangedFiles != 3 {
		t.Fatalf("verdict = %+v", v)
	}
	if got := strings.Join(v.SensitiveChange, ","); got != ".github/workflows/ci.yml,go.sum" {
		t.Errorf("sensitive = %s", got)
	}
	// First push of a branch: no base. Unknown, not "nothing changed".
	if v := f.eval(t, "push", "refs/heads/main", strings.Repeat("0", 40), policy.Default()); v.ChangeKnown {
		t.Errorf("zero base treated as known: %+v", v)
	}
}

func TestPolicyLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yml")
	os.WriteFile(p, []byte(`apiVersion: build-onion/policy/v1
release:
  refs: [refs/tags/v*]
sensitivePaths: [scripts/**]
`), 0o644)
	pol, _, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := pol.Releasable("push", "refs/heads/main"); ok {
		t.Error("main releasable under a tags-only policy")
	}
	if len(pol.Release.Events) == 0 {
		t.Error("events default not applied")
	}
	os.WriteFile(p, []byte("apiVersion: build-onion/policy/v1\nplugins: []\n"), 0o644)
	if _, _, err := policy.Load(p); err == nil {
		t.Error("unknown policy key accepted")
	}
	os.WriteFile(p, []byte("apiVersion: build-onion/policy/v1\nrelease:\n  events: [pull_request_target]\n"), 0o644)
	if _, _, err := policy.Load(p); err == nil {
		t.Error("pull_request_target accepted as a release event")
	}
}

func TestRequireBuildInputs(t *testing.T) {
	f := setup(t)
	pol := policy.Default()
	pol.RequireBuildInputs = true
	if v := f.eval(t, "push", "refs/heads/main", "", pol); !v.Blocked {
		t.Fatal("manifest without build.inputs built under a policy that requires them")
	}
	f.m.Build.Inputs = []string{"*.go"}
	if v := f.eval(t, "push", "refs/heads/main", "", pol); v.Blocked {
		t.Fatalf("declared inputs still blocked: %+v", v)
	}
}

func TestIsOpaque(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		body   []byte
		opaque bool
	}{
		"source.go":   {[]byte("package main\n\nfunc main() {}\n"), false},
		"unicode.md":  {[]byte("héllo — ✓ 日本語\n"), false},
		"empty":       {nil, false},
		"payload.xz":  {[]byte{0xfd, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x04}, true},
		"latin1.txt":  {[]byte{'c', 'a', 'f', 0xe9, '\n'}, true},
		"image.png":   {[]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00}, true},
		"boundary.md": {append(bytes.Repeat([]byte("a"), 8<<10-1), []byte("é tail")...), false}, // é split at 8 KiB
	}
	for name, c := range cases {
		p := filepath.Join(dir, name)
		os.WriteFile(p, c.body, 0o644)
		got, err := IsOpaque(p)
		if err != nil || got != c.opaque {
			t.Errorf("%s: opaque=%v err=%v, want %v", name, got, err, c.opaque)
		}
	}
	if got, err := IsOpaque(filepath.Join(dir, "deleted")); got || err != nil {
		t.Errorf("deleted file: %v %v", got, err)
	}
}

func TestSensitiveSources(t *testing.T) {
	f := setup(t)
	// setup's head commit changed main.go, go.sum and .github/workflows/ci.yml.
	pol := policy.Default()
	v := f.eval(t, "push", "refs/heads/main", f.base, pol)
	if got := strings.Join(v.SensitiveChange, ","); got != ".github/workflows/ci.yml,go.sum" {
		t.Fatalf("built-in only: %s", got)
	}
	// The repo declares its own build scripts.
	f.m.Build.Sensitive = []string{"*.go"}
	v = f.eval(t, "push", "refs/heads/main", f.base, pol)
	if !strings.Contains(strings.Join(v.SensitiveChange, ","), "main.go") {
		t.Fatalf("build.sensitive ignored: %v", v.SensitiveChange)
	}
}

func TestOpaqueInputs(t *testing.T) {
	f := setup(t)
	gitc := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", f.dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	base := strings.TrimSpace(func() string {
		out, _ := exec.Command("git", "-C", f.dir, "rev-parse", "HEAD").Output()
		return string(out)
	}())
	os.MkdirAll(filepath.Join(f.dir, "tests/files"), 0o755)
	os.WriteFile(filepath.Join(f.dir, "tests/files/bad-3-corrupt.xz"), []byte{0xfd, '7', 'z', 0x00, 0x01}, 0o644)
	os.WriteFile(filepath.Join(f.dir, "logo.png"), []byte{0x89, 'P', 'N', 'G', 0x00}, 0o644)
	gitc("add", ".")
	gitc("commit", "-qm", "fixtures")

	f.m.Build.Inputs = []string{"*.go", "*.png"}
	pol := policy.Default()
	v := f.eval(t, "push", "refs/heads/main", base, pol)
	if strings.Join(v.OpaqueChange, ",") != "logo.png,tests/files/bad-3-corrupt.xz" || strings.Join(v.OpaqueInputs, ",") != "logo.png" {
		t.Fatalf("opaque %v, in inputs %v", v.OpaqueChange, v.OpaqueInputs)
	}
	if v.Blocked {
		t.Fatal("blocked without blockOpaqueInputs")
	}
	pol.BlockOpaqueInputs = true
	if v := f.eval(t, "push", "refs/heads/main", base, pol); !v.Blocked {
		t.Fatal("binary input change not blocked under blockOpaqueInputs")
	}
	// The test fixture isn't a build input, so it alone doesn't block.
	f.m.Build.Inputs = []string{"*.go"}
	if v := f.eval(t, "push", "refs/heads/main", base, pol); v.Blocked {
		t.Fatalf("fixture outside build.inputs blocked: %v", v.BlockedBy)
	}
}

func TestPresets(t *testing.T) {
	names := policy.PresetNames()
	if len(names) < 10 {
		t.Fatalf("presets = %v", names)
	}
	p := filepath.Join(t.TempDir(), "policy.yml")
	os.WriteFile(p, []byte("apiVersion: build-onion/policy/v1\nsensitivePresets: [autotools, nope]\n"), 0o644)
	if _, _, err := policy.Load(p); err == nil || !strings.Contains(err.Error(), `unknown preset "nope"`) {
		t.Fatalf("unknown preset: %v", err)
	}
	pol := policy.Default()
	pol.SensitivePresets = []string{"autotools"}
	found := false
	for _, pat := range pol.PresetPatterns() {
		if source.Match(pat, "m4/build-to-host.m4") {
			found = true
		}
	}
	if !found {
		t.Error("autotools preset doesn't cover m4 macros")
	}
}

// A "rules for a branch" response for a branch with a pull-request ruleset.
const protectedRules = `[
  {"type":"deletion","ruleset_source_type":"Repository","ruleset_id":1},
  {"type":"non_fast_forward","ruleset_source_type":"Repository","ruleset_id":1},
  {"type":"pull_request","parameters":{"required_approving_review_count":1,"require_code_owner_review":true,"dismiss_stale_reviews_on_push":true},"ruleset_source_type":"Repository","ruleset_id":1}
]`

func strictRepo() *policy.Policy {
	pol := policy.Default()
	pol.Repository = policy.Repository{RequirePullRequest: true, MinApprovals: 1, RequireCodeOwnerReview: true,
		BlockForcePush: true, RequireCodeOwners: true, TagsFromDefaultBranch: true}
	return pol
}

func (f *fixture) evalRepo(t *testing.T, ref string, rules string, pol *policy.Policy) *Verdict {
	t.Helper()
	p := Params{SourceDir: f.dir, ManifestPath: "build-onion.yml", DefaultBranch: "main",
		Context: Context{Platform: "test", Event: "push", Ref: ref}}
	if rules != "" {
		p.BranchRules = []byte(rules)
	}
	v, err := Evaluate(p, pol, f.m)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (f *fixture) git(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", f.dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestRepositoryRequirements(t *testing.T) {
	f := setup(t)
	os.MkdirAll(filepath.Join(f.dir, ".github"), 0o755)
	os.WriteFile(filepath.Join(f.dir, ".github/CODEOWNERS"), []byte("* @acme/devs\n"), 0o644)
	f.git(t, "add", ".")
	f.git(t, "commit", "-qm", "owners")
	f.git(t, "update-ref", "refs/remotes/origin/main", "HEAD")

	v := f.evalRepo(t, "refs/heads/main", protectedRules, strictRepo())
	if v.Blocked || v.Repository == nil || v.Repository.Approvals != 1 || !v.Repository.CodeOwnerReview || v.Repository.OwnedSensitive == 0 {
		t.Fatalf("protected repo blocked: %+v %v", v.Repository, v.BlockedBy)
	}

	cases := map[string]struct {
		rules string
		mut   func(*policy.Policy)
		want  string
	}{
		"no rules supplied":    {"", nil, "were not provided"},
		"no pull requests":     {`[{"type":"non_fast_forward"}]`, nil, "doesn't require pull requests"},
		"too few approvals":    {protectedRules, func(p *policy.Policy) { p.Repository.MinApprovals = 2 }, "requires 1 approval(s); policy requires 2"},
		"force push allowed":   {`[{"type":"pull_request","parameters":{"required_approving_review_count":1,"require_code_owner_review":true}}]`, nil, "allows force pushes"},
		"no code-owner review": {`[{"type":"non_fast_forward"},{"type":"pull_request","parameters":{"required_approving_review_count":1}}]`, nil, "doesn't require code-owner review"},
		"unreadable rules":     {`{"not":"a list"}`, nil, "unreadable"},
	}
	for name, c := range cases {
		pol := strictRepo()
		if c.mut != nil {
			c.mut(pol)
		}
		v := f.evalRepo(t, "refs/heads/main", c.rules, pol)
		if !v.Blocked || !strings.Contains(strings.Join(v.BlockedBy, "; "), c.want) {
			t.Errorf("%s: blocked=%v %v", name, v.Blocked, v.BlockedBy)
		}
	}

	// A pull request build is held to the default branch's rules.
	if v := f.evalRepo(t, "refs/pull/7/merge", protectedRules, strictRepo()); v.Blocked || v.Repository.Branch != "main" {
		t.Errorf("pull request: branch %q, blocked by %v", v.Repository.Branch, v.BlockedBy)
	}

	// No requirements, no check.
	if v := f.evalRepo(t, "refs/heads/main", "", policy.Default()); v.Repository != nil || v.Blocked {
		t.Errorf("default policy checked the repository: %+v", v.Repository)
	}
}

func TestCodeOwnersCoverage(t *testing.T) {
	f := setup(t)
	pol := policy.Default()
	pol.Repository.RequireCodeOwners = true
	if v := f.evalRepo(t, "refs/heads/main", "", pol); !strings.Contains(strings.Join(v.BlockedBy, ";"), "no CODEOWNERS file") {
		t.Fatalf("missing CODEOWNERS not caught: %v", v.BlockedBy)
	}
	// Owns only go.sum: the workflow file (build configuration) is unowned.
	os.WriteFile(filepath.Join(f.dir, "CODEOWNERS"), []byte("go.sum @acme/build\n"), 0o644)
	f.git(t, "add", ".")
	f.git(t, "commit", "-qm", "partial owners")
	v := f.evalRepo(t, "refs/heads/main", "", pol)
	if !v.Blocked || len(v.Repository.Unowned) == 0 || !strings.Contains(strings.Join(v.Repository.Unowned, ","), ".github/workflows/ci.yml") {
		t.Fatalf("unowned build file not caught: %+v", v.Repository)
	}
}

func TestTagsFromDefaultBranch(t *testing.T) {
	f := setup(t)
	pol := policy.Default()
	pol.Repository.TagsFromDefaultBranch = true
	f.git(t, "update-ref", "refs/remotes/origin/main", "HEAD")
	if v := f.evalRepo(t, "refs/tags/v1.0.0", "", pol); v.Blocked || v.Repository.TagOnDefault == nil || !*v.Repository.TagOnDefault {
		t.Fatalf("tag on main blocked: %+v %v", v.Repository, v.BlockedBy)
	}
	// A commit that never went through main, then tagged.
	f.git(t, "commit", "-q", "--allow-empty", "-m", "unreviewed")
	if v := f.evalRepo(t, "refs/tags/v1.0.1", "", pol); !v.Blocked || !strings.Contains(strings.Join(v.BlockedBy, ";"), "not on main") {
		t.Fatalf("unreviewed tag not blocked: %v", v.BlockedBy)
	}
	// Branch pushes aren't subject to the tag rule.
	if v := f.evalRepo(t, "refs/heads/main", "", pol); v.Blocked {
		t.Fatalf("branch push blocked by the tag rule: %v", v.BlockedBy)
	}
}

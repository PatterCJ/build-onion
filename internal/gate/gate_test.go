package gate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/plugin"
	"github.com/PatterCJ/build-onion/internal/policy"
	"github.com/PatterCJ/build-onion/internal/source"
)

type fixture struct {
	dir        string
	base, head string
	m          *manifest.Manifest
	snap       *source.Snapshot
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
	snap, err := source.Take(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := &manifest.Manifest{Dependencies: manifest.Dependencies{Lockfiles: []string{"go.sum"}}}
	return &fixture{dir: dir, base: base, head: snap.Commit, m: m, snap: snap}
}

func (f *fixture) eval(t *testing.T, event, ref, base string, pol *policy.Policy) *Verdict {
	t.Helper()
	v, err := Evaluate(context.Background(), Params{
		SourceDir: f.dir, ManifestPath: "build-onion.yml", Base: base,
		Context: plugin.Context{Platform: "test", Event: event, Ref: ref},
	}, pol, f.m, f.snap, plugin.Runner{AllowCommand: true})
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

func TestPluginVerdicts(t *testing.T) {
	f := setup(t)
	p := filepath.Join(t.TempDir(), "risk.sh")
	// Fails whenever the change touches a sensitive path.
	os.WriteFile(p, []byte(`#!/bin/sh
if grep -q '"sensitive":\["' ; then v=fail; else v=pass; fi
echo "{\"apiVersion\":\"build-onion/plugin/v1\",\"verdict\":\"$v\",\"summary\":\"sensitive change\"}"
`), 0o755)
	for _, mode := range []string{plugin.Advisory, plugin.Enforce} {
		pol := policy.Default()
		pol.Plugins = []plugin.Spec{{Name: "risk", Hook: plugin.HookGate, Mode: mode, Command: []string{p}}}
		v := f.eval(t, "push", "refs/heads/main", f.base, pol)
		if len(v.Plugins) != 1 || v.Plugins[0].Verdict != plugin.Fail {
			t.Fatalf("%s: plugins = %+v", mode, v.Plugins)
		}
		if v.Blocked != (mode == plugin.Enforce) {
			t.Errorf("%s: blocked = %v", mode, v.Blocked)
		}
	}
}

func TestPolicyLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.yml")
	os.WriteFile(p, []byte(`apiVersion: build-onion/policy/v1
release:
  refs: [refs/tags/v*]
plugins:
  - name: jev
    hook: gate
    mode: advisory
    image: ghcr.io/acme/jev@sha256:`+strings.Repeat("b", 64)+`
    network: true
    secrets: [TYPESAFE_API_KEY]
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
	os.WriteFile(p, []byte("apiVersion: build-onion/policy/v1\nrelease:\n  events: [pull_request_target]\n"), 0o644)
	if _, _, err := policy.Load(p); err == nil {
		t.Error("pull_request_target accepted as a release event")
	}
}

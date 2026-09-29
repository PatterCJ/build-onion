package inventory

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/source"
)

const manifestYAML = `apiVersion: build-onion/v1
name: widget
builder:
  image: docker.io/library/golang:1.27.1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
dependencies:
  lockfiles: [go.sum]
  fetch: go mod download
  cache: /go/pkg/mod
build:
  run: go build -o dist/widget .
outputs:
  files: [dist/widget]
`

const goSum = `gopkg.in/yaml.v3 v3.0.1 h1:aaa=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:bbb=
github.com/only/gomod v1.0.0/go.mod h1:ccc=
github.com/a/b v1.2.0 h1:ddd=
`

// gitSource commits a minimal Go project and returns its dir and snapshot.
func gitSource(t *testing.T) (string, *source.Snapshot) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "build-onion.yml"), []byte(manifestYAML), 0o644)
	os.WriteFile(filepath.Join(src, "go.sum"), []byte(goSum), 0o644)
	os.WriteFile(filepath.Join(src, "go.mod"), []byte("module github.com/acme/widget\n\ngo 1.27\n"), 0o644)
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"commit", "-qm", "init"}} {
		cmd := exec.Command("git", append([]string{"-C", src, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	snap, err := source.Take(src)
	if err != nil {
		t.Fatal(err)
	}
	return src, snap
}

func params(src string, snap *source.Snapshot, files string) Params {
	return Params{
		SourceDir: src, ManifestPath: "build-onion.yml",
		Repository: "https://github.com/acme/widget", Commit: snap.Commit, Tree: snap.Tree,
		FilesDir: files, Snapshot: snap,
	}
}

func TestGenerate(t *testing.T) {
	src, snap := gitSource(t)
	files := t.TempDir()
	os.WriteFile(filepath.Join(files, "widget"), []byte("binary"), 0o755)

	inv, _, err := Generate(params(src, snap, files))
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.Outputs; len(got) != 1 || got[0].Digest != digest.Bytes([]byte("binary")) || got[0].Kind != "file" {
		t.Errorf("outputs = %+v", got)
	}
	if inv.Manifest.Digest != digest.Bytes([]byte(manifestYAML)) {
		t.Error("manifest digest is not over the committed bytes")
	}
	if inv.Build.Network != "none" {
		t.Errorf("network = %q", inv.Build.Network)
	}
	var names []string
	for _, d := range inv.Dependencies {
		names = append(names, d.Name+"@"+d.Version)
	}
	// go.mod-only entries are not linked code and must not be listed.
	if strings.Join(names, ",") != "github.com/a/b@v1.2.0,gopkg.in/yaml.v3@v3.0.1" {
		t.Errorf("dependencies = %v", names)
	}
	if inv.Source.Snapshot != snap.Digest || inv.Source.Files != 3 {
		t.Errorf("source = %+v", inv.Source)
	}
	if len(inv.MainModules) != 1 || inv.MainModules[0] != "github.com/acme/widget" {
		t.Errorf("main modules = %v", inv.MainModules)
	}
}

func TestGenerateMissingOutput(t *testing.T) {
	src, snap := gitSource(t)
	_, _, err := Generate(params(src, snap, t.TempDir()))
	if err == nil || !strings.Contains(err.Error(), "output dist/widget") {
		t.Fatalf("err = %v", err)
	}
}

func TestGenerateRejectsSourceDrift(t *testing.T) {
	src, snap := gitSource(t)
	files := t.TempDir()
	os.WriteFile(filepath.Join(files, "widget"), []byte("binary"), 0o755)

	// Checkout changed after the snapshot.
	os.WriteFile(filepath.Join(src, "go.sum"), []byte("tampered\n"), 0o644)
	if _, _, err := Generate(params(src, snap, files)); err == nil || !strings.Contains(err.Error(), "modified: go.sum") {
		t.Errorf("drifted checkout: err = %v", err)
	}
	os.WriteFile(filepath.Join(src, "go.sum"), []byte(goSum), 0o644)

	// Snapshot of a different commit.
	p := params(src, snap, files)
	p.Commit = strings.Repeat("f", 40)
	if _, _, err := Generate(p); err == nil || !strings.Contains(err.Error(), "snapshot is of") {
		t.Errorf("wrong commit: err = %v", err)
	}

	// Snapshot whose file list was edited to drop a file.
	edited := *snap
	edited.Files = snap.Files[1:]
	p = params(src, &edited, files)
	if _, _, err := Generate(p); err == nil || !strings.Contains(err.Error(), "does not match its file list") {
		t.Errorf("edited snapshot: err = %v", err)
	}
}

func TestPipelineRecords(t *testing.T) {
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	wf := filepath.Join(t.TempDir(), "wf.yml")
	os.WriteFile(wf, []byte("steps:\n  - uses: actions/checkout@abc # v7\n  - run: x\n  - uses: \"./local\"\n"), 0o644)
	actions, err := WorkflowActions(wf)
	must(err)
	if strings.Join(actions, ",") != "actions/checkout@abc,./local" {
		t.Fatalf("actions = %v", actions)
	}
	must(WriteBuildOnionRecord(filepath.Join(dir, "onion.json"), BuildOnionRef{Repository: "PatterCJ/build-onion", Commit: "c1"}))
	must(WriteWorkflowRecord(filepath.Join(dir, "wf.json"), Workflow{Role: "caller", Actions: actions}))
	must(WriteJobRecord(filepath.Join(dir, "job-build.json"), Job{Name: "build", Runner: "ubuntu24 1", Tools: []Tool{{"syft", "1"}, {"docker", "28"}}}))

	pl, err := ReadPipeline(dir, "github-actions")
	must(err)
	if pl.BuildOnion.Commit != "c1" || len(pl.Workflows) != 1 || len(pl.Jobs) != 1 || pl.Jobs[0].Tools[0].Name != "docker" {
		t.Fatalf("pipeline = %+v", pl)
	}

	// Without a build-onion record the builder is unnamed: refuse.
	os.Remove(filepath.Join(dir, "onion.json"))
	if _, err := ReadPipeline(dir, "x"); err == nil {
		t.Error("pipeline without builder commit accepted")
	}
	// Unknown shapes are rejected, not ignored.
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"kind":"job","extra":1}`), 0o644)
	if _, err := ReadPipeline(dir, "x"); err == nil {
		t.Error("record with unknown field accepted")
	}
}

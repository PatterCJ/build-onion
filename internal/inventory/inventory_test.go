package inventory

import (
	"archive/tar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/egress"
	"github.com/PatterCJ/build-onion/internal/manifest"
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
	if len(inv.Local) != 1 || inv.Local[0].Name != "github.com/acme/widget" || inv.Local[0].Ecosystem != "golang" {
		t.Errorf("local = %+v", inv.Local)
	}
	if inv.Lockfiles[0].Ecosystem != "golang" || inv.Dependencies[0].Ecosystem != "golang" {
		t.Errorf("ecosystem not recorded: %+v %+v", inv.Lockfiles[0], inv.Dependencies[0])
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

	// A second line may record build-onion again, but only at the same commit.
	must(WriteBuildOnionRecord(filepath.Join(dir, "onion-verify.json"), BuildOnionRef{Repository: "PatterCJ/build-onion", Commit: "c1"}))
	if _, err := ReadPipeline(dir, "x"); err != nil {
		t.Errorf("same-commit records rejected: %v", err)
	}
	must(WriteBuildOnionRecord(filepath.Join(dir, "onion-verify.json"), BuildOnionRef{Repository: "PatterCJ/build-onion", Commit: "c2"}))
	if _, err := ReadPipeline(dir, "x"); err == nil {
		t.Error("lines at different build-onion commits accepted")
	}
	os.Remove(filepath.Join(dir, "onion-verify.json"))

	// Without a build-onion record the builder is unnamed: refuse.
	os.Remove(filepath.Join(dir, "onion.json"))
	if _, err := ReadPipeline(dir, "x"); err == nil {
		t.Error("pipeline without builder commit accepted")
	}
	// The caller's directory may only hold scan records.
	callerDir := t.TempDir()
	must(WriteScanRecord(filepath.Join(callerDir, "scan.json"), Scan{Name: "sca", Tool: "t", Stage: StagePreBuild, Status: ScanCompleted,
		StartedAt: "2026-09-29T20:00:00Z", FinishedAt: "2026-09-29T20:00:01Z", Subject: ScanSubject{Kind: "source", Digest: digest.Bytes([]byte("s"))}}))
	if scans, err := ReadScans(callerDir); err != nil || len(scans) != 1 {
		t.Fatalf("scans = %v, %v", scans, err)
	}
	must(WriteJobRecord(filepath.Join(callerDir, "job-forged.json"), Job{Name: "build", Runner: "claims to be build-onion"}))
	if _, err := ReadScans(callerDir); err == nil || !strings.Contains(err.Error(), "only scan records") {
		t.Errorf("forged job record from a caller accepted: %v", err)
	}
	os.Remove(filepath.Join(callerDir, "job-forged.json"))
	must(WriteBuildOnionRecord(filepath.Join(callerDir, "onion.json"), BuildOnionRef{Commit: "c1"}))
	if _, err := ReadScans(callerDir); err == nil {
		t.Error("forged build-onion record from a caller accepted")
	}

	// Unknown shapes are rejected, not ignored.
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"kind":"job","extra":1}`), 0o644)
	if _, err := ReadPipeline(dir, "x"); err == nil {
		t.Error("record with unknown field accepted")
	}
}

func TestGenerateEgress(t *testing.T) {
	src, snap := gitSource(t)
	files := t.TempDir()
	os.WriteFile(filepath.Join(files, "widget"), []byte("binary"), 0o755)

	// No allow-list in the manifest: fetch was unrestricted, and it says so.
	inv, _, err := Generate(params(src, snap, files))
	if err != nil || inv.Egress == nil || inv.Egress.Mode != egress.ModeUnrestricted {
		t.Fatalf("unrestricted: %+v, %v", inv.Egress, err)
	}

	// A record claiming a restricted fetch doesn't match this manifest.
	p := params(src, snap, files)
	p.Egress = &egress.Record{Mode: egress.ModeAllowList, Rules: []manifest.EgressRule{{Host: "proxy.golang.org"}}, Summary: &egress.Summary{}}
	if _, _, err := Generate(p); err == nil {
		t.Error("allow-list record accepted for a manifest without one")
	}
}

func TestEgressRecordCheck(t *testing.T) {
	m := &manifest.Manifest{Dependencies: manifest.Dependencies{Fetch: "go mod download",
		Egress: []manifest.EgressRule{{Host: "proxy.golang.org"}, {Host: "sum.golang.org"}}}}
	good := func() *egress.Record {
		return &egress.Record{Mode: egress.ModeAllowList, Rules: m.Dependencies.Egress, Summary: &egress.Summary{
			Connections: []egress.Connection{{Host: "proxy.golang.org", Port: 443, Allowed: true, Count: 3}}}}
	}
	if err := good().Check(m); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*egress.Record){
		"ran unrestricted": func(r *egress.Record) { r.Mode = egress.ModeUnrestricted },
		"different rules":  func(r *egress.Record) { r.Rules = []manifest.EgressRule{{Host: "proxy.golang.org"}} },
		"no log":           func(r *egress.Record) { r.Summary = nil },
		"a denial": func(r *egress.Record) {
			r.Summary.Connections = append(r.Summary.Connections, egress.Connection{Host: "evil.example.net", Port: 443})
			r.Summary.Denied = 1
		},
		"allowed but unmatched": func(r *egress.Record) {
			r.Summary.Connections = append(r.Summary.Connections, egress.Connection{Host: "other.example.net", Port: 443, Allowed: true})
		},
	}
	for name, mutate := range cases {
		r := good()
		mutate(r)
		if r.Check(m) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestScanRecordValidation(t *testing.T) {
	ok := Scan{Name: "sca", Tool: "blackduck", Stage: StagePostBuild, Status: ScanCompleted,
		StartedAt: "2026-09-29T20:05:00Z", FinishedAt: "2026-09-29T20:31:00Z",
		Subject: ScanSubject{Kind: "artifact", Digest: digest.Bytes([]byte("x"))}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Scan){
		"bad stage":             func(s *Scan) { s.Stage = "whenever" },
		"finished before start": func(s *Scan) { s.FinishedAt = "2026-09-29T20:00:00Z" },
		"not a time":            func(s *Scan) { s.StartedAt = "yesterday" },
		"pre-build artifact":    func(s *Scan) { s.Stage = StagePreBuild },
		"bad subject kind":      func(s *Scan) { s.Subject.Kind = "repo" },
		"bad subject digest":    func(s *Scan) { s.Subject.Digest = "abc" },
		"bad report digest":     func(s *Scan) { s.Report = &Report{Digest: "md5:1"} },
		"missing tool":          func(s *Scan) { s.Tool = "" },
		"missing status":        func(s *Scan) { s.Status = "" },
		"unknown status":        func(s *Scan) { s.Status = "clean" },
		"incomplete, no reason": func(s *Scan) { s.Status = ScanIncomplete },
	}
	for name, mutate := range cases {
		s := ok
		mutate(&s)
		if s.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	partial := ok
	partial.Status, partial.Coverage = ScanIncomplete, "2 archives could not be extracted"
	if err := partial.Validate(); err != nil {
		t.Errorf("incomplete with coverage: %v", err)
	}
}

func TestScansMustBeAboutThisBuild(t *testing.T) {
	src, snap := gitSource(t)
	files := t.TempDir()
	os.WriteFile(filepath.Join(files, "widget"), []byte("binary"), 0o755)
	scan := func(kind, d string) Scan {
		return Scan{Name: "s", Tool: "t", Stage: StagePostBuild, Status: ScanCompleted, StartedAt: "2026-09-29T20:00:00Z", FinishedAt: "2026-09-29T20:01:00Z",
			Subject: ScanSubject{Kind: kind, Digest: d}}
	}
	for _, tc := range []struct {
		name string
		s    Scan
		ok   bool
	}{
		{"source snapshot", scan("source", snap.Digest), true},
		{"built artifact", scan("artifact", digest.Bytes([]byte("binary"))), true},
		{"another commit's source", scan("source", digest.Bytes([]byte("old"))), false},
		{"another build's artifact", scan("artifact", digest.Bytes([]byte("other"))), false},
	} {
		p := params(src, snap, files)
		p.Pipeline.Scans = []Scan{tc.s}
		_, _, err := Generate(p)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}

func TestGenerateImageLayers(t *testing.T) {
	src, snap := gitSource(t)
	pin := "@sha256:" + strings.Repeat("d", 64)
	base := "gcr.io/distroless/static" + pin
	os.WriteFile(filepath.Join(src, "build-onion.yml"), []byte(manifestYAML+"  image:\n    name: ghcr.io/acme/widget\n    dockerfile: Dockerfile\n"), 0o644)
	os.WriteFile(filepath.Join(src, "Dockerfile"), []byte("FROM golang:1.27"+pin+" AS build\nFROM "+base+"\nCOPY dist/widget /widget\n"), 0o644)
	for _, args := range [][]string{{"add", "."}, {"commit", "-qm", "image"}} {
		exec.Command("git", append([]string{"-C", src, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...).Run()
	}
	snap, err := source.Take(src)
	if err != nil {
		t.Fatal(err)
	}
	files := t.TempDir()
	os.WriteFile(filepath.Join(files, "widget"), []byte("binary"), 0o755)

	baseLayer, appLayer := "sha256:"+strings.Repeat("1", 64), "sha256:"+strings.Repeat("2", 64)
	archive := func(layers ...string) string {
		config := `{"rootfs":{"type":"layers","diff_ids":["` + strings.Join(layers, `","`) + `"]}}`
		manifest := `{"config":{"digest":"` + digest.Bytes([]byte(config)) + `"}}`
		p := filepath.Join(t.TempDir(), "image.tar")
		f, _ := os.Create(p)
		tw := tar.NewWriter(f)
		for name, body := range map[string]string{
			"index.json": `{"manifests":[{"digest":"` + digest.Bytes([]byte(manifest)) + `"}]}`,
			"blobs/sha256/" + digest.Hex(digest.Bytes([]byte(manifest))): manifest,
			"blobs/sha256/" + digest.Hex(digest.Bytes([]byte(config))):   config,
		} {
			tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))})
			tw.Write([]byte(body))
		}
		tw.Close()
		f.Close()
		return p
	}
	resolved := ""
	params := func(img string) Params {
		p := params(src, snap, files)
		p.ImageArchive = img
		p.ResolveBase = func(ref string) ([]string, error) { resolved = ref; return []string{baseLayer}, nil }
		return p
	}

	inv, _, err := Generate(params(archive(baseLayer, appLayer)))
	if err != nil {
		t.Fatal(err)
	}
	ib := inv.Build.Image
	if resolved != base || ib.FinalBase != base || len(ib.BaseLayers) != 1 || len(ib.Layers) != 2 {
		t.Fatalf("image build = %+v (resolved %q)", ib, resolved)
	}
	// An image that doesn't start with its base's layers wasn't built FROM it.
	if _, _, err := Generate(params(archive(appLayer))); err == nil || !strings.Contains(err.Error(), "does not start with the layers") {
		t.Fatalf("wrong base accepted: %v", err)
	}
}

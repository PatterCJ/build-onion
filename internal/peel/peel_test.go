package peel

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/inventory"
)

const (
	repo         = "acme/widget"
	repoURL      = "https://github.com/acme/widget"
	commit       = "1111111111111111111111111111111111111111"
	signer       = "PatterCJ/build-onion/.github/workflows/onion-build.yml"
	runURL       = "https://github.com/acme/widget/actions/runs/42/attempts/1"
	builderImage = "docker.io/library/golang:1.27.1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

var artifactDigest = digest.Bytes([]byte("widget binary"))

// fakeVerifier returns canned results keyed by candidate source, standing in
// for Sigstore (which attest's own tests cover against a real bundle).
type fakeVerifier map[string]*attest.Verified

func (f fakeVerifier) Verify(c attest.Candidate, d string) (*attest.Verified, error) {
	v, ok := f[c.Source]
	if !ok {
		return nil, errors.New("signature invalid")
	}
	cp := *v
	return &cp, nil
}

type world struct {
	prov map[string]any
	inv  inventory.Inventory
	sbom map[string]any
	cert certificate.Summary
}

func newWorld() *world {
	return &world{
		prov: map[string]any{
			"buildDefinition": map[string]any{
				"buildType":          GitHubBuildType,
				"externalParameters": map[string]any{"workflow": map[string]any{"ref": "refs/heads/main", "repository": repoURL, "path": ".github/workflows/release.yml"}},
				"internalParameters": map[string]any{"github": map[string]any{"event_name": "push", "runner_environment": "github-hosted"}},
				"resolvedDependencies": []any{map[string]any{
					"uri": "git+" + repoURL + "@refs/heads/main", "digest": map[string]any{"gitCommit": commit},
				}},
			},
			"runDetails": map[string]any{
				"builder":  map[string]any{"id": "https://github.com/" + signer + "@refs/tags/v1.0.0"},
				"metadata": map[string]any{"invocationId": runURL},
			},
		},
		inv: inventory.Inventory{
			Source:       inventory.Source{Repository: repoURL, Commit: commit, Tree: "t"},
			Builder:      inventory.Builder{Image: builderImage},
			Lockfiles:    []inventory.FileRef{{Path: "go.sum", Digest: digest.Bytes(nil)}},
			Dependencies: []inventory.Dependency{{Ecosystem: "go", Name: "gopkg.in/yaml.v3", Version: "v3.0.1"}},
			MainModules:  []string{"github.com/acme/widget"},
			Build:        inventory.Build{Run: "go build", Network: "none"},
			Outputs:      []inventory.Output{{Kind: "file", Name: "widget", Digest: artifactDigest}},
			Run:          inventory.Run{InvocationURL: runURL},
		},
		sbom: map[string]any{"components": []any{
			map[string]any{"name": "github.com/acme/widget", "purl": "pkg:golang/github.com/acme/widget@v0.0.0-2026"},
			map[string]any{"name": "stdlib", "purl": "pkg:golang/stdlib@go1.27.1"},
			map[string]any{"name": "gopkg.in/yaml.v3", "purl": "pkg:golang/gopkg.in/yaml.v3@v3.0.1?type=module"},
		}},
		cert: certificate.Summary{
			Extensions: certificate.Extensions{
				SourceRepositoryURI:    repoURL,
				SourceRepositoryDigest: commit,
				RunInvocationURI:       runURL,
			},
		},
	}
}

func (w *world) input(t *testing.T) Input {
	t.Helper()
	fv := fakeVerifier{}
	var cands []attest.Candidate
	for pt, pred := range map[string]any{SLSAProvenanceV1: w.prov, CycloneDX: w.sbom, inventory.PredicateType: w.inv} {
		raw, err := json.Marshal(pred)
		if err != nil {
			t.Fatal(err)
		}
		fv[pt] = &attest.Verified{Statement: attest.Statement{PredicateType: pt, Predicate: raw}, Certificate: w.cert}
		cands = append(cands, attest.Candidate{Source: pt})
	}
	return Input{
		Artifact:   "widget",
		Digest:     artifactDigest,
		Claim:      Claim{Repository: repo, Commit: commit},
		Signer:     attest.Identity{SignerWorkflow: signer},
		Verifier:   fv,
		Candidates: cands,
	}
}

func failures(r *Report) []string {
	var out []string
	for _, res := range r.Results {
		if res.Status == Fail {
			out = append(out, res.Layer+"/"+res.Check+": "+res.Detail)
		}
	}
	return out
}

func TestPeelHappyPath(t *testing.T) {
	r := Run(newWorld().input(t))
	if !r.OK() {
		t.Fatalf("expected verified, failures: %v", failures(r))
	}
}

func TestPeelDetectsTampering(t *testing.T) {
	cases := map[string]struct {
		world func(*world)
		input func(*Input)
		want  string
	}{
		"claimed commit differs": {
			input: func(in *Input) { in.Claim.Commit = strings.Repeat("2", 40) },
			want:  "provenance/source commit matches claim",
		},
		"signed for another repo": {
			world: func(w *world) { w.cert.SourceRepositoryURI = "https://github.com/evil/widget" },
			want:  "signed for claimed repo",
		},
		"self-hosted runner": {
			world: func(w *world) {
				w.prov["buildDefinition"].(map[string]any)["internalParameters"] = map[string]any{"github": map[string]any{"runner_environment": "self-hosted"}}
			},
			want: "provenance/hosted runner",
		},
		"built by a different workflow": {
			world: func(w *world) {
				w.prov["runDetails"].(map[string]any)["builder"] = map[string]any{"id": "https://github.com/acme/widget/.github/workflows/release.yml@refs/heads/main"}
			},
			want: "provenance/builder is build-onion",
		},
		"inventory from another run": {
			world: func(w *world) { w.inv.Run.InvocationURL = "https://github.com/acme/widget/actions/runs/7/attempts/1" },
			want:  "inventory/same run",
		},
		"artifact not a declared output": {
			world: func(w *world) { w.inv.Outputs[0].Digest = digest.Bytes([]byte("other")) },
			want:  "inventory/artifact is a declared output",
		},
		"build had network": {
			world: func(w *world) { w.inv.Build.Network = "host" },
			want:  "inventory/build ran without network",
		},
		"undeclared dependency in artifact": {
			world: func(w *world) {
				w.sbom["components"] = append(w.sbom["components"].([]any),
					map[string]any{"purl": "pkg:golang/github.com/evil/backdoor@v0.0.1"})
			},
			want: "github.com/evil/backdoor@v0.0.1",
		},
		"dependency version drift": {
			world: func(w *world) { w.inv.Dependencies[0].Version = "v3.0.0" },
			want:  "gopkg.in/yaml.v3@v3.0.1",
		},
		"no attestations": {
			input: func(in *Input) { in.Candidates = nil },
			want:  "seal/bundles verified",
		},
		"forged bundles rejected": {
			input: func(in *Input) { in.Verifier = fakeVerifier{} },
			want:  "signature invalid",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld()
			if tc.world != nil {
				tc.world(w)
			}
			in := w.input(t)
			if tc.input != nil {
				tc.input(&in)
			}
			r := Run(in)
			if r.OK() {
				t.Fatal("tampering not detected")
			}
			if joined := strings.Join(failures(r), "\n"); !strings.Contains(joined, tc.want) {
				t.Fatalf("want failure mentioning %q, got:\n%s", tc.want, joined)
			}
		})
	}
}

func TestPeelSourceLayer(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitc := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	os.WriteFile(filepath.Join(dir, "build-onion.yml"), []byte("apiVersion: build-onion/v1\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "go.sum"), []byte("gopkg.in/yaml.v3 v3.0.1 h1:x\n"), 0o644)
	gitc("init", "-q")
	gitc("add", ".")
	gitc("commit", "-qm", "init")
	head, tree := gitc("rev-parse", "HEAD"), gitc("rev-parse", "HEAD^{tree}")

	w := newWorld()
	md, _ := digest.File(filepath.Join(dir, "build-onion.yml"))
	ld, _ := digest.File(filepath.Join(dir, "go.sum"))
	w.inv.Manifest = inventory.FileRef{Path: "build-onion.yml", Digest: md}
	w.inv.Lockfiles = []inventory.FileRef{{Path: "go.sum", Digest: ld}}
	w.inv.Source.Commit, w.inv.Source.Tree = head, tree
	w.cert.SourceRepositoryDigest = head
	w.prov["buildDefinition"].(map[string]any)["resolvedDependencies"] = []any{map[string]any{
		"uri": "git+" + repoURL + "@refs/heads/main", "digest": map[string]any{"gitCommit": head},
	}}
	in := w.input(t)
	in.Claim.Commit = head
	in.SourceDir = dir

	if r := Run(in); !r.OK() {
		t.Fatalf("clean checkout failed: %v", failures(r))
	}

	// A lockfile edited after the build, even uncommitted, must not pass.
	os.WriteFile(filepath.Join(dir, "go.sum"), []byte("gopkg.in/yaml.v3 v3.0.2 h1:y\n"), 0o644)
	r := Run(in)
	joined := strings.Join(failures(r), "\n")
	for _, want := range []string{"source/checkout is clean", "source/go.sum unchanged"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
}

func TestGolangPURL(t *testing.T) {
	cases := map[string][2]string{
		"pkg:golang/github.com/a/b@v1.2.3?type=module":  {"github.com/a/b", "v1.2.3"},
		"pkg:golang/github.com/a/b%2Fv2@v2.0.0#sub/dir": {"github.com/a/b/v2", "v2.0.0"},
		"pkg:golang/stdlib@go1.27.1":                    {"stdlib", "go1.27.1"},
	}
	for in, want := range cases {
		n, v, ok := golangPURL(in)
		if !ok || n != want[0] || v != want[1] {
			t.Errorf("%s => %q %q %v", in, n, v, ok)
		}
	}
	if _, _, ok := golangPURL("pkg:deb/debian/base-files@12"); ok {
		t.Error("non-golang purl parsed")
	}
}

package peel

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/gate"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/source"
	"github.com/PatterCJ/build-onion/internal/verify"
)

const (
	repo         = "acme/widget"
	repoURL      = "https://github.com/acme/widget"
	commit       = "1111111111111111111111111111111111111111"
	signer       = "PatterCJ/build-onion/.github/workflows/onion-verify.yml"
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

// otherSigner stands in for bundles that verify cryptographically but were
// signed by an identity other than the expected signer.
type otherSigner struct{}

func (otherSigner) Verify(attest.Candidate, string) (*attest.Verified, error) {
	return nil, fmt.Errorf("failed to verify certificate identity: %w", &sigverify.ErrNoMatchingCertificateIdentity{})
}

type world struct {
	prov map[string]any
	inv  inventory.Inventory
	sbom map[string]any
	cert certificate.Summary
	// rawInventory, if set, replaces the marshalled inventory predicate.
	rawInventory []byte
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
			Pipeline: inventory.Pipeline{
				Platform:   "github-actions",
				BuildOnion: inventory.BuildOnionRef{Repository: "PatterCJ/build-onion", Commit: strings.Repeat("b", 40)},
				Workflows: []inventory.Workflow{{Role: "build-onion", Actions: []string{
					"actions/checkout@" + strings.Repeat("c", 40), "./.github/workflows/onion-build.yml",
				}}},
				Jobs: []inventory.Job{{Name: "build", Runner: "ubuntu24 20260921.1"}},
			},
			Gate: &gate.Verdict{Releasable: true, Reason: "push on refs/heads/main", ChangeKnown: true, ChangedFiles: 2},
			Verification: &inventory.Verification{
				Rebuild: &verify.Rebuild{Runner: "ubuntu24 20260921.1", Matched: true, Outputs: []verify.Match{
					{Kind: "file", Name: "widget", Staged: artifactDigest, Rebuilt: artifactDigest, Match: true},
				}},
			},
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
		if pt == inventory.PredicateType && w.rawInventory != nil {
			raw = w.rawInventory
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

// graded lists every result that isn't Passed or Note, as "STATUS layer/check: detail".
func graded(r *Report) []string {
	var out []string
	for _, res := range r.Results {
		if res.Status != Passed && res.Status != Note {
			out = append(out, string(res.Status)+" "+res.Layer+"/"+res.Check+": "+res.Detail)
		}
	}
	return out
}

func lines(r *Report) string {
	var out []string
	for _, res := range r.Results {
		out = append(out, string(res.Status)+" "+res.Layer+"/"+res.Check+": "+res.Detail)
	}
	return strings.Join(out, "\n")
}

func TestPeelHappyPath(t *testing.T) {
	r := Run(newWorld().input(t))
	if r.Verdict != Passed || r.ExitCode(false) != 0 {
		t.Fatalf("verdict %s, graded: %v", r.Verdict, graded(r))
	}
	if len(r.NotPerformed) != 2 {
		t.Errorf("not performed = %v", r.NotPerformed)
	}
}

// Each case changes one thing and names the exact grade and check it must
// produce, so a regression that turns a violation into missing evidence (or
// the reverse) is caught.
func TestPeelGrades(t *testing.T) {
	cases := map[string]struct {
		world   func(*world)
		input   func(*Input)
		want    string // "STATUS layer/check" prefix that must appear
		verdict Status
	}{
		"claimed commit differs": {
			input: func(in *Input) { in.Claim.Commit = strings.Repeat("2", 40) },
			want:  "FINDING provenance/source commit matches claim", verdict: Finding,
		},
		"signed for another repo": {
			world: func(w *world) { w.cert.SourceRepositoryURI = "https://github.com/evil/widget" },
			want:  "FINDING seal/inventory signed for claimed repo", verdict: Finding,
		},
		"self-hosted runner": {
			world: func(w *world) {
				w.prov["buildDefinition"].(map[string]any)["internalParameters"] = map[string]any{"github": map[string]any{"runner_environment": "self-hosted"}}
			},
			want: "FINDING provenance/hosted runner", verdict: Finding,
		},
		"built by a different workflow": {
			world: func(w *world) {
				w.prov["runDetails"].(map[string]any)["builder"] = map[string]any{"id": "https://github.com/acme/widget/.github/workflows/release.yml@refs/heads/main"}
			},
			want: "FINDING provenance/builder is build-onion", verdict: Finding,
		},
		"unknown build type": {
			world: func(w *world) { w.prov["buildDefinition"].(map[string]any)["buildType"] = "https://example.com/other" },
			want:  "UNSUPPORTED provenance/build type", verdict: Unsupported,
		},
		"inventory from another run": {
			world: func(w *world) { w.inv.Run.InvocationURL = "https://github.com/acme/widget/actions/runs/7/attempts/1" },
			want:  "FINDING inventory/same run", verdict: Finding,
		},
		"artifact not a declared output": {
			world: func(w *world) { w.inv.Outputs[0].Digest = digest.Bytes([]byte("other")) },
			want:  "FINDING inventory/artifact is a declared output", verdict: Finding,
		},
		"build had network": {
			world: func(w *world) { w.inv.Build.Network = "host" },
			want:  "FINDING inventory/build ran without network", verdict: Finding,
		},
		"undeclared Go module in artifact": {
			world: func(w *world) {
				w.sbom["components"] = append(w.sbom["components"].([]any),
					map[string]any{"purl": "pkg:golang/github.com/evil/backdoor@v0.0.1"})
			},
			want: "FINDING dependencies/Go modules within lockfile", verdict: Finding,
		},
		"dependency version drift": {
			world: func(w *world) { w.inv.Dependencies[0].Version = "v3.0.0" },
			want:  "FINDING dependencies/Go modules within lockfile", verdict: Finding,
		},
		"Go module without a version": {
			world: func(w *world) {
				w.sbom["components"] = append(w.sbom["components"].([]any), map[string]any{"purl": "pkg:golang/github.com/some/dep"})
			},
			want: "DEGRADED dependencies/Go module versions", verdict: Degraded,
		},
		"other ecosystem": {
			world: func(w *world) {
				w.sbom["components"] = append(w.sbom["components"].([]any), map[string]any{"purl": "pkg:npm/left-pad@1.3.0"})
			},
			want: "UNSUPPORTED dependencies/other ecosystems", verdict: Unsupported,
		},
		"OS packages in a file output": {
			world: func(w *world) {
				w.sbom["components"] = append(w.sbom["components"].([]any), map[string]any{"purl": "pkg:deb/debian/base-files@12"})
			},
			want: "DEGRADED dependencies/OS packages from pinned base images", verdict: Degraded,
		},
		"gate did not allow release": {
			world: func(w *world) { w.inv.Gate.Releasable, w.inv.Gate.Reason = false, "pull_request" },
			want:  "FINDING gate/release allowed", verdict: Finding,
		},
		"gate verdict missing": {
			world: func(w *world) { w.inv.Gate = nil },
			want:  "FAILED gate/gate verdict recorded", verdict: Failed,
		},
		"security line missing": {
			world: func(w *world) { w.inv.Verification = nil },
			want:  "FAILED verification/security line recorded", verdict: Failed,
		},
		"independent rebuild differed": {
			world: func(w *world) {
				m := &w.inv.Verification.Rebuild.Outputs[0]
				m.Staged, m.Match = digest.Bytes([]byte("injected")), false
				w.inv.Verification.Rebuild.Matched = false
			},
			want: "FINDING verification/independent rebuild matched", verdict: Finding,
		},
		"artifact never rebuilt": {
			world: func(w *world) { w.inv.Verification.Rebuild.Outputs = nil },
			want:  "FINDING verification/independent rebuild matched", verdict: Finding,
		},
		"scan of a different build": {
			world: func(w *world) {
				w.inv.Pipeline.Scans = []inventory.Scan{{Name: "sca", Tool: "scanner", Stage: "post-build", Status: "completed",
					Subject: inventory.ScanSubject{Kind: "artifact", Digest: digest.Bytes([]byte("some other build"))}}}
			},
			want: "FINDING scans/sca ran against this build", verdict: Finding,
		},
		"scan did not complete": {
			world: func(w *world) {
				w.inv.Pipeline.Scans = []inventory.Scan{{Name: "sca", Tool: "scanner", Stage: "post-build", Status: "incomplete", Coverage: "2 archives could not be extracted",
					Subject: inventory.ScanSubject{Kind: "artifact", Digest: artifactDigest}}}
			},
			want: "DEGRADED scans/sca completed", verdict: Degraded,
		},
		"unpinned action in pipeline": {
			world: func(w *world) {
				w.inv.Pipeline.Workflows[0].Actions = append(w.inv.Pipeline.Workflows[0].Actions, "example/scan-action@v1")
			},
			want: "FINDING pipeline/every action pinned", verdict: Finding,
		},
		"builder commit missing": {
			world: func(w *world) { w.inv.Pipeline.BuildOnion.Commit = "" },
			want:  "FAILED pipeline/builder commit recorded", verdict: Failed,
		},
		"no attestations": {
			input: func(in *Input) { in.Candidates = nil },
			want:  "FAILED seal/bundles found", verdict: Failed,
		},
		"bundles with invalid signatures": {
			input: func(in *Input) { in.Verifier = fakeVerifier{} },
			want:  "FINDING seal/no invalid bundles", verdict: Finding,
		},
		"validly signed by someone else": {
			input: func(in *Input) { in.Verifier = otherSigner{} },
			want:  "FAILED seal/has provenance", verdict: Failed,
		},
		"unreadable inventory": {
			world: func(w *world) { w.rawInventory = []byte(`{"source": 7}`) },
			want:  "FAILED inventory/predicate parses", verdict: Failed,
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
			if !strings.Contains(lines(r), tc.want) {
				t.Fatalf("want %q in:\n%s", tc.want, lines(r))
			}
			if r.Verdict != tc.verdict {
				t.Fatalf("verdict %s, want %s:\n%s", r.Verdict, tc.verdict, strings.Join(graded(r), "\n"))
			}
		})
	}
}

func TestExitCodes(t *testing.T) {
	for st, want := range map[Status]int{Passed: 0, Degraded: 3, Unsupported: 3, Finding: 4, Failed: 5} {
		r := &Report{Verdict: st}
		if got := r.ExitCode(false); got != want {
			t.Errorf("%s: exit %d, want %d", st, got, want)
		}
	}
	for st, want := range map[Status]int{Degraded: 0, Unsupported: 0, Finding: 4, Failed: 5} {
		if got := (&Report{Verdict: st}).ExitCode(true); got != want {
			t.Errorf("%s with --allow-degraded: exit %d, want %d", st, got, want)
		}
	}
	// A finding outranks a failure, which outranks degraded coverage.
	r := &Report{Results: []Result{{Status: Degraded}, {Status: Failed}, {Status: Finding}, {Status: Note}}}
	r.finish()
	if r.Verdict != Finding {
		t.Errorf("verdict %s, want FINDING", r.Verdict)
	}
	empty := &Report{}
	empty.finish()
	if empty.Verdict != Failed {
		t.Error("an empty report must not pass")
	}
}

func TestOSPackagesFromPinnedBase(t *testing.T) {
	imageDigest := digest.Bytes([]byte("image"))
	w := newWorld()
	w.inv.Outputs = append(w.inv.Outputs, inventory.Output{Kind: "oci-image", Name: "ghcr.io/acme/widget", Digest: imageDigest})
	w.inv.Verification.Rebuild.Outputs = append(w.inv.Verification.Rebuild.Outputs,
		verify.Match{Kind: "oci-image", Name: "ghcr.io/acme/widget", Staged: imageDigest, Rebuilt: imageDigest, Match: true})
	w.inv.Build.Image = &inventory.ImageBuild{BaseImages: []string{"gcr.io/distroless/static@sha256:" + strings.Repeat("d", 64)}, RunNetwork: "none"}
	w.sbom["components"] = append(w.sbom["components"].([]any),
		map[string]any{"purl": "pkg:deb/debian/base-files@12"},
		map[string]any{"type": "file", "name": "/etc/passwd"},
		map[string]any{"type": "operating-system", "name": "debian"})
	in := w.input(t)
	in.Digest = imageDigest
	r := Run(in)
	if r.Verdict != Passed || !strings.Contains(lines(r), "PASSED dependencies/OS packages from pinned base images: 1 OS package(s)") {
		t.Fatalf("verdict %s:\n%s", r.Verdict, lines(r))
	}

	// Same image, but a base that isn't pinned: the packages can't be accounted for.
	w.inv.Build.Image.BaseImages = []string{"gcr.io/distroless/static:latest"}
	in = w.input(t)
	in.Digest = imageDigest
	if r := Run(in); r.Verdict != Degraded {
		t.Fatalf("unpinned base: verdict %s:\n%s", r.Verdict, lines(r))
	}
}

func TestPeelRecordsScansWithoutJudging(t *testing.T) {
	w := newWorld()
	w.inv.Gate.SensitiveChange = []string{".github/workflows/release.yml"}
	w.inv.Gate.ChangeKnown = false
	w.inv.Source.Snapshot = digest.Bytes([]byte("snapshot"))
	w.inv.Pipeline.Scans = []inventory.Scan{
		{Name: "commit-risk", Tool: "jev", Version: "1", Stage: "pre-build", Status: "completed", StartedAt: "2026-09-29T20:00:00Z", FinishedAt: "2026-09-29T20:00:04Z",
			Subject: inventory.ScanSubject{Kind: "source", Digest: w.inv.Source.Snapshot}},
		{Name: "sca", Tool: "blackduck", Version: "2026.7", Stage: "post-build", Status: "completed", StartedAt: "2026-09-29T20:05:00Z", FinishedAt: "2026-09-29T20:31:00Z",
			Subject: inventory.ScanSubject{Kind: "artifact", Digest: artifactDigest}, Report: &inventory.Report{Digest: digest.Bytes([]byte("report"))}},
	}
	r := Run(w.input(t))
	if r.Verdict != Passed {
		t.Fatalf("verdict %s: %v", r.Verdict, graded(r))
	}
	joined := lines(r)
	for _, want := range []string{
		"NOTE gate/build-sensitive change",
		"NOTE gate/change set",
		"PASSED scans/commit-risk ran against this build: jev 1, pre-build",
		"PASSED scans/sca ran against this build: blackduck 2026.7, post-build",
		"against file widget",
		"PASSED scans/sca completed",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
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
	snap, err := source.Take(dir)
	if err != nil {
		t.Fatal(err)
	}
	w.inv.Source.Snapshot = snap.Digest
	w.cert.SourceRepositoryDigest = head
	w.prov["buildDefinition"].(map[string]any)["resolvedDependencies"] = []any{map[string]any{
		"uri": "git+" + repoURL + "@refs/heads/main", "digest": map[string]any{"gitCommit": head},
	}}
	in := w.input(t)
	in.Claim.Commit = head
	in.SourceDir = dir

	if r := Run(in); r.Verdict != Passed {
		t.Fatalf("clean checkout: verdict %s: %v", r.Verdict, graded(r))
	}

	// A lockfile edited after the build, even uncommitted, must not pass.
	os.WriteFile(filepath.Join(dir, "go.sum"), []byte("gopkg.in/yaml.v3 v3.0.2 h1:y\n"), 0o644)
	r := Run(in)
	joined := strings.Join(graded(r), "\n")
	for _, want := range []string{"FINDING source/checkout is clean", "FINDING source/go.sum unchanged", "FINDING source/every file matches snapshot"} {
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
		"pkg:golang/github.com/PatterCJ/build-onion":    {"github.com/PatterCJ/build-onion", ""},
	}
	for in, want := range cases {
		if n, v := golangPURL(in); n != want[0] || v != want[1] {
			t.Errorf("%s => %q %q", in, n, v)
		}
	}
	if purlType("pkg:deb/debian/base-files@12") != "deb" || purlType("nonsense") != "unknown" {
		t.Error("purlType")
	}
}

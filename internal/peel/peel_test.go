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
	"github.com/PatterCJ/build-onion/internal/egress"
	"github.com/PatterCJ/build-onion/internal/gate"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/lockfile"
	"github.com/PatterCJ/build-onion/internal/manifest"
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
			Dependencies: []lockfile.Package{{Ecosystem: "golang", Name: "gopkg.in/yaml.v3", Version: "v3.0.1"}},
			Local:        []lockfile.Local{{Ecosystem: "golang", Name: "github.com/acme/widget"}},
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
			Egress: &egress.Record{
				Mode:       egress.ModeAllowList,
				Rules:      []manifest.EgressRule{{Host: "proxy.golang.org"}},
				ProxyImage: "gcr.io/distroless/static-debian12:nonroot@sha256:" + strings.Repeat("e", 64),
				Summary: &egress.Summary{Connections: []egress.Connection{
					{Host: "proxy.golang.org", Port: 443, Allowed: true, Count: 12, BytesIn: 4 << 20},
				}},
			},
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
		"built from a ref the verifier doesn't accept": {
			input: func(in *Input) { in.Refs = []string{"refs/tags/v*"} },
			want:  "FINDING provenance/source ref accepted", verdict: Finding,
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
			want: "FINDING dependencies/every package declared", verdict: Finding,
		},
		"dependency version drift": {
			world: func(w *world) { w.inv.Dependencies[0].Version = "v3.0.0" },
			want:  "FINDING dependencies/every package declared", verdict: Finding,
		},
		"Go module without a version": {
			world: func(w *world) {
				w.sbom["components"] = append(w.sbom["components"].([]any), map[string]any{"purl": "pkg:golang/gopkg.in/yaml.v3"})
			},
			want: "DEGRADED dependencies/versions", verdict: Degraded,
		},
		"npm package in a Go project's artifact": {
			world: func(w *world) {
				w.sbom["components"] = append(w.sbom["components"].([]any), map[string]any{"purl": "pkg:npm/left-pad@1.3.0"})
			},
			want: "FINDING dependencies/every package declared", verdict: Finding,
		},
		"ecosystem without a parser": {
			world: func(w *world) {
				w.sbom["components"] = append(w.sbom["components"].([]any), map[string]any{"purl": "pkg:maven/org.example/lib@1.0"})
			},
			want: "UNSUPPORTED dependencies/coverage", verdict: Unsupported,
		},
		"OS packages in a file output": {
			world: func(w *world) {
				w.sbom["components"] = append(w.sbom["components"].([]any), map[string]any{"purl": "pkg:deb/debian/base-files@12"})
			},
			want: "UNSUPPORTED dependencies/coverage", verdict: Unsupported,
		},
		"gate did not allow release": {
			world: func(w *world) { w.inv.Gate.Releasable, w.inv.Gate.Reason = false, "pull_request" },
			want:  "FINDING gate/release allowed", verdict: Finding,
		},
		"gate verdict missing": {
			world: func(w *world) { w.inv.Gate = nil },
			want:  "FAILED gate/gate verdict recorded", verdict: Failed,
		},
		"fetch had unrestricted network": {
			world: func(w *world) { w.inv.Egress = &egress.Record{Mode: egress.ModeUnrestricted} },
			want:  "DEGRADED egress/fetch network", verdict: Degraded,
		},
		"egress never recorded": {
			world: func(w *world) { w.inv.Egress = nil },
			want:  "DEGRADED egress/fetch network", verdict: Degraded,
		},
		"fetch reached an undeclared host": {
			world: func(w *world) {
				w.inv.Egress.Summary.Connections = append(w.inv.Egress.Summary.Connections,
					egress.Connection{Host: "exfil.example.net", Port: 443, Allowed: false, Count: 1, Reason: "not in dependencies.egress"})
				w.inv.Egress.Summary.Denied = 1
			},
			want: "FINDING egress/fetch connections", verdict: Finding,
		},
		"allowed connection outside the rules": {
			world: func(w *world) {
				w.inv.Egress.Summary.Connections = append(w.inv.Egress.Summary.Connections,
					egress.Connection{Host: "storage.googleapis.com", Port: 443, Allowed: true, Count: 1})
			},
			want: "FINDING egress/fetch connections", verdict: Finding,
		},
		"proxy image not pinned": {
			world: func(w *world) { w.inv.Egress.ProxyImage = "gcr.io/distroless/static:latest" },
			want:  "FINDING egress/proxy pinned by digest", verdict: Finding,
		},
		"allow-list without a log": {
			world: func(w *world) { w.inv.Egress.Summary = nil },
			want:  "FAILED egress/fetch connections", verdict: Failed,
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

func TestAcceptedRefs(t *testing.T) {
	in := newWorld().input(t)
	in.Refs = []string{"refs/heads/main", "refs/tags/v*"}
	if r := Run(in); r.Verdict != Passed || !strings.Contains(lines(r), "PASSED provenance/source ref accepted: built from refs/heads/main") {
		t.Fatalf("verdict %s:\n%s", r.Verdict, lines(r))
	}
	in.Refs = nil
	if r := Run(in); !strings.Contains(lines(r), "NOTE provenance/source ref: built from refs/heads/main") {
		t.Fatalf("unconstrained ref not noted:\n%s", lines(r))
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

func TestImagePackagesAttributedByLayer(t *testing.T) {
	imageDigest := digest.Bytes([]byte("image"))
	baseLayer := "sha256:" + strings.Repeat("b", 64)
	appLayer := "sha256:" + strings.Repeat("a", 64)
	setup := func() (*world, func() Input) {
		w := newWorld()
		w.inv.Outputs = append(w.inv.Outputs, inventory.Output{Kind: "oci-image", Name: "ghcr.io/acme/widget", Digest: imageDigest})
		w.inv.Verification.Rebuild.Outputs = append(w.inv.Verification.Rebuild.Outputs,
			verify.Match{Kind: "oci-image", Name: "ghcr.io/acme/widget", Staged: imageDigest, Rebuilt: imageDigest, Match: true})
		base := "gcr.io/distroless/static@sha256:" + strings.Repeat("d", 64)
		w.inv.Build.Image = &inventory.ImageBuild{BaseImages: []string{base}, FinalBase: base, RunNetwork: "none",
			BaseLayers: []string{baseLayer}, Layers: []string{baseLayer, appLayer}}
		layerProp := func(l string) []any { return []any{map[string]any{"name": "syft:location:0:layerID", "value": l}} }
		w.sbom["components"] = append(w.sbom["components"].([]any),
			map[string]any{"purl": "pkg:deb/debian/base-files@12", "properties": layerProp(baseLayer)},
			map[string]any{"type": "file", "name": "/etc/passwd"},
			map[string]any{"type": "operating-system", "name": "debian"})
		return w, func() Input { in := w.input(t); in.Digest = imageDigest; return in }
	}

	w, in := setup()
	r := Run(in())
	if r.Verdict != Passed || !strings.Contains(lines(r), "PASSED dependencies/deb: 1 in artifact: 1 base-image") ||
		!strings.Contains(lines(r), "PASSED dependencies/image built on its pinned base") {
		t.Fatalf("verdict %s:\n%s", r.Verdict, lines(r))
	}

	// The image doesn't start with its declared base's layers.
	w.inv.Build.Image.Layers = []string{appLayer}
	if r := Run(in()); r.Verdict != Finding || !strings.Contains(lines(r), "FINDING dependencies/image built on its pinned base") {
		t.Fatalf("wrong base: verdict %s:\n%s", r.Verdict, lines(r))
	}

	// An OS package in a layer added on top of the base can't be lock-checked.
	w, in = setup()
	comps := w.sbom["components"].([]any)
	comps[len(comps)-3].(map[string]any)["properties"] = []any{map[string]any{"name": "syft:location:0:layerID", "value": appLayer}}
	if r := Run(in()); r.Verdict != Unsupported {
		t.Fatalf("OS package outside base: verdict %s:\n%s", r.Verdict, lines(r))
	}

	// Older inventories recorded pinned bases without layers: OS packages
	// still pass, because RUN had no network; an unpinned base doesn't.
	w, in = setup()
	w.inv.Build.Image.BaseLayers, w.inv.Build.Image.Layers = nil, nil
	if r := Run(in()); r.Verdict != Passed {
		t.Fatalf("legacy pinned: verdict %s:\n%s", r.Verdict, lines(r))
	}
	w.inv.Build.Image.BaseImages = []string{"gcr.io/distroless/static:latest"}
	if r := Run(in()); r.Verdict != Unsupported {
		t.Fatalf("legacy unpinned: verdict %s:\n%s", r.Verdict, lines(r))
	}
}

func TestBuildInputsGrades(t *testing.T) {
	w := newWorld()
	w.inv.Build.Inputs = &inventory.Inputs{Patterns: []string{"cmd/**/*.go"}, Files: 12, Of: 40, Digest: digest.Bytes([]byte("x"))}
	if r := Run(w.input(t)); r.Verdict != Passed || !strings.Contains(lines(r), "PASSED inventory/build inputs: the build saw 12 of 40 tracked files (cmd/**/*.go)") {
		t.Fatalf("declared:\n%s", lines(r))
	}
	w.inv.Build.Inputs = &inventory.Inputs{Files: 40, Of: 40}
	if r := Run(w.input(t)); r.Verdict != Passed || !strings.Contains(lines(r), "NOTE inventory/build inputs: the build could read all 40") {
		t.Fatalf("undeclared:\n%s", lines(r))
	}
}

func TestOlderInventoryShapes(t *testing.T) {
	// Inventories written before multi-ecosystem support used ecosystem "go"
	// and mainModules; they must still verify.
	w := newWorld()
	w.inv.Dependencies[0].Ecosystem = "go"
	w.inv.Local = nil
	w.inv.MainModules = []string{"github.com/acme/widget"}
	if r := Run(w.input(t)); r.Verdict != Passed {
		t.Fatalf("verdict %s: %v", r.Verdict, graded(r))
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

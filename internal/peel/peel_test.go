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
	"github.com/PatterCJ/build-onion/internal/chain"
	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/egress"
	"github.com/PatterCJ/build-onion/internal/gate"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/lockfile"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/source"
	"github.com/PatterCJ/build-onion/internal/trust"
	"github.com/PatterCJ/build-onion/internal/upstream"
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
	// key, if set, makes every layer key-signed by this trusted key name,
	// with no certificate.
	key string
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
			Lockfiles:    []inventory.FileRef{{Path: "go.sum", Digest: digest.Bytes(nil), Ecosystem: "golang"}},
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
				BuildSignerDigest:      strings.Repeat("b", 40),
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
		if w.key != "" {
			fv[pt] = &attest.Verified{Statement: attest.Statement{PredicateType: pt, Predicate: raw}, Key: w.key}
		}
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
	if len(r.NotPerformed) != 3 {
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

func TestRepositoryProtectionsShown(t *testing.T) {
	w := newWorld()
	on := true
	w.inv.Gate.Repository = &gate.RepoCheck{Branch: "main", Rules: []string{"non_fast_forward", "pull_request"}, Approvals: 1,
		CodeOwnerReview: true, CodeOwnersFile: ".github/CODEOWNERS", OwnedSensitive: 6, TagOnDefault: &on}
	r := Run(w.input(t))
	for _, want := range []string{
		"PASSED gate/branch rules: main: 1 approval(s), code-owner review",
		"PASSED gate/code owners: .github/CODEOWNERS owns all 6",
		"PASSED gate/tag on default branch",
	} {
		if !strings.Contains(lines(r), want) {
			t.Errorf("missing %q in:\n%s", want, lines(r))
		}
	}
	w.inv.Gate.Repository = &gate.RepoCheck{Branch: "main", Problems: []string{"main allows force pushes"}}
	if r := Run(w.input(t)); r.Verdict != Finding {
		t.Fatalf("a recorded protection problem must be a finding, got %s", r.Verdict)
	}
	w.inv.Gate.Repository = nil
	if r := Run(w.input(t)); !strings.Contains(lines(r), "NOTE gate/repository protections: not required by the policy") {
		t.Fatalf("absent check not noted:\n%s", lines(r))
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

func TestPeelUpstream(t *testing.T) {
	record := func(outcome, detail string) *upstream.Record {
		return &upstream.Record{
			CheckedAt: "2026-09-29T12:00:00Z",
			Lockfiles: []upstream.Lockfile{{Path: "go.sum", Digest: digest.Bytes(nil)}},
			Results:   []upstream.Result{{Ecosystem: "golang", Name: "gopkg.in/yaml.v3", Version: "v3.0.1", Outcome: outcome, Detail: detail}},
		}
	}
	cases := []struct {
		rec     *upstream.Record
		want    string
		verdict Status
	}{
		{nil, "NOTE upstream/registry check: not recorded", Passed},
		{record(upstream.Logged, ""), "PASSED upstream/golang: 1 locked: 1 logged", Passed},
		{record(upstream.Mismatch, "go.sum pins h1:x, checksum database has h1:y"), "FINDING upstream/locked bytes are the published bytes: 1 problem(s): mismatch: golang gopkg.in/yaml.v3@v3.0.1", Finding},
		{record(upstream.Invalid, "bad signature"), "FINDING upstream/locked bytes are the published bytes", Finding},
		{record(upstream.Error, "timeout"), "DEGRADED upstream/registries reachable", Degraded},
		{record(upstream.NotFound, "private"), "NOTE upstream/not comparable", Passed},
	}
	for _, c := range cases {
		w := newWorld()
		w.inv.Upstream = c.rec
		r := Run(w.input(t))
		if r.Verdict != c.verdict || !strings.Contains(lines(r), c.want) {
			t.Errorf("want %q (%s), got %s:\n%s", c.want, c.verdict, r.Verdict, lines(r))
		}
	}

	// A record of other lockfiles, or missing a package, can't be graded.
	w := newWorld()
	w.inv.Upstream = record(upstream.Logged, "")
	w.inv.Upstream.Lockfiles[0].Digest = digest.Bytes([]byte("another go.sum"))
	if r := Run(w.input(t)); r.Verdict != Failed || !strings.Contains(lines(r), "FAILED upstream/record covers the lockfiles") {
		t.Errorf("stale record: %s\n%s", r.Verdict, lines(r))
	}
	w = newWorld()
	w.inv.Upstream = record(upstream.Logged, "")
	w.inv.Upstream.Results = nil
	if r := Run(w.input(t)); r.Verdict != Failed {
		t.Errorf("record missing a package: %s\n%s", r.Verdict, lines(r))
	}
}

func TestTrustedBuilder(t *testing.T) {
	trusted := &trust.File{APIVersion: trust.APIVersion, Builders: []trust.Builder{{
		Repository: "PatterCJ/build-onion",
		Releases:   []trust.Release{{Tag: "v0.1.0", Commit: strings.Repeat("b", 40)}},
	}}}
	w := newWorld()
	in := w.input(t)
	in.Trust = trusted
	if r := Run(in); r.Verdict != Passed || !strings.Contains(lines(r), "PASSED seal/builder is a trusted release: PatterCJ/build-onion v0.1.0") {
		t.Fatalf("trusted builder:\n%s", lines(r))
	}

	// Sealed by a build-onion commit that isn't a trusted release.
	w = newWorld()
	w.cert.BuildSignerDigest = strings.Repeat("c", 40)
	in = w.input(t)
	in.Trust = trusted
	r := Run(in)
	for _, want := range []string{
		"FINDING seal/builder is a trusted release: PatterCJ/build-onion " + strings.Repeat("c", 40) + " is not a release",
		"FINDING pipeline/recorded builder is the signer",
	} {
		if !strings.Contains(lines(r), want) {
			t.Errorf("missing %q:\n%s", want, lines(r))
		}
	}

	// A trust file for another builder repository doesn't vouch for this one.
	w = newWorld()
	in = w.input(t)
	in.Trust = &trust.File{Builders: []trust.Builder{{Repository: "someone/fork", Releases: trusted.Builders[0].Releases}}}
	if r := Run(in); r.Verdict != Finding {
		t.Errorf("fork's trust entry accepted: %s", r.Verdict)
	}
}

func TestTrustedAppSigner(t *testing.T) {
	const maintainer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFJ3KAvvJbVkYNEbTcSipRyJVpjRqqSJJrGLeG2862oF maintainer@example.com"
	const other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIiDD36cbKDIQdZ2Rk3Oa/1nXAEmPaUrbLF9ialifbHF someone-else@example.com"
	trusted := &trust.File{
		Builders: []trust.Builder{{Repository: "PatterCJ/build-onion", Releases: []trust.Release{{Tag: "v0.1.0", Commit: strings.Repeat("b", 40)}}}},
		Apps:     []trust.App{{Repository: repo, TagSigners: []string{maintainer}}},
	}
	run := func(signer string, tf *trust.File) *Report {
		w := newWorld()
		w.inv.Gate.TagSigner = signer
		in := w.input(t)
		in.Trust = tf
		return Run(in)
	}
	cases := []struct {
		signer  string
		tf      *trust.File
		want    string
		verdict Status
	}{
		{maintainer, trusted, "PASSED gate/release tag signer trusted: signed by SHA256:", Passed},
		{other, trusted, "FINDING gate/release tag signer trusted: signed by SHA256:", Finding},
		{"", trusted, "FINDING gate/release tag signer trusted: " + repo + " requires a tag signed by", Finding},
		{maintainer, &trust.File{Builders: trusted.Builders}, "NOTE gate/release tag signer trusted: the trust file has no apps entry", Passed},
	}
	for _, c := range cases {
		if r := run(c.signer, c.tf); r.Verdict != c.verdict || !strings.Contains(lines(r), c.want) {
			t.Errorf("want %q (%s), got %s:\n%s", c.want, c.verdict, r.Verdict, lines(r))
		}
	}
}

// A reproducible build seals the same digest in more than one run (a release
// and a re-release from another commit). peel checks the run that matches
// the claim, whatever order the bundles arrive in, and never mixes runs.
func TestChoosesSealingRun(t *testing.T) {
	const otherRun = "https://github.com/acme/widget/actions/runs/999999999/attempts/1"
	build := func(otherFirst bool, claim string) Input {
		w := newWorld()
		in := w.input(t)
		fv := in.Verifier.(fakeVerifier)
		var other []attest.Candidate
		for _, c := range in.Candidates {
			v := *fv[c.Source]
			v.Certificate.SourceRepositoryDigest = strings.Repeat("9", 40)
			v.Certificate.RunInvocationURI = otherRun
			fv["other "+c.Source] = &v
			other = append(other, attest.Candidate{Source: "other " + c.Source})
		}
		if otherFirst {
			in.Candidates = append(other, in.Candidates...)
		} else {
			in.Candidates = append(in.Candidates, other...)
		}
		in.Claim.Commit = claim
		return in
	}
	for _, otherFirst := range []bool{true, false} {
		r := Run(build(otherFirst, commit))
		if r.Verdict != Passed {
			t.Fatalf("otherFirst=%v: claimed commit's run not chosen: %s\n%s", otherFirst, r.Verdict, lines(r))
		}
		if !strings.Contains(lines(r), "NOTE seal/other sealing runs: this digest was also sealed by 1 other run(s), not used: "+otherRun) {
			t.Errorf("other run not noted:\n%s", lines(r))
		}
	}
	// With no claimed commit, the newest run is checked, and its layers aren't
	// mixed with the older run's.
	r := Run(build(false, ""))
	if !strings.Contains(lines(r), "PASSED seal/one run signed every layer: run "+otherRun) {
		t.Errorf("newest run not chosen, or runs mixed:\n%s", lines(r))
	}
}

func TestReportModeGrades(t *testing.T) {
	w := newWorld()
	w.inv.Gate.Mode = "report"
	w.inv.Gate.WouldBlock = []string{"repository: main allows force pushes"}
	if r := Run(w.input(t)); r.Verdict != Finding || !strings.Contains(lines(r), "FINDING gate/would have been blocked: 1 reason(s) in report mode: repository: main allows force pushes") {
		t.Errorf("would-block:\n%s", lines(r))
	}

	rules := []manifest.EgressRule{{Host: "proxy.golang.org"}}
	conn := func(host string, unlisted bool) egress.Connection {
		return egress.Connection{Host: host, Port: 443, Allowed: true, Unlisted: unlisted, Count: 1}
	}
	cases := []struct {
		rules   []manifest.EgressRule
		conns   []egress.Connection
		want    string
		verdict Status
	}{
		{rules, []egress.Connection{conn("proxy.golang.org", false)}, "PASSED egress/fetch connections: report mode: every connection was within the allow-list", Passed},
		{rules, []egress.Connection{conn("proxy.golang.org", false), conn("evil.example.net", true)}, "FINDING egress/fetch connections: report mode: 1 connection(s) enforce mode would have denied: evil.example.net:443", Finding},
		{nil, []egress.Connection{conn("proxy.golang.org", true)}, "DEGRADED egress/fetch network: report mode with no allow-list", Degraded},
	}
	for _, c := range cases {
		w := newWorld()
		w.inv.Gate.Mode = "report"
		w.inv.Egress = &egress.Record{Mode: egress.ModeRecord, Rules: c.rules, ProxyImage: w.inv.Egress.ProxyImage,
			Summary: &egress.Summary{Connections: c.conns}}
		r := Run(w.input(t))
		if r.Verdict != c.verdict || !strings.Contains(lines(r), c.want) || !strings.Contains(lines(r), "NOTE egress/allow-list for what fetch reached") {
			t.Errorf("want %q (%s), got %s:\n%s", c.want, c.verdict, r.Verdict, lines(r))
		}
	}
}

func TestInstallScriptsAndEgressSource(t *testing.T) {
	w := newWorld()
	w.inv.Dependencies = append(w.inv.Dependencies, lockfile.Package{Ecosystem: "npm", Name: "esbuild", Version: "0.24.0", InstallScript: true})
	w.inv.Build.Fetch = "npm ci"
	if r := Run(w.input(t)); !strings.Contains(lines(r), "NOTE inventory/dependency install scripts: 1 package(s) ran install scripts during fetch: esbuild@0.24.0") {
		t.Errorf("install scripts not noted:\n%s", lines(r))
	}
	w.inv.Build.Fetch = "npm ci --ignore-scripts"
	if r := Run(w.input(t)); !strings.Contains(lines(r), "the fetch command asks npm not to run them") {
		t.Errorf("command-disabled scripts not noted:\n%s", lines(r))
	}
	w.inv.Build.Fetch = "npm ci"
	w.inv.Egress.InstallScriptsDisabled = true
	if r := Run(w.input(t)); !strings.Contains(lines(r), "policy turned them off for the whole fetch step") {
		t.Errorf("policy-disabled scripts not noted:\n%s", lines(r))
	}

	w = newWorld()
	w.inv.Source.Snapshot = digest.Bytes([]byte("snapshot"))
	w.inv.Egress.Snapshot = w.inv.Source.Snapshot
	if r := Run(w.input(t)); r.Verdict != Passed || !strings.Contains(lines(r), "PASSED egress/fetch ran on this source") {
		t.Errorf("matching egress source:\n%s", lines(r))
	}
	w.inv.Egress.Snapshot = digest.Bytes([]byte("another snapshot"))
	if r := Run(w.input(t)); r.Verdict != Finding || !strings.Contains(lines(r), "FINDING egress/fetch ran on this source") {
		t.Errorf("egress from another source:\n%s", lines(r))
	}
}

// A run sealed with a trusted enterprise key passes on the key's identity;
// the certificate checks are replaced, and everything below the seal is
// checked as usual.
func TestKeySignedSeal(t *testing.T) {
	w := newWorld()
	w.key = "acme-kms-release"
	r := Run(w.input(t))
	for _, want := range []string{
		"PASSED seal/one key signed every layer: acme-kms-release",
		"PASSED seal/signed by a trusted key: acme-kms-release (from the trust file)",
		"NOTE seal/key signing: no certificate or transparency log",
		"PASSED provenance/source commit matches claim",
		"PASSED inventory/same source commit",
	} {
		if !strings.Contains(lines(r), want) {
			t.Errorf("missing %q:\n%s", want, lines(r))
		}
	}
	if r.Verdict != Passed {
		t.Errorf("verdict %s:\n%s", r.Verdict, lines(r))
	}
	if strings.Contains(lines(r), "signed for claimed repo") || strings.Contains(lines(r), "builder is a trusted release") {
		t.Errorf("certificate checks ran on a key-signed seal:\n%s", lines(r))
	}
	if !strings.Contains(lines(r), "verified against the trust file's keys") {
		t.Errorf("key-signed bundles described as verified against a workflow:\n%s", lines(r))
	}
	// A key can seal for several repositories: claiming the artifact for
	// another one is caught by the inventory, with or without provenance.
	in := w.input(t)
	in.Claim.Repository = "someone/else"
	if r := Run(in); r.Verdict != Finding || !strings.Contains(lines(r), "FINDING inventory/claimed repository") {
		t.Errorf("another repository's key-signed artifact: %s\n%s", r.Verdict, lines(r))
	}
	delete(w.prov, "buildDefinition")
	in = w.input(t)
	in.Claim.Repository = "someone/else"
	if r := Run(in); !strings.Contains(lines(r), "FINDING inventory/claimed repository") {
		t.Errorf("another repository's key-signed inventory, no usable provenance:\n%s", lines(r))
	}
	w = newWorld()
	w.key = "acme-kms-release"
	// A claimed commit the signed provenance doesn't name is still caught.
	in = w.input(t)
	in.Claim.Commit = strings.Repeat("9", 40)
	if r := Run(in); r.Verdict != Finding {
		t.Errorf("wrong commit with a key seal: %s", r.Verdict)
	}
}

// A key-signed bundle with an untrusted key is noted, not counted as
// tampering, and doesn't count as evidence.
func TestUntrustedKeyBundles(t *testing.T) {
	in := newWorld().input(t)
	in.Verifier = untrustedKey{}
	r := Run(in)
	if !strings.Contains(lines(r), "NOTE seal/bundles signed with untrusted keys") || strings.Contains(lines(r), "FINDING seal/no invalid bundles") {
		t.Errorf("untrusted key bundles:\n%s", lines(r))
	}
	if r.Verdict != Failed {
		t.Errorf("no trusted evidence should fail, got %s", r.Verdict)
	}
}

type untrustedKey struct{}

func (untrustedKey) Verify(attest.Candidate, string) (*attest.Verified, error) {
	return nil, &attest.UntrustedKey{Hint: "abc"}
}

// Two releases sealed the same digest with the same key (a reproducible
// re-release). Their records are grouped by the run they name, so the run
// matching the claim is checked and the two are never mixed.
func TestKeySignedRunsAreNotMixed(t *testing.T) {
	const otherCommit = "9999999999999999999999999999999999999999"
	const otherRun = "https://github.com/acme/widget/actions/runs/777/attempts/1"
	build := func(otherFirst bool) Input {
		w := newWorld()
		w.key = "acme-kms"
		in := w.input(t)
		fv := in.Verifier.(fakeVerifier)
		var other []attest.Candidate
		for _, c := range in.Candidates {
			v := *fv[c.Source]
			var pred map[string]any
			json.Unmarshal(v.Statement.Predicate, &pred)
			if bd, ok := pred["buildDefinition"].(map[string]any); ok {
				bd["resolvedDependencies"].([]any)[0].(map[string]any)["digest"] = map[string]any{"gitCommit": otherCommit}
				pred["runDetails"].(map[string]any)["metadata"] = map[string]any{"invocationId": otherRun}
			}
			if src, ok := pred["source"].(map[string]any); ok {
				src["commit"] = otherCommit
				pred["run"] = map[string]any{"invocationUrl": otherRun}
			}
			raw, _ := json.Marshal(pred)
			v.Statement.Predicate = raw
			fv["other "+c.Source] = &v
			other = append(other, attest.Candidate{Source: "other " + c.Source})
		}
		if otherFirst {
			in.Candidates = append(other, in.Candidates...)
		} else {
			in.Candidates = append(in.Candidates, other...)
		}
		in.Claim.Commit = commit
		return in
	}
	for _, otherFirst := range []bool{true, false} {
		r := Run(build(otherFirst))
		if r.Verdict != Passed || !strings.Contains(lines(r), "NOTE seal/other sealing runs") {
			t.Errorf("otherFirst=%v: %s\n%s", otherFirst, r.Verdict, lines(r))
		}
	}
}

// A single-pipeline build: its phase records pass, and the missing
// independent rebuild is degraded with the reason in the report.
func TestSinglePipelineGrades(t *testing.T) {
	w := newWorld()
	snap := digest.Bytes([]byte("snapshot"))
	w.inv.Source.Snapshot = snap
	w.inv.Verification = nil
	s := chain.Link{Step: chain.StepSnapshot, Run: runURL, Snapshot: snap, Products: []chain.Resource{{Name: "source-snapshot", Digest: snap}}}
	b, _ := chain.Next(s, chain.StepBuild, runURL, snap)
	b.Materials = []chain.Resource{{Name: "source-snapshot", Digest: snap}}
	b.Products = []chain.Resource{{Name: "file widget", Digest: artifactDigest}}
	w.inv.Chain = []chain.Link{s, b}
	r := Run(w.input(t))
	for _, want := range []string{
		"PASSED verification/phase records: snapshot → build: every hand-off matched, run " + runURL,
		"DEGRADED verification/independent rebuild: not performed: a single-pipeline build",
		"only a rebuild on separate infrastructure detects that",
	} {
		if !strings.Contains(lines(r), want) {
			t.Errorf("missing %q:\n%s", want, lines(r))
		}
	}
	if r.Verdict != Degraded {
		t.Errorf("verdict %s", r.Verdict)
	}
	// A record that doesn't end in the sealed artifact is a finding.
	w.inv.Chain[1].Products[0].Digest = digest.Bytes([]byte("other"))
	if r := Run(w.input(t)); r.Verdict != Finding || !strings.Contains(lines(r), "FINDING verification/phase records") {
		t.Errorf("tampered chain: %s\n%s", r.Verdict, lines(r))
	}
}

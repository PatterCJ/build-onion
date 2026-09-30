package peel

import (
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/lockfile"
	"github.com/PatterCJ/build-onion/internal/upstream"
)

func diffInv(commit string, pkgs []lockfile.Package, results []upstream.Result) *inventory.Inventory {
	w := newWorld()
	inv := w.inv
	inv.Source.Commit = commit
	inv.Dependencies = pkgs
	inv.Upstream = &upstream.Record{Results: results}
	return &inv
}

func attested(name, version, repo, workflow string) upstream.Result {
	return upstream.Result{Ecosystem: "npm", Name: name, Version: version, Outcome: upstream.Attested,
		Attestations: []upstream.Attestation{{Signer: upstream.Signer{Issuer: "https://token.actions.githubusercontent.com",
			Repository: repo, Workflow: workflow + "@refs/tags/v" + version}}}}
}

func published(name, version string) upstream.Result {
	return upstream.Result{Ecosystem: "npm", Name: name, Version: version, Outcome: upstream.Published}
}

func runDiff(t *testing.T, old, cur *inventory.Inventory, accept bool) *Report {
	t.Helper()
	r := &Report{Artifact: "widget", Results: []Result{{Layer: "seal", Check: "ok", Status: Passed}}, inv: cur}
	base := &Report{Artifact: "widget:previous", Verdict: Passed, inv: old}
	Differential(r, base, accept)
	return r
}

func TestDifferentialSigners(t *testing.T) {
	const repo, wf = "https://github.com/acme/lib", "https://github.com/acme/lib/.github/workflows/release.yml"
	pkgs := func(v string) []lockfile.Package {
		return []lockfile.Package{{Ecosystem: "npm", Name: "lib", Version: v}}
	}
	old := diffInv("aaaa", pkgs("1.0.0"), []upstream.Result{attested("lib", "1.0.0", repo, wf)})

	cases := []struct {
		name    string
		cur     upstream.Result
		want    string
		verdict Status
	}{
		{"same signer, new version", attested("lib", "1.1.0", repo, wf), "PASSED differential/dependency signers: 1 attested", Passed},
		{"provenance lost", published("lib", "1.1.0"), "FINDING differential/provenance lost: 1 package(s)", Finding},
		{"other repository", attested("lib", "1.1.0", "https://github.com/someone/lib", wf), "FINDING differential/signer changed: 1 package(s)", Finding},
		{"other workflow", attested("lib", "1.1.0", repo, repo+"/.github/workflows/manual.yml"), "FINDING differential/signer changed", Finding},
		{"registry unreachable now", upstream.Result{Ecosystem: "npm", Name: "lib", Version: "1.1.0", Outcome: upstream.Error}, "PASSED differential/dependency signers", Passed},
	}
	for _, c := range cases {
		r := runDiff(t, old, diffInv("bbbb", pkgs(c.cur.Version), []upstream.Result{c.cur}), false)
		if r.Verdict != c.verdict || !strings.Contains(lines(r), c.want) {
			t.Errorf("%s: want %q (%s), got %s:\n%s", c.name, c.want, c.verdict, r.Verdict, lines(r))
		}
	}

	r := runDiff(t, old, diffInv("bbbb", pkgs("1.1.0"), []upstream.Result{published("lib", "1.1.0")}), true)
	if r.Verdict != Passed || !strings.Contains(lines(r), "NOTE differential/provenance lost") {
		t.Errorf("accepted signer change should be a note:\n%s", lines(r))
	}
	r = runDiff(t, diffInv("aaaa", pkgs("1.0.0"), []upstream.Result{published("lib", "1.0.0")}),
		diffInv("bbbb", pkgs("1.1.0"), []upstream.Result{attested("lib", "1.1.0", repo, wf)}), false)
	if r.Verdict != Passed || !strings.Contains(lines(r), "NOTE differential/provenance gained: 1 package(s)") {
		t.Errorf("gained provenance:\n%s", lines(r))
	}
}

func TestDifferentialChanges(t *testing.T) {
	old := diffInv("aaaa", []lockfile.Package{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"}, {Ecosystem: "npm", Name: "gone", Version: "2.0.0"},
	}, nil)
	cur := diffInv("bbbb", []lockfile.Package{
		{Ecosystem: "npm", Name: "a", Version: "1.1.0"}, {Ecosystem: "npm", Name: "new", Version: "0.1.0"},
	}, nil)
	cur.Builder.Image = "docker.io/library/golang:1.28@sha256:" + strings.Repeat("9", 64)
	cur.Egress.Rules = append(cur.Egress.Rules, cur.Egress.Rules[0])
	cur.Egress.Rules[1].Host = "evil.example.com"
	r := runDiff(t, old, cur, false)
	for _, want := range []string{
		"PASSED differential/baseline: widget:previous, built from aaaa",
		"NOTE differential/dependencies added: 1: npm:new@0.1.0",
		"NOTE differential/dependency versions changed: 1: npm:a 1.0.0→1.1.0",
		"NOTE differential/dependencies removed: 1: npm:gone",
		"NOTE differential/build configuration changed: 2 change(s): builder:",
		"evil.example.com",
	} {
		if !strings.Contains(lines(r), want) {
			t.Errorf("missing %q in:\n%s", want, lines(r))
		}
	}
	if r.Verdict != Passed {
		t.Errorf("changes alone must not fail the verdict: %s", r.Verdict)
	}
	if r := runDiff(t, old, old, false); !strings.Contains(lines(r), "NOTE differential/baseline: widget:previous is the same commit") {
		t.Errorf("same commit:\n%s", lines(r))
	}
}

func TestDifferentialNeedsVerifiedBaseline(t *testing.T) {
	cur := diffInv("bbbb", nil, nil)
	r := &Report{Artifact: "widget", inv: cur}
	Differential(r, &Report{Artifact: "widget:previous", Verdict: Finding, inv: diffInv("aaaa", nil, nil)}, false)
	if r.Verdict != Degraded || !strings.Contains(lines(r), "DEGRADED differential/baseline verifies: baseline widget:previous is FINDING") {
		t.Errorf("unverified baseline:\n%s", lines(r))
	}
	r = &Report{Artifact: "widget", inv: cur}
	Differential(r, &Report{Artifact: "missing", Verdict: Failed}, false)
	if r.Verdict != Degraded {
		t.Errorf("missing baseline: %s", r.Verdict)
	}
}

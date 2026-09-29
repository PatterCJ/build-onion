// Package peel runs the reverse check. Starting from an artifact digest it
// removes one layer at a time — seal, provenance, inventory, dependencies,
// source, rebuild — and checks that each layer agrees with the one beneath it
// and with what the caller claims the artifact is.
package peel

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/source"
	"github.com/PatterCJ/build-onion/internal/verify"
)

const (
	SLSAProvenanceV1 = "https://slsa.dev/provenance/v1"
	CycloneDX        = "https://cyclonedx.org/bom"
	GitHubBuildType  = "https://actions.github.io/buildtypes/workflow/v1"
)

type Status string

const (
	Pass Status = "PASS"
	Fail Status = "FAIL"
	Warn Status = "WARN" // recorded concern that does not fail verification
	Skip Status = "SKIP"
)

type Result struct {
	Layer  string `json:"layer"`
	Check  string `json:"check"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	Artifact string   `json:"artifact"`
	Digest   string   `json:"digest"`
	Results  []Result `json:"results"`
}

func (r *Report) OK() bool {
	for _, res := range r.Results {
		if res.Status == Fail {
			return false
		}
	}
	return len(r.Results) > 0
}

func (r *Report) add(layer, check string, ok bool, detail string, a ...any) bool {
	st := Pass
	if !ok {
		st = Fail
	}
	r.Results = append(r.Results, Result{Layer: layer, Check: check, Status: st, Detail: fmt.Sprintf(detail, a...)})
	return ok
}

func (r *Report) warn(layer, check, detail string) {
	r.Results = append(r.Results, Result{Layer: layer, Check: check, Status: Warn, Detail: detail})
}

func (r *Report) skip(layer, check, detail string) {
	r.Results = append(r.Results, Result{Layer: layer, Check: check, Status: Skip, Detail: detail})
}

// Claim is what the caller asserts about the artifact.
type Claim struct {
	Repository string // owner/repo the artifact claims to be built from
	Commit     string // optional: the exact commit claimed
}

// Input is everything peel needs; bundles are verified by the caller-supplied
// verifier so this package stays testable without a trust root.
type Input struct {
	Artifact string
	Digest   string
	Claim    Claim
	Signer   attest.Identity
	Verifier interface {
		Verify(c attest.Candidate, digest string) (*attest.Verified, error)
	}
	Candidates []attest.Candidate
	SourceDir  string // optional local checkout for the source layer
	Rebuild    bool   // re-run the build from SourceDir and compare digests
}

// Run peels every layer and returns the report. It never stops early: a
// failed outer layer still lets inner layers report what they can see.
func Run(in Input) *Report {
	r := &Report{Artifact: in.Artifact, Digest: in.Digest}
	repoURL := "https://github.com/" + in.Claim.Repository

	// Layer 1: seal — signatures, identities, and one run behind all of them.
	verified := map[string]*attest.Verified{}
	var rejected []string
	unrelated := 0
	for _, c := range in.Candidates {
		if about, known := c.About(in.Digest); known && !about {
			unrelated++
			continue
		}
		v, err := in.Verifier.Verify(c, in.Digest)
		if err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %v", c.Source, err))
			continue
		}
		v.Source = c.Source
		// Keep the first verified statement per predicate type.
		if _, dup := verified[v.Statement.PredicateType]; !dup {
			verified[v.Statement.PredicateType] = v
		}
	}
	r.add("seal", "bundles verified", len(verified) > 0,
		"%d of %d bundles for this artifact verified against signer %s%s%s",
		len(verified), len(in.Candidates)-unrelated, in.Signer.SignerWorkflow, unrelatedNote(unrelated), rejectedNote(rejected))
	for _, pt := range []string{SLSAProvenanceV1, CycloneDX, inventory.PredicateType} {
		_, ok := verified[pt]
		r.add("seal", "has "+shortType(pt), ok, "%s", pt)
	}
	var runs []string
	for _, v := range verified {
		cert := v.Certificate
		r.add("seal", shortType(v.Statement.PredicateType)+" signed for claimed repo", cert.SourceRepositoryURI == repoURL,
			"certificate source repo %q, claimed %q", cert.SourceRepositoryURI, repoURL)
		if in.Claim.Commit != "" {
			r.add("seal", shortType(v.Statement.PredicateType)+" signed for claimed commit", cert.SourceRepositoryDigest == in.Claim.Commit,
				"certificate commit %s, claimed %s", cert.SourceRepositoryDigest, in.Claim.Commit)
		}
		runs = append(runs, cert.RunInvocationURI)
	}
	if len(runs) > 0 {
		r.add("seal", "one run signed every layer", allEqual(runs), "run %s", strings.Join(uniq(runs), ", "))
	}

	// Layer 2: provenance — SLSA v1 from GitHub, signed by the isolated builder.
	var prov provenance
	if v := verified[SLSAProvenanceV1]; v != nil && decode(r, "provenance", v.Statement.Predicate, &prov) {
		bd, rd := prov.BuildDefinition, prov.RunDetails
		r.add("provenance", "build type", bd.BuildType == GitHubBuildType, "%s", bd.BuildType)
		builderPrefix := "https://github.com/" + in.Signer.SignerWorkflow + "@"
		r.add("provenance", "builder is build-onion", strings.HasPrefix(rd.Builder.ID, builderPrefix), "builder.id %s", rd.Builder.ID)
		r.add("provenance", "hosted runner", bd.InternalParameters.GitHub.RunnerEnvironment == "github-hosted",
			"runner_environment %q (SLSA L3 requires a hosted build platform)", bd.InternalParameters.GitHub.RunnerEnvironment)
		r.add("provenance", "source repository", bd.ExternalParameters.Workflow.Repository == repoURL,
			"workflow repository %s", bd.ExternalParameters.Workflow.Repository)
		commit := prov.sourceCommit(repoURL)
		r.add("provenance", "source commit recorded", commit != "", "resolvedDependencies gitCommit %q", commit)
		if in.Claim.Commit != "" {
			r.add("provenance", "source commit matches claim", commit == in.Claim.Commit, "provenance %s, claimed %s", commit, in.Claim.Commit)
		}
		if in.Claim.Commit == "" {
			in.Claim.Commit = commit
		}
	}

	// Layer 3: inventory — the bottom-up record binds to the same run and source.
	var inv inventory.Inventory
	haveInv := false
	if v := verified[inventory.PredicateType]; v != nil && decode(r, "inventory", v.Statement.Predicate, &inv) {
		haveInv = true
		r.add("inventory", "same source commit", inv.Source.Commit == in.Claim.Commit && in.Claim.Commit != "",
			"inventory %s, provenance %s", inv.Source.Commit, in.Claim.Commit)
		r.add("inventory", "same run", prov.RunDetails.Metadata.InvocationID == "" || sameRun(inv.Run.InvocationURL, prov.RunDetails.Metadata.InvocationID),
			"inventory %s, provenance %s", inv.Run.InvocationURL, prov.RunDetails.Metadata.InvocationID)
		out, ok := inv.Subject(in.Digest)
		r.add("inventory", "artifact is a declared output", ok, "%s %s", out.Kind, out.Name)
		r.add("inventory", "builder pinned by digest", manifest.IsPinnedImage(inv.Builder.Image), "%s", inv.Builder.Image)
		r.add("inventory", "build ran without network", inv.Build.Network == "none", "network %q", inv.Build.Network)
		r.add("inventory", "inputs locked", len(inv.Lockfiles) > 0, "%d lockfile(s), %d locked dependencies", len(inv.Lockfiles), len(inv.Dependencies))
	}

	// Layer 4: gate — the build was allowed to become a release, and what the
	// gate noticed on the way in.
	if haveInv {
		checkGate(r, &inv)
		checkVerification(r, &inv, in.Digest)
		checkPipeline(r, &inv)
		checkScans(r, &inv)
	}

	// Layer 5: dependencies — everything the SBOM finds in the artifact must be
	// something the lockfile declared.
	if v := verified[CycloneDX]; v != nil && haveInv {
		checkDependencies(r, v.Statement.Predicate, &inv)
	} else {
		r.skip("dependencies", "SBOM within lockfile", "needs verified SBOM and inventory")
	}

	// Layer 6: source — recompute the inventory's source facts from a checkout.
	if in.SourceDir == "" {
		r.skip("source", "checkout matches inventory", "pass --source <checkout> to peel to the source")
	} else if haveInv {
		checkSource(r, in.SourceDir, &inv)
	}

	// Layer 7: rebuild — run the declared build again and compare.
	if !in.Rebuild {
		r.skip("rebuild", "reproduces artifact", "pass --rebuild with --source to rebuild")
	} else if haveInv && in.SourceDir != "" {
		checkRebuild(r, in.SourceDir, &inv, in.Digest)
	}
	return r
}

type provenance struct {
	BuildDefinition struct {
		BuildType          string `json:"buildType"`
		ExternalParameters struct {
			Workflow struct {
				Ref        string `json:"ref"`
				Repository string `json:"repository"`
				Path       string `json:"path"`
			} `json:"workflow"`
		} `json:"externalParameters"`
		InternalParameters struct {
			GitHub struct {
				EventName         string `json:"event_name"`
				RunnerEnvironment string `json:"runner_environment"`
			} `json:"github"`
		} `json:"internalParameters"`
		ResolvedDependencies []struct {
			URI    string            `json:"uri"`
			Digest map[string]string `json:"digest"`
		} `json:"resolvedDependencies"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		Metadata struct {
			InvocationID string `json:"invocationId"`
		} `json:"metadata"`
	} `json:"runDetails"`
}

func (p *provenance) sourceCommit(repoURL string) string {
	for _, d := range p.BuildDefinition.ResolvedDependencies {
		if strings.HasPrefix(d.URI, "git+"+repoURL+"@") {
			return d.Digest["gitCommit"]
		}
	}
	return ""
}

func checkGate(r *Report, inv *inventory.Inventory) {
	g := inv.Gate
	if !r.add("gate", "gate verdict recorded", g != nil, "") {
		return
	}
	r.add("gate", "release allowed", g.Releasable && !g.Blocked, "%s", g.Reason)
	if len(g.SensitiveChange) > 0 {
		r.warn("gate", "build-sensitive change", fmt.Sprintf("this commit changed %s", strings.Join(g.SensitiveChange, ", ")))
	}
	if !g.ChangeKnown {
		r.warn("gate", "change set", "unknown; no previous build point to diff against")
	}
}

// checkVerification reads the security line's record: an independent rebuild
// matched the build line for this artifact.
func checkVerification(r *Report, inv *inventory.Inventory, d string) {
	v := inv.Verification
	if !r.add("verification", "security line recorded", v != nil && v.Rebuild != nil, "") {
		return
	}
	var m *verify.Match
	for i := range v.Rebuild.Outputs {
		if v.Rebuild.Outputs[i].Rebuilt == d {
			m = &v.Rebuild.Outputs[i]
		}
	}
	if m == nil {
		r.add("verification", "independent rebuild matched", false, "artifact not among the rebuilt outputs")
	} else {
		r.add("verification", "independent rebuild matched", m.Match && v.Rebuild.Matched,
			"%s %s: build line %s, rebuild %s on %s", m.Kind, m.Name, m.Staged, m.Rebuilt, v.Rebuild.Runner)
	}
}

// checkScans lists the tools the pipeline ran and binds each to this build.
// build-onion records that a scan happened; it does not judge findings.
func checkScans(r *Report, inv *inventory.Inventory) {
	if len(inv.Pipeline.Scans) == 0 {
		r.skip("scans", "scans recorded", "the pipeline recorded no scans")
		return
	}
	for _, sc := range inv.Pipeline.Scans {
		var about string
		var bound bool
		switch sc.Subject.Kind {
		case "source":
			about, bound = "source snapshot", sc.Subject.Digest == inv.Source.Snapshot
		case "artifact":
			out, ok := inv.Subject(sc.Subject.Digest)
			about, bound = out.Kind+" "+out.Name, ok
		}
		detail := fmt.Sprintf("%s %s, %s, %s → %s, against %s %s", sc.Tool, sc.Version, sc.Stage, sc.StartedAt, sc.FinishedAt, about, sc.Subject.Digest)
		if sc.Report != nil {
			detail += ", report " + sc.Report.Digest
		}
		r.add("scans", sc.Name+" ran against this build", bound, "%s", detail)
	}
}

var pinnedUse = regexp.MustCompile(`^[^@\s]+@[a-f0-9]{40}$`)

func checkPipeline(r *Report, inv *inventory.Inventory) {
	pl := inv.Pipeline
	r.add("pipeline", "builder commit recorded", len(pl.BuildOnion.Commit) == 40,
		"build-onion %s@%s", pl.BuildOnion.Repository, pl.BuildOnion.Commit)
	var loose []string
	n := 0
	for _, w := range pl.Workflows {
		for _, a := range w.Actions {
			n++
			if !strings.HasPrefix(a, "./") && !pinnedUse.MatchString(a) && !(strings.HasPrefix(a, "docker://") && manifest.IsPinnedImage(strings.TrimPrefix(a, "docker://"))) {
				loose = append(loose, a)
			}
		}
	}
	r.add("pipeline", "every action pinned", len(pl.Workflows) > 0 && len(loose) == 0,
		"%d action reference(s) across %d workflow(s)%s", n, len(pl.Workflows), listNote(loose))
	r.add("pipeline", "jobs inventoried", len(pl.Jobs) > 0, "%d job(s) recorded runner and tool versions", len(pl.Jobs))
}

func checkDependencies(r *Report, bom json.RawMessage, inv *inventory.Inventory) {
	var doc struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		} `json:"components"`
	}
	if !decode(r, "dependencies", bom, &doc) {
		return
	}
	locked := map[string]bool{}
	for _, d := range inv.Dependencies {
		locked[strings.ToLower(d.Name+"@"+d.Version)] = true
	}
	main := map[string]bool{"stdlib": true}
	for _, m := range inv.MainModules {
		main[m] = true
	}
	var undeclared []string
	goCount, other := 0, 0
	for _, c := range doc.Components {
		name, version, ok := golangPURL(c.PURL)
		if !ok {
			if c.PURL != "" {
				other++
			}
			continue
		}
		if main[name] {
			continue
		}
		goCount++
		if !locked[strings.ToLower(name+"@"+version)] {
			undeclared = append(undeclared, name+"@"+version)
		}
	}
	sort.Strings(undeclared)
	r.add("dependencies", "SBOM within lockfile", len(undeclared) == 0,
		"%d Go modules found in artifact, %d not in lockfile%s", goCount, len(undeclared), listNote(undeclared))
	if other > 0 {
		r.skip("dependencies", "non-Go components", fmt.Sprintf("%d component(s) not lock-checked (e.g. OS packages from a pinned base image)", other))
	}
}

// golangPURL parses pkg:golang/<module>@<version>[?qualifiers].
func golangPURL(p string) (name, version string, ok bool) {
	rest, found := strings.CutPrefix(p, "pkg:golang/")
	if !found {
		return "", "", false
	}
	rest, _, _ = strings.Cut(rest, "?")
	rest, _, _ = strings.Cut(rest, "#")
	i := strings.LastIndex(rest, "@")
	if i < 0 {
		return "", "", false
	}
	n, err1 := url.PathUnescape(rest[:i])
	v, err2 := url.PathUnescape(rest[i+1:])
	return n, v, err1 == nil && err2 == nil
}

func checkSource(r *Report, dir string, inv *inventory.Inventory) {
	head, err := git(dir, "rev-parse", "HEAD")
	if !r.add("source", "checkout at claimed commit", err == nil && head == inv.Source.Commit, "HEAD %s, inventory %s%s", head, inv.Source.Commit, errNote(err)) {
		return
	}
	tree, err := git(dir, "rev-parse", "HEAD^{tree}")
	r.add("source", "tree hash", err == nil && tree == inv.Source.Tree, "tree %s, inventory %s%s", tree, inv.Source.Tree, errNote(err))
	dirty, err := git(dir, "status", "--porcelain", "--untracked-files=no")
	r.add("source", "checkout is clean", err == nil && dirty == "", "%s", firstLine(dirty))
	if snap, err := source.Take(dir); err == nil {
		r.add("source", "every file matches snapshot", snap.Digest == inv.Source.Snapshot,
			"%d files hash to %s, inventory %s", len(snap.Files), snap.Digest, inv.Source.Snapshot)
	} else {
		r.add("source", "every file matches snapshot", false, "%v", err)
	}
	for _, f := range append([]inventory.FileRef{inv.Manifest}, inv.Lockfiles...) {
		d, err := digest.File(filepath.Join(dir, f.Path))
		r.add("source", f.Path+" unchanged", err == nil && d == f.Digest, "%s%s", d, errNote(err))
	}
}

func checkRebuild(r *Report, dir string, inv *inventory.Inventory, want string) {
	out, ok := inv.Subject(want)
	if !ok || out.Kind != "file" {
		r.skip("rebuild", "reproduces artifact", "rebuild supports file outputs; images are checked via their files")
		return
	}
	m, _, err := manifest.Load(filepath.Join(dir, inv.Manifest.Path))
	if !r.add("rebuild", "load manifest", err == nil, "%s%s", inv.Manifest.Path, errNote(err)) {
		return
	}
	got, err := Rebuild(dir, m, out.Name)
	r.add("rebuild", "reproduces artifact", err == nil && got == want, "rebuilt %s, attested %s%s", got, want, errNote(err))
}

func decode(r *Report, layer string, raw json.RawMessage, v any) bool {
	err := json.Unmarshal(raw, v)
	return r.add(layer, "predicate parses", err == nil, "%s", errNote(err))
}

func git(dir string, args ...string) (string, error) {
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	return strings.TrimSpace(string(out)), err
}

// sameRun compares run URLs ignoring the attempt suffix, since the inventory
// records the run and provenance records the attempt.
func sameRun(a, b string) bool {
	trim := func(s string) string { s, _, _ = strings.Cut(s, "/attempts/"); return s }
	return a != "" && trim(a) == trim(b)
}

func shortType(pt string) string {
	switch pt {
	case SLSAProvenanceV1:
		return "provenance"
	case CycloneDX:
		return "sbom"
	case inventory.PredicateType:
		return "inventory"
	}
	return pt
}

func allEqual(xs []string) bool {
	for _, x := range xs {
		if x != xs[0] {
			return false
		}
	}
	return true
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func errNote(err error) string {
	if err == nil {
		return ""
	}
	return " (" + err.Error() + ")"
}

func unrelatedNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d bundle(s) for other artifacts ignored)", n)
}

func rejectedNote(rej []string) string {
	if len(rej) == 0 {
		return ""
	}
	return "; rejected: " + strings.Join(rej, "; ")
}

func listNote(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	if len(xs) > 5 {
		xs = append(xs[:5:5], fmt.Sprintf("… %d more", len(xs)-5))
	}
	return ": " + strings.Join(xs, ", ")
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}

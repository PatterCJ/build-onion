// Package peel runs the reverse check. Starting from an artifact digest it
// removes one layer at a time — seal, provenance, inventory, gate,
// verification, pipeline, scans, dependencies, source, rebuild — and checks
// that each layer agrees with the one beneath it and with what the caller
// claims the artifact is.
//
// Every check is graded, and the report's verdict is the worst grade present.
// Incomplete evidence is never reported as clean: a check that could not be
// performed is Failed, Degraded or Unsupported, never Passed.
package peel

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/deps"
	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/egress"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/lockfile"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/source"
	"github.com/PatterCJ/build-onion/internal/verify"
)

const (
	SLSAProvenanceV1 = "https://slsa.dev/provenance/v1"
	CycloneDX        = "https://cyclonedx.org/bom"
	GitHubBuildType  = "https://actions.github.io/buildtypes/workflow/v1"
)

// Status grades one check.
type Status string

const (
	// Passed: the control completed and the evidence satisfies it.
	Passed Status = "PASSED"
	// Degraded: the check ran but its coverage is incomplete.
	Degraded Status = "DEGRADED"
	// Unsupported: a specific input or format could not be analyzed.
	Unsupported Status = "UNSUPPORTED"
	// Failed: trustworthy evidence could not be produced or read.
	Failed Status = "FAILED"
	// Finding: the analysis completed and found a violation.
	Finding Status = "FINDING"
	// Note: context worth reading that does not grade the artifact.
	Note Status = "NOTE"
)

// rank orders grades for the overall verdict. A finding outranks a failure:
// a confirmed problem is the more important thing to surface.
var rank = map[Status]int{Note: 0, Passed: 0, Degraded: 1, Unsupported: 1, Failed: 2, Finding: 3}

// Exit codes for each verdict, so a gate can tell them apart.
var exitCodes = map[Status]int{Passed: 0, Degraded: 3, Unsupported: 3, Finding: 4, Failed: 5}

type Result struct {
	Layer  string `json:"layer"`
	Check  string `json:"check"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	Artifact string   `json:"artifact"`
	Digest   string   `json:"digest"`
	Verdict  Status   `json:"verdict"`
	Results  []Result `json:"results"`
	// NotPerformed lists optional checks the caller did not ask for.
	NotPerformed []string `json:"notPerformed,omitempty"`
	// Packages is every package found in the artifact and its outcome.
	Packages []deps.Result `json:"packages,omitempty"`
}

// ExitCode is 0 for Passed, 3 for Degraded or Unsupported, 4 for Finding and
// 5 for Failed. allowDegraded maps Degraded and Unsupported to 0.
func (r *Report) ExitCode(allowDegraded bool) int {
	if allowDegraded && (r.Verdict == Degraded || r.Verdict == Unsupported) {
		return 0
	}
	return exitCodes[r.Verdict]
}

// OK reports whether the verdict is Passed.
func (r *Report) OK() bool { return r.Verdict == Passed }

func (r *Report) finish() {
	r.Verdict = Passed
	if len(r.Results) == 0 {
		r.Verdict = Failed
		return
	}
	for _, res := range r.Results {
		if rank[res.Status] > rank[r.Verdict] {
			r.Verdict = res.Status
		}
	}
}

func (r *Report) grade(layer, check string, st Status, detail string, a ...any) {
	r.Results = append(r.Results, Result{Layer: layer, Check: check, Status: st, Detail: fmt.Sprintf(detail, a...)})
}

// check records Passed when ok, otherwise the given grade, and returns ok.
func (r *Report) check(layer, check string, ok bool, otherwise Status, detail string, a ...any) bool {
	st := Passed
	if !ok {
		st = otherwise
	}
	r.grade(layer, check, st, detail, a...)
	return ok
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
	// Refs, if set, are the refs (globs) the verifier accepts. They're checked
	// against the provenance, whose ref comes from GitHub's signing identity,
	// independent of any policy the repository itself declares.
	Refs []string
}

// Run peels every layer and returns the graded report. It never stops early:
// a failed outer layer still lets inner layers report what they can see.
func Run(in Input) *Report {
	r := &Report{Artifact: in.Artifact, Digest: in.Digest}
	defer r.finish()
	repoURL := "https://github.com/" + in.Claim.Repository

	// seal: signatures, identities, and one run behind all of them.
	verified := map[string]*attest.Verified{}
	var invalid, otherSigners []string
	unrelated := 0
	for _, c := range in.Candidates {
		if about, known := c.About(in.Digest); known && !about {
			unrelated++
			continue
		}
		v, err := in.Verifier.Verify(c, in.Digest)
		switch {
		case err == nil:
			if _, dup := verified[v.Statement.PredicateType]; !dup {
				verified[v.Statement.PredicateType] = v
			}
		case attest.IdentityMismatch(err):
			otherSigners = append(otherSigners, c.Source)
		default:
			invalid = append(invalid, fmt.Sprintf("%s: %v", c.Source, err))
		}
	}
	relevant := len(in.Candidates) - unrelated
	r.check("seal", "bundles found", relevant > 0, Failed,
		"%d bundle(s) name this artifact%s", relevant, unrelatedNote(unrelated))
	// A bundle that names this artifact but fails cryptographic verification
	// is evidence of tampering, not missing evidence.
	r.check("seal", "no invalid bundles", len(invalid) == 0, Finding,
		"%d verified against signer %s%s", len(verified), in.Signer.SignerWorkflow, listNote(invalid))
	if len(otherSigners) > 0 {
		r.grade("seal", "bundles from other signers", Note,
			"%d validly signed bundle(s) from other identities were not used%s", len(otherSigners), listNote(otherSigners))
	}
	for _, pt := range []string{SLSAProvenanceV1, CycloneDX, inventory.PredicateType} {
		_, ok := verified[pt]
		r.check("seal", "has "+shortType(pt), ok, Failed, "%s", pt)
	}
	var runs []string
	for _, pt := range sortedKeys(verified) {
		cert := verified[pt].Certificate
		r.check("seal", shortType(pt)+" signed for claimed repo", cert.SourceRepositoryURI == repoURL, Finding,
			"certificate source repo %q, claimed %q", cert.SourceRepositoryURI, repoURL)
		if in.Claim.Commit != "" {
			r.check("seal", shortType(pt)+" signed for claimed commit", cert.SourceRepositoryDigest == in.Claim.Commit, Finding,
				"certificate commit %s, claimed %s", cert.SourceRepositoryDigest, in.Claim.Commit)
		}
		runs = append(runs, cert.RunInvocationURI)
	}
	if len(runs) > 0 {
		r.check("seal", "one run signed every layer", allEqual(runs), Finding, "run %s", strings.Join(uniq(runs), ", "))
	}

	// provenance: SLSA v1 from GitHub, signed by the security line.
	var prov provenance
	if v := verified[SLSAProvenanceV1]; v != nil && decode(r, "provenance", v.Statement.Predicate, &prov) {
		bd, rd := prov.BuildDefinition, prov.RunDetails
		r.check("provenance", "build type", bd.BuildType == GitHubBuildType, Unsupported, "%s", bd.BuildType)
		builderPrefix := "https://github.com/" + in.Signer.SignerWorkflow + "@"
		r.check("provenance", "builder is build-onion", strings.HasPrefix(rd.Builder.ID, builderPrefix), Finding, "builder.id %s", rd.Builder.ID)
		r.check("provenance", "hosted runner", bd.InternalParameters.GitHub.RunnerEnvironment == "github-hosted", Finding,
			"runner_environment %q (SLSA L3 requires a hosted build platform)", bd.InternalParameters.GitHub.RunnerEnvironment)
		r.check("provenance", "source repository", bd.ExternalParameters.Workflow.Repository == repoURL, Finding,
			"workflow repository %s", bd.ExternalParameters.Workflow.Repository)
		ref := bd.ExternalParameters.Workflow.Ref
		if len(in.Refs) == 0 {
			r.grade("provenance", "source ref", Note, "built from %s (pass --ref to require specific refs)", ref)
		} else {
			r.check("provenance", "source ref accepted", refMatches(in.Refs, ref), Finding,
				"built from %s; accepted: %s", ref, strings.Join(in.Refs, ", "))
		}
		commit := prov.sourceCommit(repoURL)
		r.check("provenance", "source commit recorded", commit != "", Failed, "resolvedDependencies gitCommit %q", commit)
		if in.Claim.Commit != "" {
			r.check("provenance", "source commit matches claim", commit == in.Claim.Commit, Finding, "provenance %s, claimed %s", commit, in.Claim.Commit)
		} else {
			in.Claim.Commit = commit
		}
	}

	// inventory: the bottom-up record binds to the same run and source.
	var inv inventory.Inventory
	haveInv := false
	if v := verified[inventory.PredicateType]; v != nil && decode(r, "inventory", v.Statement.Predicate, &inv) {
		haveInv = true
		r.check("inventory", "same source commit", inv.Source.Commit == in.Claim.Commit && in.Claim.Commit != "", Finding,
			"inventory %s, provenance %s", inv.Source.Commit, in.Claim.Commit)
		r.check("inventory", "same run", prov.RunDetails.Metadata.InvocationID == "" || sameRun(inv.Run.InvocationURL, prov.RunDetails.Metadata.InvocationID), Finding,
			"inventory %s, provenance %s", inv.Run.InvocationURL, prov.RunDetails.Metadata.InvocationID)
		out, ok := inv.Subject(in.Digest)
		r.check("inventory", "artifact is a declared output", ok, Finding, "%s %s", out.Kind, out.Name)
		r.check("inventory", "builder pinned by digest", manifest.IsPinnedImage(inv.Builder.Image), Finding, "%s", inv.Builder.Image)
		r.check("inventory", "build ran without network", inv.Build.Network == "none", Finding, "network %q", inv.Build.Network)
		r.check("inventory", "inputs locked", len(inv.Lockfiles) > 0, Finding, "%d lockfile(s), %d locked dependencies", len(inv.Lockfiles), len(inv.Dependencies))
		switch bi := inv.Build.Inputs; {
		case bi == nil:
			r.grade("inventory", "build inputs", Note, "not recorded; this inventory predates build.inputs")
		case len(bi.Patterns) == 0:
			r.grade("inventory", "build inputs", Note, "the build could read all %d tracked files; declare build.inputs to narrow it", bi.Of)
		default:
			r.grade("inventory", "build inputs", Passed, "the build saw %d of %d tracked files (%s)", bi.Files, bi.Of, strings.Join(bi.Patterns, ", "))
		}
		checkGate(r, &inv)
		checkEgress(r, &inv)
		checkVerification(r, &inv, in.Digest)
		checkPipeline(r, &inv)
		checkScans(r, &inv)
	}

	// dependencies: everything the SBOM finds in the artifact must be accounted for.
	if v := verified[CycloneDX]; v != nil && haveInv {
		checkDependencies(r, v.Statement.Predicate, &inv, in.Digest)
	}

	// source: recompute the inventory's source facts from a checkout.
	if in.SourceDir == "" {
		r.NotPerformed = append(r.NotPerformed, "source (pass --source <checkout>)")
	} else if haveInv {
		checkSource(r, in.SourceDir, &inv)
	}

	// rebuild: run the declared build again and compare.
	if !in.Rebuild {
		r.NotPerformed = append(r.NotPerformed, "local rebuild (pass --rebuild with --source)")
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
	if !r.check("gate", "gate verdict recorded", g != nil, Failed, "") {
		return
	}
	r.check("gate", "release allowed", g.Releasable && !g.Blocked, Finding, "%s", g.Reason)
	if len(g.SensitiveChange) > 0 {
		r.grade("gate", "build-sensitive change", Note, "this commit changed %s", strings.Join(g.SensitiveChange, ", "))
	}
	if len(g.OpaqueInputs) > 0 {
		r.grade("gate", "binary change the build can read", Note, "%s", strings.Join(g.OpaqueInputs, ", "))
	}
	if n := len(g.OpaqueChange) - len(g.OpaqueInputs); n > 0 {
		r.grade("gate", "binary change outside build inputs", Note, "%d file(s), not visible to the build", n)
	}
	if !g.ChangeKnown {
		// The release rules above don't depend on the diff; only this
		// context does. Tag pushes and first pushes have no diff base.
		r.grade("gate", "change set", Note, "not computed; no previous build point to diff against")
	}
}

// checkEgress grades the fetch step's network: an allow-list with every
// connection declared passes; unrestricted network is a coverage gap; any
// denied or unexplained connection is a finding.
func checkEgress(r *Report, inv *inventory.Inventory) {
	e := inv.Egress
	switch {
	case e == nil:
		r.grade("egress", "fetch network", Degraded, "not recorded; this inventory predates egress recording")
		return
	case e.Mode == egress.ModeNone:
		r.grade("egress", "fetch network", Passed, "no fetch step")
		return
	case e.Mode == egress.ModeUnrestricted:
		r.grade("egress", "fetch network", Degraded, "fetch had unrestricted network; declare dependencies.egress to restrict and record it")
		return
	case e.Mode != egress.ModeAllowList:
		r.grade("egress", "fetch network", Unsupported, "unknown egress mode %q", e.Mode)
		return
	}
	r.check("egress", "proxy pinned by digest", manifest.IsPinnedImage(e.ProxyImage), Finding, "%s", e.ProxyImage)
	if e.Summary == nil {
		r.grade("egress", "fetch connections", Failed, "allow-list mode without a connection log")
		return
	}
	hosts := map[string]bool{}
	var total int
	for _, c := range e.Summary.Connections {
		hosts[fmt.Sprintf("%s:%d", c.Host, c.Port)] = true
		total += c.Count
	}
	if err := e.Summary.CheckAgainst(e.Rules); err != nil {
		r.grade("egress", "fetch connections", Finding, "%v", err)
		return
	}
	var declared []string
	for _, rule := range e.Rules {
		declared = append(declared, fmt.Sprintf("%s:%d", rule.Host, rule.EffectivePort()))
	}
	r.grade("egress", "fetch connections", Passed, "%d connection(s) to %d destination(s), all within the allow-list (%s)",
		total, len(hosts), strings.Join(declared, ", "))
}

// checkVerification reads the security line's record: an independent rebuild
// matched the build line for this artifact.
func checkVerification(r *Report, inv *inventory.Inventory, d string) {
	v := inv.Verification
	if !r.check("verification", "security line recorded", v != nil && v.Rebuild != nil, Failed, "") {
		return
	}
	var m *verify.Match
	for i := range v.Rebuild.Outputs {
		if v.Rebuild.Outputs[i].Rebuilt == d {
			m = &v.Rebuild.Outputs[i]
		}
	}
	if m == nil {
		r.grade("verification", "independent rebuild matched", Finding, "artifact not among the rebuilt outputs")
		return
	}
	r.check("verification", "independent rebuild matched", m.Match && v.Rebuild.Matched, Finding,
		"%s %s: build line %s, rebuild %s on %s", m.Kind, m.Name, m.Staged, m.Rebuilt, v.Rebuild.Runner)
}

// checkScans lists the tools the pipeline ran and binds each to this build.
// build-onion records that a scan happened and whether it completed; it does
// not judge findings.
func checkScans(r *Report, inv *inventory.Inventory) {
	if len(inv.Pipeline.Scans) == 0 {
		r.grade("scans", "scans recorded", Note, "the pipeline recorded no scans")
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
		if !r.check("scans", sc.Name+" ran against this build", bound, Finding, "%s", detail) {
			continue
		}
		switch sc.Status {
		case inventory.ScanCompleted:
			r.grade("scans", sc.Name+" completed", Passed, "analysis completed")
		case inventory.ScanIncomplete, inventory.ScanFailed:
			r.grade("scans", sc.Name+" completed", Degraded, "%s: %s", sc.Status, sc.Coverage)
		default:
			r.grade("scans", sc.Name+" completed", Degraded, "completion not recorded")
		}
	}
}

var pinnedUse = regexp.MustCompile(`^[^@\s]+@[a-f0-9]{40}$`)

func checkPipeline(r *Report, inv *inventory.Inventory) {
	pl := inv.Pipeline
	r.check("pipeline", "builder commit recorded", len(pl.BuildOnion.Commit) == 40, Failed,
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
	if len(pl.Workflows) == 0 {
		r.grade("pipeline", "every action pinned", Failed, "no workflows recorded")
	} else {
		r.check("pipeline", "every action pinned", len(loose) == 0, Finding,
			"%d action reference(s) across %d workflow(s)%s", n, len(pl.Workflows), listNote(loose))
	}
	r.check("pipeline", "jobs inventoried", len(pl.Jobs) > 0, Degraded, "%d job(s) recorded runner and tool versions", len(pl.Jobs))
}

// checkDependencies proves every package in the artifact against what the
// build declared, in any ecosystem with a lockfile parser: each package is
// matched by name and version (and content hash where both sides carry one),
// attributed to the pinned base image by layer, recognized as vendored inside
// a declared package, or reported.
func checkDependencies(r *Report, bom json.RawMessage, inv *inventory.Inventory, d string) {
	present, err := deps.FromSBOM(bom)
	if err != nil {
		r.grade("dependencies", "SBOM readable", Failed, "%v", err)
		return
	}
	declared, local := declaredFrom(inv)
	in := deps.Input{Present: present, Declared: declared, Local: local}
	out, _ := inv.Subject(d)
	img := inv.Build.Image
	isImage := out.Kind == "oci-image" && img != nil
	if isImage {
		in.BaseLayers = img.BaseLayers
		if len(img.BaseLayers) > 0 {
			r.check("dependencies", "image built on its pinned base", hasPrefix(img.Layers, img.BaseLayers), Finding,
				"%d of %d layers are %s", len(img.BaseLayers), len(img.Layers), img.FinalBase)
		}
	}
	rep := deps.Match(in)

	// Older inventories recorded pinned bases without their layers. Their OS
	// packages can still only have come from those bases, since RUN steps had
	// no network.
	legacyBase := isImage && len(img.BaseLayers) == 0 && img.RunNetwork == "none" && len(img.BaseImages) > 0 && allPinned(img.BaseImages)

	type tally struct {
		n       int
		byKind  map[deps.Outcome]int
		problem []string
	}
	per := map[string]*tally{}
	var findings, degraded, unsupported []string
	for i, res := range rep.Results {
		if res.Outcome == deps.OSPackage && legacyBase {
			rep.Results[i].Outcome, rep.Results[i].Detail = deps.BaseImage, "pinned base (layers not recorded)"
			res = rep.Results[i]
		}
		t := per[res.Ecosystem]
		if t == nil {
			t = &tally{byKind: map[deps.Outcome]int{}}
			per[res.Ecosystem] = t
		}
		t.n++
		t.byKind[res.Outcome]++
		id := fmt.Sprintf("%s %s@%s (%s)", res.Ecosystem, res.Name, res.Version, res.Detail)
		switch res.Outcome {
		case deps.Undeclared, deps.VersionDrift, deps.HashMismatch:
			findings = append(findings, string(res.Outcome)+": "+id)
		case deps.NoVersion:
			degraded = append(degraded, id)
		case deps.OSPackage, deps.NoParser:
			unsupported = append(unsupported, id)
		}
	}
	r.Packages = rep.Results

	for _, eco := range sortedKeys(per) {
		t := per[eco]
		var parts []string
		for _, o := range []deps.Outcome{deps.HashVerified, deps.VersionVerified, deps.Vendored, deps.BaseImage, deps.Toolchain, deps.LocalPackage} {
			if t.byKind[o] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", t.byKind[o], o))
			}
		}
		if len(parts) > 0 {
			r.grade("dependencies", eco, Passed, "%d in artifact: %s", t.n, strings.Join(parts, ", "))
		}
	}
	if len(per) == 0 {
		r.grade("dependencies", "packages", Passed, "the SBOM lists no packages")
	}
	r.check("dependencies", "every package declared", len(findings) == 0, Finding, "%d violation(s)%s", len(findings), listNote(findings))
	if len(degraded) > 0 {
		r.grade("dependencies", "versions", Degraded, "%d package(s) have no version in the SBOM%s", len(degraded), listNote(degraded))
	}
	if len(unsupported) > 0 {
		r.grade("dependencies", "coverage", Unsupported, "%d package(s) can't be checked against a lockfile%s", len(unsupported), listNote(unsupported))
	}
	for _, eco := range sortedKeys(rep.NotShipped) {
		r.grade("dependencies", eco+" declared, not shipped", Note, "%d declared package(s) (plus %d dev) aren't in this artifact",
			rep.NotShipped[eco], rep.NotShippedDev[eco])
	}
}

// declaredFrom reads the declared side, including the shapes older
// inventories wrote (ecosystem "go", mainModules).
func declaredFrom(inv *inventory.Inventory) ([]lockfile.Package, []lockfile.Local) {
	declared := make([]lockfile.Package, len(inv.Dependencies))
	for i, d := range inv.Dependencies {
		if d.Ecosystem == "go" {
			d.Ecosystem = "golang"
		}
		declared[i] = d
	}
	local := append([]lockfile.Local{}, inv.Local...)
	for _, m := range inv.MainModules {
		local = append(local, lockfile.Local{Ecosystem: "golang", Name: m})
	}
	return declared, local
}

func refMatches(patterns []string, ref string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, ref); ok {
			return true
		}
	}
	return false
}

func hasPrefix(all, prefix []string) bool {
	if len(prefix) > len(all) {
		return false
	}
	for i := range prefix {
		if all[i] != prefix[i] {
			return false
		}
	}
	return true
}

func allPinned(refs []string) bool {
	for _, ref := range refs {
		if !manifest.IsPinnedImage(ref) {
			return false
		}
	}
	return true
}

func checkSource(r *Report, dir string, inv *inventory.Inventory) {
	head, err := git(dir, "rev-parse", "HEAD")
	if err != nil {
		r.grade("source", "checkout at claimed commit", Failed, "%v", err)
		return
	}
	if !r.check("source", "checkout at claimed commit", head == inv.Source.Commit, Finding, "HEAD %s, inventory %s", head, inv.Source.Commit) {
		return
	}
	if tree, err := git(dir, "rev-parse", "HEAD^{tree}"); err != nil {
		r.grade("source", "tree hash", Failed, "%v", err)
	} else {
		r.check("source", "tree hash", tree == inv.Source.Tree, Finding, "tree %s, inventory %s", tree, inv.Source.Tree)
	}
	if dirty, err := git(dir, "status", "--porcelain", "--untracked-files=no"); err != nil {
		r.grade("source", "checkout is clean", Failed, "%v", err)
	} else {
		r.check("source", "checkout is clean", dirty == "", Finding, "%s", firstLine(dirty))
	}
	if snap, err := source.Hash(dir); err != nil {
		r.grade("source", "every file matches snapshot", Failed, "%v", err)
	} else {
		r.check("source", "every file matches snapshot", snap.Digest == inv.Source.Snapshot, Finding,
			"%d files hash to %s, inventory %s", len(snap.Files), snap.Digest, inv.Source.Snapshot)
	}
	for _, f := range append([]inventory.FileRef{inv.Manifest}, inv.Lockfiles...) {
		d, err := digest.File(filepath.Join(dir, f.Path))
		if err != nil {
			r.grade("source", f.Path+" unchanged", Failed, "%v", err)
			continue
		}
		r.check("source", f.Path+" unchanged", d == f.Digest, Finding, "%s", d)
	}
}

func checkRebuild(r *Report, dir string, inv *inventory.Inventory, want string) {
	out, ok := inv.Subject(want)
	if !ok {
		r.grade("rebuild", "reproduces artifact", Failed, "artifact is not an output in the inventory")
		return
	}
	if out.Kind != "file" {
		r.grade("rebuild", "reproduces artifact", Unsupported,
			"local rebuild supports file outputs; the security line's rebuild covered this %s", out.Kind)
		return
	}
	m, _, err := manifest.Load(filepath.Join(dir, inv.Manifest.Path))
	if err != nil {
		r.grade("rebuild", "reproduces artifact", Failed, "load manifest: %v", err)
		return
	}
	got, err := Rebuild(dir, inv.Manifest.Path, m, out.Name)
	if err != nil {
		r.grade("rebuild", "reproduces artifact", Failed, "%v", err)
		return
	}
	r.check("rebuild", "reproduces artifact", got == want, Finding, "rebuilt %s, attested %s", got, want)
}

// decode grades an unreadable predicate as Failed: the evidence exists but
// can't be used, which must never pass silently.
func decode(r *Report, layer string, raw json.RawMessage, v any) bool {
	if err := json.Unmarshal(raw, v); err != nil {
		r.grade(layer, "predicate parses", Failed, "%v", err)
		return false
	}
	return true
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

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
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

func unrelatedNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d bundle(s) for other artifacts ignored)", n)
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

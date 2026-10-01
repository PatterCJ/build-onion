// Package peel runs the reverse check. Starting from an artifact digest it
// removes one layer at a time — seal, provenance, inventory, gate,
// verification, pipeline, scans, dependencies, upstream, differential,
// source, rebuild — and checks that each layer agrees with the one beneath it
// and with what the caller claims the artifact is.
//
// Every check is graded, and the report's verdict is the worst grade present.
// Incomplete evidence is never reported as clean: a check that could not be
// performed is Failed, Degraded or Unsupported, never Passed.
package peel

import (
	"bytes"
	"encoding/json"
	"errors"
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
	"github.com/PatterCJ/build-onion/internal/gate"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/lockfile"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/policy"
	repoid "github.com/PatterCJ/build-onion/internal/repo"
	sigs "github.com/PatterCJ/build-onion/internal/signer"
	"github.com/PatterCJ/build-onion/internal/source"
	"github.com/PatterCJ/build-onion/internal/tagsig"
	"github.com/PatterCJ/build-onion/internal/trust"
	"github.com/PatterCJ/build-onion/internal/upstream"
	"github.com/PatterCJ/build-onion/internal/verify"
	"golang.org/x/crypto/ssh"
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
	// Upstream is every locked package's registry check, as sealed.
	Upstream []upstream.Result `json:"upstream,omitempty"`

	inv *inventory.Inventory // the verified inventory, for Differential
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
	// Trust, if set, lists the build-onion releases allowed to have sealed
	// the artifact.
	Trust *trust.File
}

// Run peels every layer and returns the graded report. It never stops early:
// a failed outer layer still lets inner layers report what they can see.
func Run(in Input) *Report {
	r := &Report{Artifact: in.Artifact, Digest: in.Digest}
	defer r.finish()
	repoURL, err := repoid.URL(in.Claim.Repository)
	if err != nil {
		r.grade("seal", "claimed repository", Failed, "%v", err)
	}

	// seal: signatures, identities, and one run behind all of them.
	var all []*attest.Verified
	var invalid, otherSigners, untrustedKeys []string
	unrelated := 0
	for _, c := range in.Candidates {
		if about, known := c.About(in.Digest); known && !about {
			unrelated++
			continue
		}
		v, err := in.Verifier.Verify(c, in.Digest)
		switch {
		case err == nil:
			all = append(all, v)
		case attest.IdentityMismatch(err):
			otherSigners = append(otherSigners, c.Source)
		case errors.As(err, new(*attest.UntrustedKey)):
			untrustedKeys = append(untrustedKeys, c.Source)
		default:
			invalid = append(invalid, fmt.Sprintf("%s: %v", c.Source, err))
		}
	}
	verified, others := chooseRun(all, in)
	relevant := len(in.Candidates) - unrelated
	r.check("seal", "bundles found", relevant > 0, Failed,
		"%d bundle(s) name this artifact%s", relevant, unrelatedNote(unrelated))
	// A bundle that names this artifact but fails cryptographic verification
	// is evidence of tampering, not missing evidence.
	against := "signer " + in.Signer.SignerWorkflow
	for _, v := range verified {
		if v.Key != "" {
			against = "the trust file's keys"
		}
	}
	r.check("seal", "no invalid bundles", len(invalid) == 0, Finding,
		"%d verified against %s%s", len(verified), against, listNote(invalid))
	if len(others) > 0 {
		r.grade("seal", "other sealing runs", Note,
			"this digest was also sealed by %d other run(s), not used: %s", len(others), strings.Join(others, ", "))
	}
	if len(untrustedKeys) > 0 {
		r.grade("seal", "bundles signed with untrusted keys", Note,
			"%d bundle(s) signed with a key the trust file doesn't list were not checked%s", len(untrustedKeys), listNote(untrustedKeys))
	}
	if len(otherSigners) > 0 {
		r.grade("seal", "bundles from other signers", Note,
			"%d validly signed bundle(s) from other identities were not used%s", len(otherSigners), listNote(otherSigners))
	}
	for _, pt := range []string{SLSAProvenanceV1, CycloneDX, inventory.PredicateType} {
		_, ok := verified[pt]
		r.check("seal", "has "+shortType(pt), ok, Failed, "%s", pt)
	}
	// Key-signed layers name a trusted key instead of a CI workload, and
	// carry no certificate to check repository, commit or run against.
	keys, certs := map[string]bool{}, 0
	for _, v := range verified {
		if v.Key != "" {
			keys[v.Key] = true
		} else {
			certs++
		}
	}
	keySigned := len(keys) > 0
	if keySigned {
		checkKeySeal(r, keys, certs)
	}
	var runs []string
	for _, pt := range sortedKeys(verified) {
		if keySigned {
			break
		}
		cert := verified[pt].Certificate
		r.check("seal", shortType(pt)+" signed for claimed repo", strings.EqualFold(cert.SourceRepositoryURI, repoURL), Finding,
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
	// The builder commit comes from the certificate: the exact commit of the
	// signing workflow, however the caller referenced it.
	var builders []string
	for _, pt := range sortedKeys(verified) {
		if !keySigned {
			builders = append(builders, verified[pt].Certificate.BuildSignerDigest)
		}
	}
	builders = uniq(builders)
	builderCommit := ""
	if len(builders) > 0 {
		if r.check("seal", "one builder commit signed every layer", len(builders) == 1 && builders[0] != "", Finding,
			"build-onion %s", strings.Join(builders, ", ")) {
			builderCommit = builders[0]
		}
		signerRepo := signerRepository(in.Signer.SignerWorkflow)
		switch {
		case in.Trust == nil:
			r.NotPerformed = append(r.NotPerformed, "trusted builder release (pass --trust <file>)")
		case builderCommit != "":
			rel, ok := in.Trust.Trusted(signerRepo, builderCommit)
			detail := fmt.Sprintf("%s %s is not a release in the trust file", signerRepo, builderCommit)
			if ok {
				detail = fmt.Sprintf("%s %s (%s)", signerRepo, rel.Tag, builderCommit)
			}
			r.check("seal", "builder is a trusted release", ok, Finding, "%s", detail)
		}
	}

	// provenance: SLSA v1 from GitHub, signed by the security line, or
	// from a GitLab pipeline, signed by a trusted key.
	var prov provenance
	if v := verified[SLSAProvenanceV1]; v != nil && decode(r, "provenance", v.Statement.Predicate, &prov) {
		bd, rd := prov.BuildDefinition, prov.RunDetails
		switch {
		case bd.BuildType == GitHubBuildType:
			r.grade("provenance", "build type", Passed, "%s", bd.BuildType)
			builderPrefix := "https://github.com/" + in.Signer.SignerWorkflow + "@"
			r.check("provenance", "builder is build-onion", strings.HasPrefix(rd.Builder.ID, builderPrefix), Finding, "builder.id %s", rd.Builder.ID)
			r.check("provenance", "hosted runner", bd.InternalParameters.GitHub.RunnerEnvironment == "github-hosted", Finding,
				"runner_environment %q (SLSA L3 requires a hosted build platform)", bd.InternalParameters.GitHub.RunnerEnvironment)
		case bd.BuildType == sigs.GitLabBuildType && keySigned:
			gl := bd.InternalParameters.GitLab
			r.grade("provenance", "build type", Passed, "%s", bd.BuildType)
			// Only protected refs should be able to reach the signing key.
			r.check("provenance", "protected ref", gl.RefProtected == "true", Finding,
				"%s (protected: %s)", bd.ExternalParameters.Workflow.Ref, orNone(gl.RefProtected))
			r.grade("provenance", "pipeline definition", Note, "%s", bd.ExternalParameters.Workflow.Path)
			r.grade("provenance", "runner", Note, "%s, as the sealing job reported it", orNone(gl.RunnerDescription))
		case bd.BuildType == sigs.GitLabBuildType:
			r.grade("provenance", "build type", Unsupported, "%s: GitLab provenance is accepted only from a trusted key", bd.BuildType)
		default:
			r.grade("provenance", "build type", Unsupported, "%s", bd.BuildType)
		}
		r.check("provenance", "source repository", strings.EqualFold(bd.ExternalParameters.Workflow.Repository, repoURL), Finding,
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
		r.inv = &inv
		// A key may seal for many repositories; the record says which one.
		r.check("inventory", "claimed repository", repoURL != "" && repoid.Same(inv.Source.Repository, repoURL), Finding,
			"inventory %s, claimed %s", inv.Source.Repository, repoURL)
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
		checkInstallScripts(r, &inv)
		checkGate(r, &inv)
		if in.Trust != nil {
			checkAppSigner(r, in.Trust, in.Claim.Repository, &inv)
		}
		checkEgress(r, &inv)
		checkVerification(r, &inv, in.Digest)
		checkPipeline(r, &inv)
		if builderCommit != "" && inv.Pipeline.BuildOnion.Commit != "" {
			r.check("pipeline", "recorded builder is the signer", inv.Pipeline.BuildOnion.Commit == builderCommit, Finding,
				"inventory build-onion %s, certificate %s", inv.Pipeline.BuildOnion.Commit, builderCommit)
		}
		checkScans(r, &inv)
	}

	// dependencies: everything the SBOM finds in the artifact must be accounted for.
	if v := verified[CycloneDX]; v != nil && haveInv {
		checkDependencies(r, v.Statement.Predicate, &inv, in.Digest)
	}
	// upstream: every locked package against its public registry.
	if haveInv {
		checkUpstream(r, &inv)
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
			GitLab struct {
				RefProtected      string `json:"ref_protected"`
				RunnerDescription string `json:"runner_description"`
			} `json:"gitlab"`
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
		if p := "git+" + repoURL + "@"; len(d.URI) > len(p) && strings.EqualFold(d.URI[:len(p)], p) {
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
	if g.Mode == policy.ModeReport {
		r.grade("gate", "policy mode", Note, "report: the gate and fetch recorded what they would block instead of blocking")
	}
	if len(g.WouldBlock) > 0 {
		r.grade("gate", "would have been blocked", Finding, "%d reason(s) in report mode%s", len(g.WouldBlock), listNote(g.WouldBlock))
	}
	if g.TagSigner != "" {
		r.grade("gate", "release tag signed", Passed, "by %s", g.TagSigner)
	}
	if len(g.SensitiveChange) > 0 {
		r.grade("gate", "build-sensitive change", Note, "this commit changed %s", strings.Join(g.SensitiveChange, ", "))
	}
	if rc := g.Repository; rc != nil {
		checkRepoProtections(r, rc)
	} else {
		r.grade("gate", "repository protections", Note, "not required by the policy")
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

// checkAppSigner holds the artifact's release tag to the signers the trust
// file lists for its repository. A repository the trust file doesn't list is
// noted, not graded.
func checkAppSigner(r *Report, t *trust.File, repo string, inv *inventory.Inventory) {
	app := t.App(repo)
	if app == nil {
		r.grade("gate", "release tag signer trusted", Note, "the trust file has no apps entry for %s; its tag signers aren't pinned", repo)
		return
	}
	signer := ""
	if inv.Gate != nil {
		signer = inv.Gate.TagSigner
	}
	allowed, err := tagsig.Keys(app.TagSigners)
	if err != nil {
		r.grade("gate", "release tag signer trusted", Failed, "%v", err)
		return
	}
	var fps []string
	for _, k := range allowed {
		fps = append(fps, ssh.FingerprintSHA256(k))
	}
	if signer == "" {
		ref := ""
		if inv.Gate != nil {
			ref = inv.Gate.Context.Ref
		}
		r.grade("gate", "release tag signer trusted", Finding, "%s requires a tag signed by %s; this was built from %s with no verified tag signature",
			repo, strings.Join(fps, ", "), orNone(ref))
		return
	}
	got, _, _, _, err := ssh.ParseAuthorizedKey([]byte(signer))
	if err != nil {
		r.grade("gate", "release tag signer trusted", Failed, "recorded signer unreadable: %v", err)
		return
	}
	for _, k := range allowed {
		if bytes.Equal(k.Marshal(), got.Marshal()) {
			r.grade("gate", "release tag signer trusted", Passed, "signed by %s, allowed for %s", ssh.FingerprintSHA256(got), repo)
			return
		}
	}
	r.grade("gate", "release tag signer trusted", Finding, "signed by %s; the trust file allows %s for %s",
		ssh.FingerprintSHA256(got), strings.Join(fps, ", "), repo)
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
	case e.Mode == egress.ModeRecord:
		checkEgressSource(r, e, inv)
		checkRecordedEgress(r, e)
		return
	case e.Mode != egress.ModeAllowList:
		r.grade("egress", "fetch network", Unsupported, "unknown egress mode %q", e.Mode)
		return
	}
	r.check("egress", "proxy pinned by digest", manifest.IsPinnedImage(e.ProxyImage), Finding, "%s", e.ProxyImage)
	checkEgressSource(r, e, inv)
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

// checkEgressSource requires the egress record, when it names the source it
// fetched for, to name this build's.
func checkEgressSource(r *Report, e *egress.Record, inv *inventory.Inventory) {
	if e.Snapshot == "" {
		return
	}
	r.check("egress", "fetch ran on this source", e.Snapshot == inv.Source.Snapshot, Finding,
		"egress record %s, inventory %s", e.Snapshot, inv.Source.Snapshot)
}

// checkInstallScripts notes locked packages that run code during fetch, and
// whether the fetch step turned that off. Whether to allow it is a policy
// decision (blockInstallScripts), so this is context, not a grade.
func checkInstallScripts(r *Report, inv *inventory.Inventory) {
	scripts := lockfile.InstallScripts(inv.Dependencies)
	if len(scripts) == 0 {
		return
	}
	if inv.Egress != nil && inv.Egress.InstallScriptsDisabled {
		r.grade("inventory", "dependency install scripts", Note, "%d package(s) have install scripts; policy turned them off for the whole fetch step%s", len(scripts), listNote(scripts))
		return
	}
	if lockfile.ScriptsDisabled(inv.Build.Fetch, inv.Build.FetchEnv) {
		r.grade("inventory", "dependency install scripts", Note, "%d package(s) have install scripts; the fetch command asks npm not to run them%s", len(scripts), listNote(scripts))
		return
	}
	r.grade("inventory", "dependency install scripts", Note, "%d package(s) ran install scripts during fetch%s", len(scripts), listNote(scripts))
}

// checkRecordedEgress grades a report-mode fetch: the proxy recorded every
// connection instead of denying those outside the allow-list. A connection
// enforce mode would have denied is a finding; with no allow-list at all,
// fetch was in effect unrestricted (degraded), and the allow-list that
// covers what it reached is shown.
func checkRecordedEgress(r *Report, e *egress.Record) {
	r.check("egress", "proxy pinned by digest", manifest.IsPinnedImage(e.ProxyImage), Finding, "%s", e.ProxyImage)
	if e.Summary == nil {
		r.grade("egress", "fetch connections", Failed, "report mode without a connection log")
		return
	}
	var outside, proposed []string
	for _, c := range e.Summary.Connections {
		if !c.Allowed {
			outside = append(outside, fmt.Sprintf("%s:%d denied (%s)", c.Host, c.Port, c.Reason))
		} else if _, ok := egress.Match(e.Rules, c.Host, c.Port); !ok {
			outside = append(outside, fmt.Sprintf("%s:%d", c.Host, c.Port))
		}
	}
	for _, p := range e.Summary.Proposed() {
		proposed = append(proposed, fmt.Sprintf("%s:%d", p.Host, p.EffectivePort()))
	}
	switch {
	case len(e.Rules) == 0:
		r.grade("egress", "fetch network", Degraded, "report mode with no allow-list: fetch could reach any host")
	case len(outside) > 0:
		r.grade("egress", "fetch connections", Finding, "report mode: %d connection(s) enforce mode would have denied%s", len(outside), listNote(outside))
	default:
		r.grade("egress", "fetch connections", Passed, "report mode: every connection was within the allow-list")
	}
	r.grade("egress", "allow-list for what fetch reached", Note, "%s", orNone(strings.Join(proposed, ", ")))
}

// checkRepoProtections reports what the gate verified about the repository.
// The gate blocks a build when a requirement fails, so a sealed inventory
// should only ever show passing checks; anything else is a finding.
func checkRepoProtections(r *Report, rc *gate.RepoCheck) {
	if !r.check("gate", "repository protections", len(rc.Problems) == 0, Finding, "%s", strings.Join(rc.Problems, "; ")) {
		return
	}
	if len(rc.Rules) > 0 {
		review := "no code-owner review"
		if rc.CodeOwnerReview {
			review = "code-owner review"
		}
		r.grade("gate", "branch rules", Passed, "%s: %d approval(s), %s; rules %s", rc.Branch, rc.Approvals, review, strings.Join(rc.Rules, ", "))
	}
	if rc.CodeOwnersFile != "" {
		r.grade("gate", "code owners", Passed, "%s owns all %d build-configuration file(s)", rc.CodeOwnersFile, rc.OwnedSensitive)
	}
	if rc.TagOnDefault != nil {
		r.grade("gate", "tag on default branch", Passed, "tagged commit is on %s", rc.Branch)
	}
}

// checkVerification reads the security line's record: an independent rebuild
// matched the build line for this artifact.
func checkVerification(r *Report, inv *inventory.Inventory, d string) {
	v := inv.Verification
	if (v == nil || v.Rebuild == nil) && len(inv.Chain) > 0 {
		checkChain(r, inv)
		r.grade("verification", "independent rebuild", Degraded,
			"not performed: a single-pipeline build. Its phase records show every phase consumed exactly what the previous one produced and the outputs are the ones recorded, so nothing was swapped between phases. They can't show a phase computed the right result: a compromised build step records its own wrong output consistently, and only a rebuild on separate infrastructure detects that")
		return
	}
	if len(inv.Chain) > 0 {
		checkChain(r, inv)
	}
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

// checkChain re-verifies a single-pipeline build's phase records against
// the inventory's own facts.
func checkChain(r *Report, inv *inventory.Inventory) {
	if err := inventory.CheckChain(inv, inv.Chain); err != nil {
		r.grade("verification", "phase records", Finding, "%v", firstLine(err.Error()))
		return
	}
	var steps []string
	for _, l := range inv.Chain {
		steps = append(steps, l.Step)
	}
	r.grade("verification", "phase records", Passed, "%s: every hand-off matched, run %s", strings.Join(steps, " → "), inv.Chain[0].Run)
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

// checkUpstream grades the security line's registry check. Bytes the
// registry doesn't publish, or provenance that fails verification, are
// findings; a package with no provenance is not, since most publish none.
func checkUpstream(r *Report, inv *inventory.Inventory) {
	rec := inv.Upstream
	if rec == nil {
		if len(inv.Dependencies) > 0 {
			r.grade("upstream", "registry check", Note, "not recorded (sealed before build-onion checked registries)")
		}
		return
	}
	if err := inventory.CheckUpstream(inv.Lockfiles, inv.Dependencies, rec); err != nil {
		r.grade("upstream", "record covers the lockfiles", Failed, "%v", firstLine(err.Error()))
		return
	}
	r.Upstream = rec.Results
	if len(rec.Results) == 0 {
		r.grade("upstream", "packages", Passed, "no locked packages")
		return
	}
	per := map[string]map[string]int{}
	var findings, errs, unchecked []string
	repos := map[string]bool{}
	for _, res := range rec.Results {
		if per[res.Ecosystem] == nil {
			per[res.Ecosystem] = map[string]int{}
		}
		per[res.Ecosystem][res.Outcome]++
		id := fmt.Sprintf("%s %s@%s", res.Ecosystem, res.Name, res.Version)
		switch res.Outcome {
		case upstream.Mismatch, upstream.Invalid:
			findings = append(findings, fmt.Sprintf("%s: %s (%s)", res.Outcome, id, res.Detail))
		case upstream.Error:
			errs = append(errs, fmt.Sprintf("%s (%s)", id, res.Detail))
		case upstream.NotFound, upstream.Unhashed:
			unchecked = append(unchecked, fmt.Sprintf("%s (%s)", id, res.Outcome))
		}
		for _, a := range res.Attestations {
			repos[a.Repository] = true
		}
	}
	for _, eco := range sortedKeys(per) {
		var parts []string
		n := 0
		for _, o := range []string{upstream.Attested, upstream.Logged, upstream.Published, upstream.Unhashed, upstream.NotFound, upstream.Mismatch, upstream.Invalid, upstream.Error} {
			if c := per[eco][o]; c > 0 {
				n += c
				parts = append(parts, fmt.Sprintf("%d %s", c, o))
			}
		}
		st := Passed
		if per[eco][upstream.Attested]+per[eco][upstream.Logged]+per[eco][upstream.Published] == 0 {
			st = Note
		}
		r.grade("upstream", eco, st, "%d locked: %s", n, strings.Join(parts, ", "))
	}
	r.check("upstream", "locked bytes are the published bytes", len(findings) == 0, Finding, "%d problem(s)%s", len(findings), listNote(findings))
	if len(errs) > 0 {
		r.grade("upstream", "registries reachable", Degraded, "%d package(s) couldn't be checked%s", len(errs), listNote(errs))
	}
	if len(unchecked) > 0 {
		r.grade("upstream", "not comparable", Note, "%d package(s) not on a public registry or without a locked hash%s", len(unchecked), listNote(unchecked))
	}
	if len(repos) > 0 {
		r.grade("upstream", "provenance", Note, "%d attested package(s) built by %d source repositories; checked %s", countAttested(rec), len(repos), rec.CheckedAt)
	}
}

func countAttested(rec *upstream.Record) int {
	n := 0
	for _, res := range rec.Results {
		if res.Outcome == upstream.Attested {
			n++
		}
	}
	return n
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

// checkKeySeal grades a run sealed with an enterprise key. The key verifier
// accepts only keys the trust file lists, so a verified bundle was signed
// by a trusted key.
func checkKeySeal(r *Report, keys map[string]bool, certs int) {
	names := sortedKeys(keys)
	r.check("seal", "one key signed every layer", len(names) == 1 && certs == 0, Finding,
		"%s%s", strings.Join(names, ", "), map[bool]string{true: "", false: fmt.Sprintf(" (and %d layer(s) signed with a certificate)", certs)}[certs == 0])
	r.grade("seal", "signed by a trusted key", Passed, "%s (from the trust file)", strings.Join(names, ", "))
	r.grade("seal", "key signing", Note, "no certificate or transparency log: the key is the signer's identity, and repository, commit and run come from the signed records")
}

// chooseRun picks the bundles of one sealing run. A reproducible build can
// seal the same digest in several runs (a release and its re-release); the
// run checked is the one matching the claim: the claimed commit, then an
// accepted ref, then a trusted builder, then the most complete set, then the
// newest run. Bundles from different runs are never mixed.
func chooseRun(all []*attest.Verified, in Input) (map[string]*attest.Verified, []string) {
	byRun := map[string]map[string]*attest.Verified{}
	add := func(run string, v *attest.Verified) {
		if byRun[run] == nil {
			byRun[run] = map[string]*attest.Verified{}
		}
		if _, dup := byRun[run][v.Statement.PredicateType]; !dup {
			byRun[run][v.Statement.PredicateType] = v
		}
	}
	// A key-signed bundle has no certificate naming its run; provenance and
	// inventory name it in their signed content. A record that names no run
	// (an SBOM describes bytes, not a run) may pair with any run of its key.
	var unattached []*attest.Verified
	for _, v := range all {
		switch {
		case v.Key == "":
			add(v.Certificate.RunInvocationURI, v)
		case recordRun(v) != "":
			add("key "+v.Key+" "+recordRun(v), v)
		default:
			unattached = append(unattached, v)
		}
	}
	for _, v := range unattached {
		attached := false
		for run := range byRun {
			if strings.HasPrefix(run, "key "+v.Key+" ") {
				add(run, v)
				attached = true
			}
		}
		if !attached {
			add("key "+v.Key, v)
		}
	}
	if len(byRun) == 0 {
		return map[string]*attest.Verified{}, nil
	}
	score := func(run string) []int {
		set := byRun[run]
		var any *attest.Verified
		for _, v := range set {
			any = v
		}
		b := func(ok bool) int {
			if ok {
				return 1
			}
			return 0
		}
		if any.Key != "" {
			// The claim is matched against the signed records; a verified
			// key is trusted.
			commit := ""
			for _, v := range set {
				if c := recordCommit(v); c != "" {
					commit = c
				}
			}
			return []int{b(in.Claim.Commit == "" || commit == in.Claim.Commit), 1, 1, len(set), runNumber(run)}
		}
		cert := any.Certificate
		trusted := false
		if in.Trust != nil {
			_, trusted = in.Trust.Trusted(signerRepository(in.Signer.SignerWorkflow), cert.BuildSignerDigest)
		}
		return []int{
			b(in.Claim.Commit == "" || cert.SourceRepositoryDigest == in.Claim.Commit),
			b(len(in.Refs) == 0 || refMatches(in.Refs, cert.SourceRepositoryRef)),
			b(trusted),
			len(set),
			runNumber(run),
		}
	}
	best := ""
	var bestScore []int
	for _, run := range sortedKeys(byRun) {
		sc := score(run)
		if best == "" || greater(sc, bestScore) {
			best, bestScore = run, sc
		}
	}
	var others []string
	for _, run := range sortedKeys(byRun) {
		if run != best {
			others = append(others, run)
		}
	}
	return byRun[best], others
}

// recordRun is the run a signed record names: SLSA provenance's invocation,
// or the inventory's.
func recordRun(v *attest.Verified) string {
	var p struct {
		RunDetails struct {
			Metadata struct {
				InvocationID string `json:"invocationId"`
			} `json:"metadata"`
		} `json:"runDetails"`
		Run struct {
			InvocationURL string `json:"invocationUrl"`
		} `json:"run"`
	}
	if json.Unmarshal(v.Statement.Predicate, &p) != nil {
		return ""
	}
	if p.RunDetails.Metadata.InvocationID != "" {
		return strings.TrimSuffix(p.RunDetails.Metadata.InvocationID, "/")
	}
	return strings.TrimSuffix(p.Run.InvocationURL, "/")
}

// recordCommit is the source commit a signed record names.
func recordCommit(v *attest.Verified) string {
	var p struct {
		BuildDefinition struct {
			ResolvedDependencies []struct {
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		Source struct {
			Commit string `json:"commit"`
		} `json:"source"`
	}
	if json.Unmarshal(v.Statement.Predicate, &p) != nil {
		return ""
	}
	if p.Source.Commit != "" {
		return p.Source.Commit
	}
	for _, d := range p.BuildDefinition.ResolvedDependencies {
		if c := d.Digest["gitCommit"]; c != "" {
			return c
		}
	}
	return ""
}

// runNumber is the run ID in a GitHub Actions run URL, so newer runs sort
// higher; 0 if there is none.
func runNumber(url string) int {
	m := runIDRe.FindStringSubmatch(url)
	if m == nil {
		return 0
	}
	n := 0
	fmt.Sscan(m[1], &n)
	return n
}

var runIDRe = regexp.MustCompile(`/actions/runs/([0-9]+)`)

func greater(a, b []int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}

// signerRepository is OWNER/REPO of OWNER/REPO/.github/workflows/file.yml.
func signerRepository(workflow string) string {
	parts := strings.SplitN(workflow, "/", 3)
	if len(parts) < 2 {
		return workflow
	}
	return parts[0] + "/" + parts[1]
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

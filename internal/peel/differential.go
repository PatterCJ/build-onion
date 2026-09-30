package peel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/lockfile"
	"github.com/PatterCJ/build-onion/internal/upstream"
)

// Differential compares a verified artifact with a verified baseline, usually
// the previous release, and adds a "differential" section to r. Changes are
// notes: the release process decides whether they were intended. The
// exception is a dependency whose provenance was lost, or now comes from a
// different source repository, workflow or identity provider, which is a
// finding unless acceptSignerChanges.
func Differential(r, base *Report, acceptSignerChanges bool) {
	defer r.finish()
	const layer = "differential"
	switch {
	case r.inv == nil:
		r.grade(layer, "baseline compared", Degraded, "this artifact's inventory didn't verify; nothing to compare")
		return
	case base.inv == nil || rank[base.Verdict] > rank[Degraded]:
		r.grade(layer, "baseline verifies", Degraded, "baseline %s is %s; differential not performed", base.Artifact, base.Verdict)
		return
	}
	cur, old := r.inv, base.inv
	if cur.Source.Commit == old.Source.Commit {
		r.grade(layer, "baseline", Note, "%s is the same commit %s; nothing to compare", base.Artifact, short(cur.Source.Commit))
		return
	}
	r.grade(layer, "baseline", Passed, "%s, built from %s (%s)", base.Artifact, short(old.Source.Commit), base.Verdict)

	signerChange := Finding
	if acceptSignerChanges {
		signerChange = Note
	}
	compareSigners(r, layer, old.Upstream, cur.Upstream, signerChange)
	compareDependencies(r, layer, old, cur)
	compareBuild(r, layer, old, cur)
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

// signers is who built one package's archives, keyed by package without
// version: a new release of a dependency should come from the same place.
type signers struct {
	attested bool
	checked  bool // outcome says anything about provenance (not an error)
	ids      map[string]bool
	version  string
}

func signersByPackage(rec *upstream.Record) map[string]*signers {
	out := map[string]*signers{}
	if rec == nil {
		return out
	}
	for _, res := range rec.Results {
		k := res.Ecosystem + ":" + lockfile.Normalize(res.Ecosystem, res.Name)
		s := out[k]
		if s == nil {
			s = &signers{ids: map[string]bool{}, checked: true}
			out[k] = s
		}
		s.version = res.Version
		if res.Outcome == upstream.Error {
			s.checked = false
		}
		if res.Outcome == upstream.Attested {
			s.attested = true
		}
		for _, a := range res.Attestations {
			wf, _, _ := strings.Cut(a.Workflow, "@") // the ref changes every release
			s.ids[a.Issuer+" "+a.Repository+" "+wf] = true
		}
	}
	return out
}

func compareSigners(r *Report, layer string, old, cur *upstream.Record, changed Status) {
	if old == nil || cur == nil {
		if cur != nil {
			r.grade(layer, "dependency signers", Note, "the baseline predates upstream checks; signers not compared")
		}
		return
	}
	before, after := signersByPackage(old), signersByPackage(cur)
	var lost, moved, gained []string
	for _, k := range sortedKeys(after) {
		a, b := after[k], before[k]
		if b == nil || !a.checked || !b.checked {
			continue
		}
		switch {
		case b.attested && !a.attested:
			lost = append(lost, fmt.Sprintf("%s %s→%s (was %s)", k, b.version, a.version, strings.Join(sortedKeys(b.ids), ", ")))
		case !b.attested && a.attested:
			gained = append(gained, k)
		case a.attested && !sameKeys(a.ids, b.ids):
			moved = append(moved, fmt.Sprintf("%s %s→%s: %s → %s", k, b.version, a.version,
				strings.Join(sortedKeys(b.ids), ", "), strings.Join(sortedKeys(a.ids), ", ")))
		}
	}
	attested := 0
	for _, s := range after {
		if s.attested {
			attested++
		}
	}
	if len(lost) == 0 && len(moved) == 0 {
		r.grade(layer, "dependency signers", Passed, "%d attested package(s); none lost provenance or changed who builds them", attested)
	}
	if len(lost) > 0 {
		r.grade(layer, "provenance lost", changed, "%d package(s) published with provenance before, without it now%s", len(lost), listNote(lost))
	}
	if len(moved) > 0 {
		r.grade(layer, "signer changed", changed, "%d package(s) now built by a different repository, workflow or identity provider%s", len(moved), listNote(moved))
	}
	if len(gained) > 0 {
		r.grade(layer, "provenance gained", Note, "%d package(s) now publish provenance%s", len(gained), listNote(gained))
	}
}

func compareDependencies(r *Report, layer string, old, cur *inventory.Inventory) {
	versions := func(inv *inventory.Inventory) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for _, p := range inv.Dependencies {
			eco := p.Ecosystem
			if eco == "go" {
				eco = "golang"
			}
			k := eco + ":" + lockfile.Normalize(eco, p.Name)
			if out[k] == nil {
				out[k] = map[string]bool{}
			}
			out[k][p.Version] = true
		}
		return out
	}
	before, after := versions(old), versions(cur)
	var added, removed, changed []string
	for _, k := range sortedKeys(after) {
		switch b := before[k]; {
		case b == nil:
			added = append(added, k+"@"+strings.Join(sortedKeys(after[k]), ","))
		case !sameKeys(b, after[k]):
			changed = append(changed, fmt.Sprintf("%s %s→%s", k, strings.Join(sortedKeys(b), ","), strings.Join(sortedKeys(after[k]), ",")))
		}
	}
	for _, k := range sortedKeys(before) {
		if after[k] == nil {
			removed = append(removed, k)
		}
	}
	if len(added)+len(removed)+len(changed) == 0 {
		r.grade(layer, "dependencies", Note, "unchanged (%d locked packages)", len(after))
		return
	}
	if len(added) > 0 {
		r.grade(layer, "dependencies added", Note, "%d%s", len(added), listNote(added))
	}
	if len(changed) > 0 {
		r.grade(layer, "dependency versions changed", Note, "%d%s", len(changed), listNote(changed))
	}
	if len(removed) > 0 {
		r.grade(layer, "dependencies removed", Note, "%d%s", len(removed), listNote(removed))
	}
}

// compareBuild lists what changed in how the artifact was built.
func compareBuild(r *Report, layer string, old, cur *inventory.Inventory) {
	var changes []string
	diff := func(what, a, b string) {
		if a != b {
			changes = append(changes, fmt.Sprintf("%s: %s → %s", what, orNone(a), orNone(b)))
		}
	}
	diff("builder", old.Builder.Image, cur.Builder.Image)
	diff("manifest", old.Manifest.Digest, cur.Manifest.Digest)
	diff("fetch command", old.Build.Fetch, cur.Build.Fetch)
	diff("build command", old.Build.Run, cur.Build.Run)
	diff("build env", envString(old.Build.Env), envString(cur.Build.Env))
	lockDigests := func(inv *inventory.Inventory) map[string]string {
		m := map[string]string{}
		for _, l := range inv.Lockfiles {
			m[l.Path] = l.Digest
		}
		return m
	}
	ol, cl := lockDigests(old), lockDigests(cur)
	for _, p := range unionKeys(ol, cl) {
		diff("lockfile "+p, ol[p], cl[p])
	}
	if old.Build.Inputs != nil && cur.Build.Inputs != nil {
		diff("build inputs", strings.Join(old.Build.Inputs.Patterns, " "), strings.Join(cur.Build.Inputs.Patterns, " "))
	}
	oi, ci := old.Build.Image, cur.Build.Image
	switch {
	case oi != nil && ci != nil:
		diff("Dockerfile", oi.Dockerfile.Digest, ci.Dockerfile.Digest)
		diff("base images", strings.Join(oi.BaseImages, " "), strings.Join(ci.BaseImages, " "))
	case oi != nil || ci != nil:
		changes = append(changes, "image output added or removed")
	}
	if old.Egress != nil && cur.Egress != nil {
		diff("egress", egressString(old), egressString(cur))
	}
	diff("build-onion", old.Pipeline.BuildOnion.Commit, cur.Pipeline.BuildOnion.Commit)
	oa, ca := actionSet(old), actionSet(cur)
	if !sameKeys(oa, ca) {
		var add, rm []string
		for _, a := range sortedKeys(ca) {
			if !oa[a] {
				add = append(add, a)
			}
		}
		for _, a := range sortedKeys(oa) {
			if !ca[a] {
				rm = append(rm, a)
			}
		}
		changes = append(changes, fmt.Sprintf("workflow actions: +%s -%s", orNone(strings.Join(add, " ")), orNone(strings.Join(rm, " "))))
	}
	if old.Gate != nil && cur.Gate != nil {
		diff("policy", old.Gate.PolicyDigest, cur.Gate.PolicyDigest)
	}
	if len(changes) == 0 {
		r.grade(layer, "build configuration", Note, "unchanged")
		return
	}
	r.grade(layer, "build configuration changed", Note, "%d change(s)%s", len(changes), listNote(changes))
}

func actionSet(inv *inventory.Inventory) map[string]bool {
	out := map[string]bool{}
	for _, w := range inv.Pipeline.Workflows {
		for _, a := range w.Actions {
			out[a] = true
		}
	}
	return out
}

func egressString(inv *inventory.Inventory) string {
	var hosts []string
	for _, rule := range inv.Egress.Rules {
		h := rule.Host
		if rule.Port != 0 {
			h += fmt.Sprintf(":%d", rule.Port)
		}
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return inv.Egress.Mode + " " + strings.Join(hosts, ",")
}

func envString(env map[string]string) string {
	var kv []string
	for _, k := range sortedKeys(env) {
		kv = append(kv, k+"="+env[k])
	}
	return strings.Join(kv, " ")
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func sameKeys[V any](a, b map[string]V) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func unionKeys(a, b map[string]string) []string {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return sortedKeys(m)
}

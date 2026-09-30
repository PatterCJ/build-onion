package upstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/PatterCJ/build-onion/internal/lockfile"
)

// slsaProvenanceV1 is the predicate npm's provenance attestation carries.
const slsaProvenanceV1 = "https://slsa.dev/provenance/v1"

// checkNpm compares the locked integrity with the registry's, then verifies
// the registry's provenance attestation, whose subject is the tarball's
// sha512: the same digest the lockfile pins.
func (c *Checker) checkNpm(ctx context.Context, p lockfile.Package, r *Result) {
	if len(p.Archives) == 0 {
		r.Outcome, r.Detail = Unhashed, "lockfile has no integrity for it"
		return
	}
	body, err := c.get(ctx, c.Registries.Npm+"/"+npmEscape(p.Name)+"/"+url.PathEscape(p.Version), "application/json")
	if err != nil {
		fail(r, err, p.Name+"@"+p.Version)
		return
	}
	var doc struct {
		Dist struct {
			Integrity    string `json:"integrity"`
			Shasum       string `json:"shasum"`
			Attestations *struct {
				URL string `json:"url"`
			} `json:"attestations"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		r.Outcome, r.Detail = Error, fmt.Sprintf("registry response: %v", err)
		return
	}
	published := npmDigests(doc.Dist.Integrity, doc.Dist.Shasum)
	locked := p.Archives[0] // strongest first
	alg, _, _ := strings.Cut(locked, ":")
	if published[alg] == "" {
		r.Outcome, r.Detail = Error, fmt.Sprintf("registry publishes no %s digest to compare", alg)
		return
	}
	if published[alg] != locked {
		r.Outcome, r.Detail = Mismatch, fmt.Sprintf("lockfile pins %s, registry publishes %s", short(locked), short(published[alg]))
		return
	}
	if doc.Dist.Attestations == nil || doc.Dist.Attestations.URL == "" {
		r.Outcome, r.Detail = Published, "no provenance published"
		return
	}
	subject := published["sha512"]
	if subject == "" {
		r.Outcome, r.Detail = Error, "provenance published but the registry has no sha512 for it"
		return
	}
	body, err = c.get(ctx, doc.Dist.Attestations.URL, "application/json")
	if err != nil {
		r.Outcome, r.Detail = Error, fmt.Sprintf("provenance: %v", err)
		return
	}
	var atts struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &atts); err != nil {
		r.Outcome, r.Detail = Error, fmt.Sprintf("provenance response: %v", err)
		return
	}
	for _, a := range atts.Attestations {
		if a.PredicateType != slsaProvenanceV1 {
			continue // npm's publish attestation is signed by npm's own key
		}
		att, err := c.verify(a.Bundle, subject, "")
		if err != nil {
			r.Outcome, r.Detail = Invalid, fmt.Sprintf("provenance: %v", err)
			return
		}
		r.Outcome, r.Attestations = Attested, []Attestation{att}
		return
	}
	r.Outcome, r.Detail = Invalid, "registry advertises provenance but serves no SLSA provenance bundle"
}

// npmDigests converts the registry's integrity and legacy shasum to alg:hex.
func npmDigests(integrity, shasum string) map[string]string {
	out := map[string]string{}
	if ds, err := lockfile.SRIDigests(integrity); err == nil {
		for _, d := range ds {
			alg, _, _ := strings.Cut(d, ":")
			out[alg] = d
		}
	}
	if shasum != "" && out["sha1"] == "" {
		out["sha1"] = "sha1:" + strings.ToLower(shasum)
	}
	return out
}

// npmEscape encodes a package name as one registry path segment
// (@scope/name → @scope%2Fname).
func npmEscape(name string) string { return url.PathEscape(name) }

func short(d string) string {
	if alg, h, ok := strings.Cut(d, ":"); ok && len(h) > 16 {
		return alg + ":" + h[:16] + "…"
	}
	return d
}

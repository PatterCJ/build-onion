// Package deps proves an artifact's contents against what the build
// declared. The artifact side comes from an SBOM of the built output; the
// declared side comes from onion's own lockfile parsers. Every package found
// in the artifact gets exactly one outcome, and nothing is passed over
// silently.
package deps

import (
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/lockfile"
)

// Present is a package found inside the artifact.
type Present struct {
	Ecosystem string `json:"ecosystem"` // package-URL type
	Name      string `json:"name"`
	Version   string `json:"version"`
	Hash      string `json:"hash,omitempty"`     // comparable content hash (Go h1:)
	Location  string `json:"location,omitempty"` // where the SBOM tool found it
	Layer     string `json:"layer,omitempty"`    // image layer diffID, for image scans
}

// FromSBOM reads a CycloneDX SBOM. Components without a package URL (files,
// the OS descriptor) are contents, not packages, and are skipped.
func FromSBOM(data []byte) ([]Present, error) {
	var bom struct {
		Components []struct {
			PURL       string `json:"purl"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("SBOM: %w", err)
	}
	var out []Present
	for _, c := range bom.Components {
		if c.PURL == "" {
			continue
		}
		eco, name, version, err := ParsePURL(c.PURL)
		if err != nil {
			return nil, err
		}
		p := Present{Ecosystem: eco, Name: name, Version: version}
		for _, prop := range c.Properties {
			switch prop.Name {
			case "syft:metadata:h1Digest":
				p.Hash = prop.Value
			case "syft:location:0:path":
				p.Location = prop.Value
			case "syft:location:0:layerID":
				p.Layer = prop.Value
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// ParsePURL splits pkg:type/namespace/name@version?qualifiers#subpath. The
// name includes its namespace (an npm @scope, a Go module path), each segment
// percent-decoded.
func ParsePURL(p string) (ecosystem, name, version string, err error) {
	rest, ok := strings.CutPrefix(p, "pkg:")
	if !ok {
		return "", "", "", fmt.Errorf("package URL %q: missing pkg: scheme", p)
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	typ, rest, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || rest == "" {
		return "", "", "", fmt.Errorf("package URL %q: missing type or name", p)
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		if version, err = url.PathUnescape(rest[i+1:]); err != nil {
			return "", "", "", fmt.Errorf("package URL %q: %w", p, err)
		}
		rest = rest[:i]
	}
	segs := strings.Split(rest, "/")
	for i, s := range segs {
		if segs[i], err = url.PathUnescape(s); err != nil {
			return "", "", "", fmt.Errorf("package URL %q: %w", p, err)
		}
	}
	return strings.ToLower(typ), strings.Join(segs, "/"), version, nil
}

// Outcome is what peel concluded about one package in the artifact.
type Outcome string

const (
	HashVerified    Outcome = "hash-verified"    // declared; same version and same content hash
	VersionVerified Outcome = "version-verified" // declared; same version (no comparable hash)
	Vendored        Outcome = "vendored"         // bundled inside a declared package
	BaseImage       Outcome = "base-image"       // in a layer of a pinned base image
	Toolchain       Outcome = "toolchain"        // the language runtime from the pinned builder
	LocalPackage    Outcome = "local"            // built from this source
	Undeclared      Outcome = "undeclared"       // in the artifact, not declared
	VersionDrift    Outcome = "version-drift"    // declared at a different version
	HashMismatch    Outcome = "hash-mismatch"    // same version, different content
	NoVersion       Outcome = "no-version"       // the SBOM carries no version to check
	OSPackage       Outcome = "os-package"       // an OS package outside the base image layers
	NoParser        Outcome = "no-parser"        // ecosystem without a lockfile parser
)

// Result is one package's outcome.
type Result struct {
	Ecosystem string  `json:"ecosystem"`
	Name      string  `json:"name"`
	Version   string  `json:"version"`
	Outcome   Outcome `json:"outcome"`
	Detail    string  `json:"detail,omitempty"`
}

// Input is everything the match needs.
type Input struct {
	Present  []Present
	Declared []lockfile.Package
	Local    []lockfile.Local
	// BaseLayers are the diffIDs of the pinned base image's layers, for image
	// artifacts. Empty for file artifacts.
	BaseLayers []string
}

// Report is the per-package result plus what was declared but didn't ship.
type Report struct {
	Results []Result `json:"results"`
	// NotShipped counts declared packages absent from the artifact, per
	// ecosystem. Lockfiles pin more than any one artifact ships (tests,
	// tooling, other platforms), so these are context, not violations.
	NotShipped    map[string]int `json:"notShipped"`
	NotShippedDev map[string]int `json:"notShippedDev"`
}

var osTypes = map[string]bool{"deb": true, "rpm": true, "apk": true, "alpm": true}

// vendorDirs are directory names under which packages bundle copies of other
// packages (setuptools/_vendor, pip/_vendor, …).
var vendorDirs = map[string]bool{"_vendor": true, "vendor": true, "_vendored": true, "extern": true}

type declaredKey struct{ eco, name string }

// Match gives every present package an outcome.
func Match(in Input) *Report {
	rep := &Report{NotShipped: map[string]int{}, NotShippedDev: map[string]int{}}
	parser := map[string]bool{}
	for _, e := range lockfile.Supported() {
		parser[e] = true
	}
	declared := map[declaredKey][]lockfile.Package{}
	for _, d := range in.Declared {
		k := declaredKey{d.Ecosystem, lockfile.Normalize(d.Ecosystem, d.Name)}
		declared[k] = append(declared[k], d)
	}
	local := map[declaredKey]bool{}
	for _, l := range in.Local {
		local[declaredKey{l.Ecosystem, lockfile.Normalize(l.Ecosystem, l.Name)}] = true
	}
	base := map[string]bool{}
	for _, l := range in.BaseLayers {
		base[l] = true
	}
	// A vendoring parent must itself be something the artifact legitimately
	// contains: a declared or local package.
	parentOK := func(eco, name string) bool {
		k := declaredKey{eco, lockfile.Normalize(eco, name)}
		return len(declared[k]) > 0 || local[k]
	}
	shipped := map[string]bool{} // eco|name|version of declared packages found

	for _, p := range in.Present {
		r := Result{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version}
		k := declaredKey{p.Ecosystem, lockfile.Normalize(p.Ecosystem, p.Name)}
		switch {
		case local[k]:
			r.Outcome = LocalPackage
		case p.Ecosystem == "golang" && p.Name == "stdlib":
			r.Outcome, r.Detail = Toolchain, "Go standard library from the pinned builder image"
		case p.Layer != "" && base[p.Layer]:
			r.Outcome, r.Detail = BaseImage, "layer "+short(p.Layer)
		case osTypes[p.Ecosystem]:
			r.Outcome, r.Detail = OSPackage, "OS package outside the pinned base image's layers"
		case !parser[p.Ecosystem]:
			r.Outcome, r.Detail = NoParser, "no lockfile parser for "+p.Ecosystem
		case len(declared[k]) == 0:
			if parent, ok := vendorParent(p.Location); ok && parentOK(p.Ecosystem, parent) {
				r.Outcome, r.Detail = Vendored, "bundled inside "+parent
			} else {
				r.Outcome, r.Detail = Undeclared, "not in any lockfile"
			}
		case p.Version == "" || p.Version == "UNKNOWN":
			r.Outcome, r.Detail = NoVersion, "the SBOM has no version to check"
		default:
			var match *lockfile.Package
			var versions []string
			for i, d := range declared[k] {
				versions = append(versions, d.Version)
				if d.Version == p.Version {
					match = &declared[k][i]
				}
			}
			switch {
			case match == nil:
				r.Outcome, r.Detail = VersionDrift, "declared "+strings.Join(uniq(versions), ", ")
			case p.Hash != "" && match.Hash != "" && p.Hash != match.Hash:
				r.Outcome, r.Detail = HashMismatch, fmt.Sprintf("artifact %s, declared %s", p.Hash, match.Hash)
				shipped[shipKey(*match)] = true
			case p.Hash != "" && match.Hash != "":
				r.Outcome, r.Detail = HashVerified, p.Hash
				shipped[shipKey(*match)] = true
			default:
				r.Outcome = VersionVerified
				shipped[shipKey(*match)] = true
			}
		}
		rep.Results = append(rep.Results, r)
	}
	for _, d := range in.Declared {
		if !shipped[shipKey(d)] {
			if d.Dev {
				rep.NotShippedDev[d.Ecosystem]++
			} else {
				rep.NotShipped[d.Ecosystem]++
			}
		}
	}
	sort.Slice(rep.Results, func(i, j int) bool {
		a, b := rep.Results[i], rep.Results[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return rep
}

// vendorParent finds the package a vendored copy lives inside, from its
// location: …/setuptools/_vendor/autocommand-2.2.2.dist-info/METADATA → setuptools.
func vendorParent(loc string) (string, bool) {
	segs := strings.Split(path.Clean("/"+loc), "/")
	for i := 1; i < len(segs); i++ {
		if vendorDirs[segs[i]] && segs[i-1] != "" {
			return segs[i-1], true
		}
	}
	return "", false
}

func shipKey(p lockfile.Package) string {
	return p.Ecosystem + "|" + lockfile.Normalize(p.Ecosystem, p.Name) + "|" + p.Version
}

func short(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

func uniq(xs []string) []string {
	sort.Strings(xs)
	out := xs[:0]
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

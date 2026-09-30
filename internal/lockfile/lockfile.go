// Package lockfile reads what a build declared: one parser per ecosystem,
// each turning a lockfile into the exact packages and versions it pins. It is
// deliberately independent of the SBOM tool, so what was declared (read here)
// and what is inside the artifact (read by syft) come from two separate
// implementations that must agree.
//
// Adding an ecosystem is one file with a parser and its test.
package lockfile

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Package is one pinned dependency.
type Package struct {
	// Ecosystem is the package-URL type: golang, npm, pypi, cargo.
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// Hash is a content hash in a form an SBOM can also carry (Go's h1:).
	// Lockfile hashes of downloaded archives, which can't be compared with
	// installed files, are not recorded here.
	Hash string `json:"hash,omitempty"`
	// Archives are the digests (sha512:hex, sha256:hex) of the registry
	// archives the lockfile allows for this version: npm's integrity, the
	// wheels and sdists of a hash-pinned Python lock, a crate's checksum.
	Archives []string `json:"archives,omitempty"`
	// Dev marks development-only dependencies, expected not to ship.
	Dev bool `json:"dev,omitempty"`
}

// Local is a package built from this source rather than fetched: a Go main
// module, a workspace member, the project itself.
type Local struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Result is what one lockfile declares.
type Result struct {
	Packages []Package
	Local    []Local
}

// Sibling reads a file next to the lockfile (go.mod beside go.sum).
type Sibling func(name string) ([]byte, error)

type parser struct {
	ecosystem string
	handles   func(base string) bool
	parse     func(data []byte, sibling Sibling) (Result, error)
}

var parsers []parser

func register(ecosystem string, handles func(string) bool, parse func([]byte, Sibling) (Result, error)) {
	parsers = append(parsers, parser{ecosystem, handles, parse})
}

// Ecosystem returns the ecosystem that handles a lockfile path, or "".
func Ecosystem(p string) string {
	base := path.Base(p)
	for _, pr := range parsers {
		if pr.handles(base) {
			return pr.ecosystem
		}
	}
	return ""
}

// Supported lists every ecosystem with a parser.
func Supported() []string {
	seen := map[string]bool{}
	var out []string
	for _, pr := range parsers {
		if !seen[pr.ecosystem] {
			seen[pr.ecosystem] = true
			out = append(out, pr.ecosystem)
		}
	}
	sort.Strings(out)
	return out
}

// Parse reads one lockfile. ok is false when no parser handles it: the
// lockfile is still hashed into the inventory, but its packages can't be
// cross-checked.
func Parse(p string, data []byte, sibling Sibling) (res Result, ok bool, err error) {
	base := path.Base(p)
	for _, pr := range parsers {
		if pr.handles(base) {
			res, err := pr.parse(data, sibling)
			if err != nil {
				return Result{}, true, fmt.Errorf("%s: %w", p, err)
			}
			for i := range res.Packages {
				res.Packages[i].Ecosystem = pr.ecosystem
			}
			for i := range res.Local {
				res.Local[i].Ecosystem = pr.ecosystem
			}
			sort.Slice(res.Packages, func(i, j int) bool { return res.Packages[i].key() < res.Packages[j].key() })
			return res, true, nil
		}
	}
	return Result{}, false, nil
}

func (p Package) key() string { return p.Name + "@" + p.Version }

var pypiSep = regexp.MustCompile(`[-_.]+`)

// Normalize puts a package name in the form two tools must agree on,
// following each ecosystem's own equivalence rules.
func Normalize(ecosystem, name string) string {
	switch ecosystem {
	case "pypi":
		// PEP 503: case-insensitive; runs of -, _ and . are equivalent.
		return pypiSep.ReplaceAllString(strings.ToLower(name), "-")
	case "cargo":
		// crates.io treats - and _ as the same name.
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	case "npm":
		return strings.ToLower(name)
	}
	return name
}

// archiveDigest normalizes a lockfile hash (sha256:hex, sha256=hex, or bare
// hex with a default algorithm) to alg:hex.
func archiveDigest(h, defaultAlg string) (string, error) {
	alg, val := defaultAlg, h
	if i := strings.IndexAny(h, ":="); i >= 0 {
		alg, val = strings.ToLower(h[:i]), h[i+1:]
	}
	val = strings.ToLower(val)
	if _, err := hex.DecodeString(val); err != nil || alg == "" {
		return "", fmt.Errorf("unrecognized hash %q", h)
	}
	return alg + ":" + val, nil
}

// SRIDigests converts a Subresource Integrity string (npm's "integrity") to
// alg:hex digests, strongest first.
func SRIDigests(sri string) ([]string, error) {
	var out []string
	for _, f := range strings.Fields(sri) {
		alg, b64, ok := strings.Cut(f, "-")
		if !ok {
			return nil, fmt.Errorf("unrecognized integrity %q", f)
		}
		if i := strings.IndexByte(b64, '?'); i >= 0 {
			b64 = b64[:i]
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("integrity %q: %w", f, err)
		}
		out = append(out, strings.ToLower(alg)+":"+hex.EncodeToString(raw))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i] > out[j] }) // sha512 > sha384 > sha256 > sha1
	return out, nil
}

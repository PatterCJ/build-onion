package deps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/lockfile"
)

// The fixtures under testdata are real: each is a small project depending on
// real open-source packages, locked by its ecosystem's own tool, installed or
// built from that lock, and scanned by syft. See testdata/generate.sh.

func declared(t *testing.T, lockPath string) lockfile.Result {
	t.Helper()
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	sibling := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(filepath.Dir(lockPath), name)) }
	res, ok, err := lockfile.Parse(lockPath, data, sibling)
	if err != nil || !ok {
		t.Fatalf("parse %s: ok=%v err=%v", lockPath, ok, err)
	}
	return res
}

func present(t *testing.T, sbomPath string) []Present {
	t.Helper()
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := FromSBOM(data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func counts(rep *Report) map[Outcome]int {
	c := map[Outcome]int{}
	for _, r := range rep.Results {
		c[r.Outcome]++
	}
	return c
}

// violations are the outcomes that must never appear for an honest build.
var violations = []Outcome{Undeclared, VersionDrift, HashMismatch, NoVersion, NoParser, OSPackage}

func TestRealArtifactsMatchTheirLockfiles(t *testing.T) {
	cases := []struct {
		name, lock, sbom string
		want             map[Outcome]int // exact counts for the outcomes listed
	}{
		// govulncheck: its own main module, the standard library, and four
		// dependencies, each proven by the h1: hash embedded in the binary.
		{"go", "testdata/go/go.sum", "testdata/go/sbom.json",
			map[Outcome]int{HashVerified: 4, LocalPackage: 1, Toolchain: 1}},
		// http-server and a scoped package, production install: every one of
		// the 51 installed packages is in package-lock.json.
		{"npm", "testdata/npm/package-lock.json", "testdata/npm/sbom.json",
			map[Outcome]int{VersionVerified: 51}},
		// httpie and PyYAML. Three lockfile formats describing the same set
		// must each account for the same installed artifact, including the
		// packages setuptools bundles in its _vendor directory.
		{"pypi requirements.txt", "testdata/pypi/requirements.txt", "testdata/pypi/sbom.json", nil},
		{"pypi uv.lock", "testdata/pypi/uv.lock", "testdata/pypi/sbom.json", nil},
		{"pypi poetry.lock", "testdata/pypi/poetry.lock", "testdata/pypi/sbom.json", nil},
		// serde_json and anyhow, built with cargo-auditable: the binary's
		// embedded crate list against Cargo.lock.
		{"cargo", "testdata/cargo/Cargo.lock", "testdata/cargo/sbom.json",
			map[Outcome]int{VersionVerified: 7, LocalPackage: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := declared(t, tc.lock)
			pres := present(t, tc.sbom)
			if len(pres) == 0 {
				t.Fatal("fixture SBOM lists no packages")
			}
			rep := Match(Input{Present: pres, Declared: d.Packages, Local: d.Local})
			c := counts(rep)
			for _, v := range violations {
				if c[v] > 0 {
					for _, r := range rep.Results {
						if r.Outcome == v {
							t.Errorf("%s %s@%s: %s", v, r.Name, r.Version, r.Detail)
						}
					}
				}
			}
			for o, n := range tc.want {
				if c[o] != n {
					t.Errorf("%s: got %d, want %d (all: %v)", o, c[o], n, c)
				}
			}
			if len(rep.Results) != len(pres) {
				t.Errorf("%d results for %d packages: every package needs exactly one outcome", len(rep.Results), len(pres))
			}
		})
	}
}

func TestPythonVendoredPackagesAreAttributed(t *testing.T) {
	d := declared(t, "testdata/pypi/uv.lock")
	rep := Match(Input{Present: present(t, "testdata/pypi/sbom.json"), Declared: d.Packages, Local: d.Local})
	var vendored []string
	for _, r := range rep.Results {
		if r.Outcome == Vendored {
			if r.Detail != "bundled inside setuptools" {
				t.Errorf("%s: %s", r.Name, r.Detail)
			}
			vendored = append(vendored, r.Name)
		}
	}
	if len(vendored) == 0 {
		t.Fatal("setuptools' _vendor packages were not recognized")
	}
}

func TestDevDependenciesDeclaredNotShipped(t *testing.T) {
	d := declared(t, "testdata/npm/package-lock.json")
	rep := Match(Input{Present: present(t, "testdata/npm/sbom.json"), Declared: d.Packages, Local: d.Local})
	if rep.NotShippedDev["npm"] != 1 {
		t.Errorf("semver (dev) should be declared-not-shipped: %v", rep.NotShippedDev)
	}
}

// tamper edits one real SBOM component and returns the rewritten SBOM.
func tamper(t *testing.T, sbomPath string, edit func(c map[string]any) bool) []Present {
	t.Helper()
	raw, _ := os.ReadFile(sbomPath)
	var bom map[string]any
	if err := json.Unmarshal(raw, &bom); err != nil {
		t.Fatal(err)
	}
	comps := bom["components"].([]any)
	done := false
	for _, c := range comps {
		if !done && edit(c.(map[string]any)) {
			done = true
		}
	}
	if !done {
		t.Fatal("tamper edited nothing")
	}
	out, _ := json.Marshal(bom)
	p, err := FromSBOM(out)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTamperedArtifactsAreCaught(t *testing.T) {
	cases := []struct {
		name, lock, sbom string
		edit             func(map[string]any) bool
		want             Outcome
	}{
		{"go module content swapped (same version, different h1)", "testdata/go/go.sum", "testdata/go/sbom.json",
			func(c map[string]any) bool {
				for _, p := range c["properties"].([]any) {
					if pm := p.(map[string]any); pm["name"] == "syft:metadata:h1Digest" {
						pm["value"] = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
						return true
					}
				}
				return false
			}, HashMismatch},
		{"go module at another version", "testdata/go/go.sum", "testdata/go/sbom.json",
			func(c map[string]any) bool {
				if strings.Contains(c["purl"].(string), "golang.org/x/mod@") {
					c["purl"] = "pkg:golang/golang.org/x/mod@v0.21.0"
					return true
				}
				return false
			}, VersionDrift},
		{"npm package nobody declared", "testdata/npm/package-lock.json", "testdata/npm/sbom.json",
			func(c map[string]any) bool { c["purl"] = "pkg:npm/%40evil/postinstall@1.0.0"; return true }, Undeclared},
		{"python package at another version", "testdata/pypi/uv.lock", "testdata/pypi/sbom.json",
			func(c map[string]any) bool {
				if strings.HasPrefix(c["purl"].(string), "pkg:pypi/requests@") {
					c["purl"] = "pkg:pypi/requests@2.0.0"
					return true
				}
				return false
			}, VersionDrift},
		{"fake vendored package under an undeclared parent", "testdata/pypi/uv.lock", "testdata/pypi/sbom.json",
			func(c map[string]any) bool {
				c["purl"] = "pkg:pypi/backdoor@1.0.0"
				c["properties"] = []any{map[string]any{"name": "syft:location:0:path", "value": "/evilpkg/_vendor/backdoor-1.0.0.dist-info/METADATA"}}
				return true
			}, Undeclared},
		{"crate nobody declared", "testdata/cargo/Cargo.lock", "testdata/cargo/sbom.json",
			func(c map[string]any) bool { c["purl"] = "pkg:cargo/evil-crate@0.1.0"; return true }, Undeclared},
		{"ecosystem with no parser", "testdata/npm/package-lock.json", "testdata/npm/sbom.json",
			func(c map[string]any) bool { c["purl"] = "pkg:maven/org.example/lib@1.0"; return true }, NoParser},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := declared(t, tc.lock)
			rep := Match(Input{Present: tamper(t, tc.sbom, tc.edit), Declared: d.Packages, Local: d.Local})
			if counts(rep)[tc.want] != 1 {
				t.Fatalf("want exactly one %s, got %v", tc.want, counts(rep))
			}
		})
	}
}

func TestBaseImageLayers(t *testing.T) {
	baseLayer := "sha256:" + strings.Repeat("b", 64)
	appLayer := "sha256:" + strings.Repeat("a", 64)
	pres := []Present{
		{Ecosystem: "deb", Name: "base-files", Version: "12", Layer: baseLayer},
		{Ecosystem: "pypi", Name: "pip", Version: "24.0", Layer: baseLayer}, // the base image's own tooling
		{Ecosystem: "deb", Name: "curl", Version: "8", Layer: appLayer},     // added on top: not the base's
		{Ecosystem: "pypi", Name: "requests", Version: "2.32.3", Layer: appLayer},
	}
	rep := Match(Input{
		Present:    pres,
		Declared:   []lockfile.Package{{Ecosystem: "pypi", Name: "requests", Version: "2.32.3"}},
		BaseLayers: []string{baseLayer},
	})
	got := map[string]Outcome{}
	for _, r := range rep.Results {
		got[r.Name] = r.Outcome
	}
	want := map[string]Outcome{"base-files": BaseImage, "pip": BaseImage, "curl": OSPackage, "requests": VersionVerified}
	for n, o := range want {
		if got[n] != o {
			t.Errorf("%s: %s, want %s", n, got[n], o)
		}
	}
}

func TestParsePURL(t *testing.T) {
	cases := map[string][3]string{
		"pkg:npm/%40sindresorhus/slugify@2.2.1":                    {"npm", "@sindresorhus/slugify", "2.2.1"},
		"pkg:golang/github.com/blang/semver@v3.5.1%2Bincompatible": {"golang", "github.com/blang/semver", "v3.5.1+incompatible"},
		"pkg:golang/github.com/PatterCJ/build-onion":               {"golang", "github.com/PatterCJ/build-onion", ""},
		"pkg:pypi/charset-normalizer@3.5.1":                        {"pypi", "charset-normalizer", "3.5.1"},
		"pkg:deb/debian/base-files@12.4%2Bdeb12u15?arch=amd64":     {"deb", "debian/base-files", "12.4+deb12u15"},
		"pkg:cargo/serde_json@1.0.128#sub":                         {"cargo", "serde_json", "1.0.128"},
	}
	for in, want := range cases {
		e, n, v, err := ParsePURL(in)
		if err != nil || e != want[0] || n != want[1] || v != want[2] {
			t.Errorf("%s => %q %q %q %v", in, e, n, v, err)
		}
	}
	for _, bad := range []string{"npm/x@1", "pkg:", "pkg:npm", "pkg:npm/%zz@1"} {
		if _, _, _, err := ParsePURL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

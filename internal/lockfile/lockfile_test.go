package lockfile

import (
	"os"
	"strings"
	"testing"
)

func parse(t *testing.T, name, body string) Result {
	t.Helper()
	res, ok, err := Parse(name, []byte(body), func(string) ([]byte, error) { return []byte("module example.com/app\n"), nil })
	if err != nil || !ok {
		t.Fatalf("%s: ok=%v err=%v", name, ok, err)
	}
	return res
}

func find(res Result, name string) (Package, bool) {
	for _, p := range res.Packages {
		if p.Name == name {
			return p, true
		}
	}
	return Package{}, false
}

func TestEcosystemRouting(t *testing.T) {
	cases := map[string]string{
		"go.sum": "golang", "sub/go.sum": "golang", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
		"requirements.txt": "pypi", "requirements-prod.txt": "pypi", "uv.lock": "pypi", "poetry.lock": "pypi",
		"Cargo.lock": "cargo", "pom.xml": "", "yarn.lock": "",
	}
	for p, want := range cases {
		if got := Ecosystem(p); got != want {
			t.Errorf("%s => %q, want %q", p, got, want)
		}
	}
	if _, ok, _ := Parse("yarn.lock", []byte("x"), nil); ok {
		t.Error("yarn.lock reported as supported")
	}
}

func TestGoSum(t *testing.T) {
	res := parse(t, "go.sum", "golang.org/x/mod v0.22.0 h1:abc=\ngolang.org/x/mod v0.22.0/go.mod h1:def=\nexample.com/only v1.0.0/go.mod h1:x=\n")
	if len(res.Packages) != 1 || res.Packages[0].Hash != "h1:abc=" || res.Packages[0].Ecosystem != "golang" {
		t.Fatalf("packages = %+v", res.Packages)
	}
	if len(res.Local) != 1 || res.Local[0].Name != "example.com/app" {
		t.Errorf("local = %+v", res.Local)
	}
	if _, _, err := Parse("go.sum", []byte("garbage line\n"), nil); err == nil {
		t.Error("malformed go.sum accepted")
	}
}

func TestNpmLockV3Fixture(t *testing.T) {
	data, err := os.ReadFile("../deps/testdata/npm/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	res, _, err := Parse("package-lock.json", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := find(res, "@sindresorhus/slugify"); !ok || p.Version != "2.2.1" {
		t.Errorf("scoped package: %+v %v", p, ok)
	}
	if p, ok := find(res, "semver"); !ok || !p.Dev {
		t.Errorf("dev dependency not flagged: %+v %v", p, ok)
	}
	if len(res.Local) != 1 || res.Local[0].Name != "onion-npm-fixture" {
		t.Errorf("local = %+v", res.Local)
	}
}

func TestNpmLockV1AndWorkspaces(t *testing.T) {
	v1 := parse(t, "package-lock.json", `{"name":"app","lockfileVersion":1,"dependencies":{
		"a":{"version":"1.0.0","dependencies":{"b":{"version":"2.0.0","dev":true}}}}}`)
	if b, ok := find(v1, "b"); !ok || b.Version != "2.0.0" || !b.Dev {
		t.Errorf("nested v1 dependency: %+v %v", b, ok)
	}
	ws := parse(t, "package-lock.json", `{"name":"root","lockfileVersion":3,"packages":{
		"":{"name":"root"},
		"packages/lib":{"name":"@acme/lib","version":"0.1.0"},
		"node_modules/@acme/lib":{"resolved":"packages/lib","link":true},
		"node_modules/a/node_modules/@x/y":{"version":"3.0.0"}}}`)
	if _, ok := find(ws, "@x/y"); !ok {
		t.Error("nested scoped package not read from its install path")
	}
	locals := map[string]bool{}
	for _, l := range ws.Local {
		locals[l.Name] = true
	}
	if !locals["root"] || !locals["@acme/lib"] {
		t.Errorf("workspace members not local: %+v", ws.Local)
	}
	if len(ws.Packages) != 1 {
		t.Errorf("workspace folder counted as a package: %+v", ws.Packages)
	}
}

func TestRequirements(t *testing.T) {
	res := parse(t, "requirements.txt", `# a comment
--index-url https://pypi.org/simple
certifi==2026.7.22 \
    --hash=sha256:aa11 \
    --hash=sha256:BB22
requests[socks]==2.32.3 ; python_version >= "3.8"
PyYAML===6.0.2  # exact
`)
	for name, v := range map[string]string{"certifi": "2026.7.22", "requests": "2.32.3", "PyYAML": "6.0.2"} {
		if p, ok := find(res, name); !ok || p.Version != v {
			t.Errorf("%s: %+v %v", name, p, ok)
		}
	}
	for _, bad := range []string{"requests>=2.0\n", "-r other.txt\n", "-e .\n", "git+https://example.com/x.git\n", "requests\n"} {
		if _, _, err := Parse("requirements.txt", []byte(bad), nil); err == nil {
			t.Errorf("%q accepted as a lockfile", strings.TrimSpace(bad))
		}
	}
}

func TestPoetryAndUvGroups(t *testing.T) {
	poetry := parse(t, "poetry.lock", `
[[package]]
name = "requests"
version = "2.32.3"
groups = ["main"]

[[package]]
name = "pytest"
version = "8.0.0"
groups = ["dev"]

[[package]]
name = "mylib"
version = "0.1.0"
[package.source]
type = "directory"
url = "libs/mylib"
`)
	if p, _ := find(poetry, "pytest"); !p.Dev {
		t.Error("poetry dev group not flagged")
	}
	if p, _ := find(poetry, "requests"); p.Dev {
		t.Error("poetry main group flagged dev")
	}
	if len(poetry.Local) != 1 || poetry.Local[0].Name != "mylib" {
		t.Errorf("poetry directory source not local: %+v", poetry.Local)
	}
	uv := parse(t, "uv.lock", `
[[package]]
name = "app"
version = "1.0.0"
source = { editable = "." }

[[package]]
name = "rich"
version = "13.9.4"
source = { registry = "https://pypi.org/simple" }
`)
	if len(uv.Local) != 1 || len(uv.Packages) != 1 {
		t.Errorf("uv: local %+v packages %+v", uv.Local, uv.Packages)
	}
}

func TestCargoWorkspaceMembers(t *testing.T) {
	res := parse(t, "Cargo.lock", `
version = 4

[[package]]
name = "my-app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ab12"
`)
	if len(res.Local) != 1 || res.Local[0].Name != "my-app" || len(res.Packages) != 1 {
		t.Errorf("local %+v packages %+v", res.Local, res.Packages)
	}
}

func TestNormalize(t *testing.T) {
	cases := []struct{ eco, a, b string }{
		{"pypi", "PyYAML", "pyyaml"},
		{"pypi", "charset_normalizer", "charset-normalizer"},
		{"pypi", "jaraco.context", "jaraco-context"},
		{"pypi", "backports.tarfile", "backports-tarfile"},
		{"cargo", "serde_json", "serde-json"},
		{"npm", "@Scope/Pkg", "@scope/pkg"},
	}
	for _, c := range cases {
		if Normalize(c.eco, c.a) != Normalize(c.eco, c.b) {
			t.Errorf("%s: %q and %q should be the same package", c.eco, c.a, c.b)
		}
	}
	if Normalize("golang", "github.com/Foo/bar") == Normalize("golang", "github.com/foo/bar") {
		t.Error("Go module paths are case-sensitive")
	}
}

func TestArchives(t *testing.T) {
	read := func(p string) Result {
		t.Helper()
		data, err := os.ReadFile("../deps/testdata/" + p)
		if err != nil {
			t.Fatal(err)
		}
		res, _, err := Parse(p, data, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	for _, c := range []struct{ file, pkg, prefix string }{
		{"npm/package-lock.json", "http-server", "sha512:"},
		{"pypi/requirements.txt", "pyyaml", "sha256:"},
		{"pypi/uv.lock", "pyyaml", "sha256:"},
		{"pypi/poetry.lock", "pyyaml", "sha256:"},
		{"cargo/Cargo.lock", "serde_json", "sha256:"},
	} {
		var pkg Package
		for _, p := range read(c.file).Packages {
			if Normalize(p.Ecosystem, p.Name) == Normalize(p.Ecosystem, c.pkg) {
				pkg = p
			}
		}
		if len(pkg.Archives) == 0 {
			t.Errorf("%s: %s has no archive hashes", c.file, c.pkg)
			continue
		}
		for _, a := range pkg.Archives {
			if !strings.HasPrefix(a, c.prefix) {
				t.Errorf("%s: %s archive %q, want %s…", c.file, c.pkg, a, c.prefix)
			}
		}
	}
	req := parse(t, "requirements.txt", "certifi==1.0 --hash=sha256:AA11 --hash=sha256:bb22\n")
	if got := strings.Join(req.Packages[0].Archives, " "); got != "sha256:aa11 sha256:bb22" {
		t.Errorf("requirement hashes = %q", got)
	}
	npm := parse(t, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0",
		"integrity":"sha1-qvuhGE4j9RfuB1BU4t0PFhQXL0s= sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="}}}`)
	if a := npm.Packages[0].Archives; len(a) != 2 || !strings.HasPrefix(a[0], "sha512:cf83e135") {
		t.Errorf("integrity = %v, want sha512 first", a)
	}
	if _, _, err := Parse("Cargo.lock", []byte("[[package]]\nname=\"x\"\nversion=\"1\"\nsource=\"registry+x\"\nchecksum=\"zz\"\n"), nil); err == nil {
		t.Error("non-hex checksum accepted")
	}
}

func TestInstallScripts(t *testing.T) {
	data, err := os.ReadFile("testdata/npm-install-scripts/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	res, _, err := Parse("package-lock.json", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := InstallScripts(res.Packages); len(got) != 1 || got[0] != "esbuild@0.24.0" {
		t.Errorf("install scripts = %v", got)
	}
	for fetch, want := range map[string]bool{
		"npm ci":                       false,
		"npm ci --ignore-scripts":      true,
		"npm ci --ignore-scripts=true": true,
		"npm ci --ignore-scripts-x":    false,
	} {
		if got := ScriptsDisabled(fetch, nil); got != want {
			t.Errorf("%q: disabled = %v", fetch, got)
		}
	}
	if !ScriptsDisabled("npm ci", map[string]string{"NPM_CONFIG_IGNORE_SCRIPTS": "true"}) {
		t.Error("npm_config_ignore_scripts not honoured")
	}
}

package upstream

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb"
	"golang.org/x/mod/sumdb/note"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/lockfile"
)

// Real responses captured by testdata/generate.sh.
const (
	semverIntegrity = "sha512-oVekP1cKtI+CTDvHWYFUcMtsK/00wmAEfyqKfNdARm8u1wNVhSgaX7A8d4UuIlUI5e84iEwOhs7ZPYRmzU9U6A=="
	sigstoreWheel   = "sha256:b568b16322222e834940acabdc84fbb16c8780874c3c21c6c8dde928dae0f881"
	sigstoreSdist   = "sha256:ee60fdc9236fd6709271ad53b44027461360c3fde155d2af15482e4c451ff865"
)

// registry serves captured files, with the public hosts in them rewritten to
// the test server. edit, if set, can change a response before it is served.
type registry struct {
	t     *testing.T
	srv   *httptest.Server
	files map[string]string // path → testdata file
	raw   map[string]string // path → literal body
	edit  func(path string, body []byte) []byte
}

func newRegistry(t *testing.T) *registry {
	r := &registry{t: t, files: map[string]string{}, raw: map[string]string{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		p := req.URL.EscapedPath()
		var body []byte
		if f, ok := r.files[p]; ok {
			b, err := os.ReadFile("testdata/" + f)
			if err != nil {
				t.Error(err)
			}
			body = b
		} else if s, ok := r.raw[p]; ok {
			body = []byte(s)
		} else {
			http.NotFound(w, req)
			return
		}
		body = []byte(strings.NewReplacer("https://registry.npmjs.org", r.srv.URL, "https://pypi.org", r.srv.URL).Replace(string(body)))
		if r.edit != nil {
			body = r.edit(p, body)
		}
		w.Write(body)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *registry) checker() *Checker {
	v, err := attest.NewAnyIdentityVerifier("testdata/trusted-root.json")
	if err != nil {
		r.t.Fatal(err)
	}
	return NewChecker(Registries{Npm: r.srv.URL, PyPI: r.srv.URL, Crates: r.srv.URL}, v)
}

func (r *registry) check(p lockfile.Package) Result {
	r.t.Helper()
	res := r.checker().Check(context.Background(), []lockfile.Package{p})
	if len(res) != 1 {
		r.t.Fatalf("results = %+v", res)
	}
	r.t.Logf("%s: %s", res[0].Outcome, res[0].Detail)
	return res[0]
}

func npmPkg(t *testing.T, integrity string) lockfile.Package {
	d, err := lockfile.SRIDigests(integrity)
	if err != nil {
		t.Fatal(err)
	}
	return lockfile.Package{Ecosystem: "npm", Name: "semver", Version: "7.6.3", Archives: d}
}

func npmRegistry(t *testing.T) *registry {
	r := newRegistry(t)
	r.files["/semver/7.6.3"] = "npm-semver-7.6.3.json"
	r.files["/-/npm/v1/attestations/semver@7.6.3"] = "npm-semver-7.6.3-attestations.json"
	return r
}

func TestNpmAttested(t *testing.T) {
	res := npmRegistry(t).check(npmPkg(t, semverIntegrity))
	if res.Outcome != Attested || len(res.Attestations) != 1 {
		t.Fatalf("%+v", res)
	}
	a := res.Attestations[0]
	if a.Repository != "https://github.com/npm/node-semver" || a.Issuer != attest.GitHubIssuer || a.LogIndex == 0 ||
		!strings.HasPrefix(a.Subject, "sha512:") || !strings.Contains(a.Workflow, "/.github/workflows/") {
		t.Errorf("attestation = %+v", a)
	}
}

func TestNpmTampering(t *testing.T) {
	other := "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))

	t.Run("lockfile pins other bytes", func(t *testing.T) {
		if res := npmRegistry(t).check(npmPkg(t, other)); res.Outcome != Mismatch {
			t.Errorf("%+v", res)
		}
	})
	t.Run("registry metadata points at other bytes", func(t *testing.T) {
		// The lockfile and registry agree on bytes the provenance isn't about.
		r := npmRegistry(t)
		r.edit = func(p string, b []byte) []byte {
			return []byte(strings.ReplaceAll(string(b), semverIntegrity, other))
		}
		if res := r.check(npmPkg(t, other)); res.Outcome != Invalid {
			t.Errorf("%+v", res)
		}
	})
	t.Run("bundle altered", func(t *testing.T) {
		r := npmRegistry(t)
		r.edit = func(p string, b []byte) []byte {
			if !strings.Contains(p, "attestations") {
				return b
			}
			var doc map[string]any
			json.Unmarshal(b, &doc)
			for _, a := range doc["attestations"].([]any) {
				env := a.(map[string]any)["bundle"].(map[string]any)["dsseEnvelope"].(map[string]any)
				payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
				payload = []byte(strings.Replace(string(payload), "node-semver", "node-semvex", 1))
				env["payload"] = base64.StdEncoding.EncodeToString(payload)
			}
			out, _ := json.Marshal(doc)
			return out
		}
		if res := r.check(npmPkg(t, semverIntegrity)); res.Outcome != Invalid {
			t.Errorf("%+v", res)
		}
	})
	t.Run("no provenance", func(t *testing.T) {
		r := npmRegistry(t)
		r.edit = func(p string, b []byte) []byte {
			var doc map[string]any
			json.Unmarshal(b, &doc)
			if dist, ok := doc["dist"].(map[string]any); ok {
				delete(dist, "attestations")
			}
			out, _ := json.Marshal(doc)
			return out
		}
		if res := r.check(npmPkg(t, semverIntegrity)); res.Outcome != Published {
			t.Errorf("%+v", res)
		}
	})
	t.Run("not on the registry", func(t *testing.T) {
		p := npmPkg(t, semverIntegrity)
		p.Name = "@acme/internal"
		if res := npmRegistry(t).check(p); res.Outcome != NotFound {
			t.Errorf("%+v", res)
		}
	})
	t.Run("no integrity", func(t *testing.T) {
		if res := npmRegistry(t).check(lockfile.Package{Ecosystem: "npm", Name: "semver", Version: "7.6.3"}); res.Outcome != Unhashed {
			t.Errorf("%+v", res)
		}
	})
}

func pypiRegistry(t *testing.T) *registry {
	r := newRegistry(t)
	r.files["/simple/sigstore/"] = "pypi-sigstore-simple.json"
	r.files["/integrity/sigstore/3.6.1/sigstore-3.6.1-py3-none-any.whl/provenance"] = "pypi-sigstore-3.6.1-whl-provenance.json"
	return r
}

func pypiPkg(version string, archives ...string) lockfile.Package {
	return lockfile.Package{Ecosystem: "pypi", Name: "Sigstore", Version: version, Archives: archives}
}

func TestPyPIAttested(t *testing.T) {
	res := pypiRegistry(t).check(pypiPkg("3.6.1", sigstoreWheel))
	if res.Outcome != Attested || len(res.Attestations) == 0 {
		t.Fatalf("%+v", res)
	}
	a := res.Attestations[0]
	if a.Subject != sigstoreWheel || a.File != "sigstore-3.6.1-py3-none-any.whl" ||
		a.Repository != "https://github.com/sigstore/sigstore-python" || len(a.Commit) != 40 {
		t.Errorf("attestation = %+v", a)
	}
}

func TestPyPITampering(t *testing.T) {
	t.Run("hash not published", func(t *testing.T) {
		if res := pypiRegistry(t).check(pypiPkg("3.6.1", "sha256:"+strings.Repeat("0", 64))); res.Outcome != Mismatch {
			t.Errorf("%+v", res)
		}
	})
	t.Run("version not on PyPI", func(t *testing.T) {
		if res := pypiRegistry(t).check(pypiPkg("9.9.9", "sha256:"+strings.Repeat("0", 64))); res.Outcome != NotFound {
			t.Errorf("%+v", res)
		}
	})
	t.Run("file of another version", func(t *testing.T) {
		if res := pypiRegistry(t).check(pypiPkg("3.6.0", sigstoreWheel)); res.Outcome != Mismatch {
			t.Errorf("%+v", res)
		}
	})
	t.Run("provenance for another file", func(t *testing.T) {
		// The index serves the wheel's provenance for the sdist.
		r := pypiRegistry(t)
		r.files["/integrity/sigstore/3.6.1/sigstore-3.6.1.tar.gz/provenance"] = "pypi-sigstore-3.6.1-whl-provenance.json"
		if res := r.check(pypiPkg("3.6.1", sigstoreSdist)); res.Outcome != Invalid {
			t.Errorf("%+v", res)
		}
	})
	t.Run("statement altered", func(t *testing.T) {
		r := pypiRegistry(t)
		r.edit = func(p string, b []byte) []byte {
			if !strings.HasSuffix(p, "/provenance") {
				return b
			}
			var doc map[string]any
			json.Unmarshal(b, &doc)
			a := doc["attestation_bundles"].([]any)[0].(map[string]any)["attestations"].([]any)[0].(map[string]any)
			env := a["envelope"].(map[string]any)
			st, _ := base64.StdEncoding.DecodeString(env["statement"].(string))
			env["statement"] = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(st), "3.6.1", "3.6.2", 1)))
			out, _ := json.Marshal(doc)
			return out
		}
		if res := r.check(pypiPkg("3.6.1", sigstoreWheel)); res.Outcome != Invalid {
			t.Errorf("%+v", res)
		}
	})
	t.Run("advertised provenance missing", func(t *testing.T) {
		// The sdist's provenance isn't served: a lookup failure, not a forgery.
		if res := pypiRegistry(t).check(pypiPkg("3.6.1", sigstoreWheel, sigstoreSdist)); res.Outcome != Error {
			t.Errorf("%+v", res)
		}
	})
	t.Run("partly attested", func(t *testing.T) {
		r := pypiRegistry(t)
		r.edit = func(p string, b []byte) []byte {
			return []byte(strings.Replace(string(b), `"`+r.srv.URL+`/integrity/sigstore/3.6.1/sigstore-3.6.1.tar.gz/provenance"`, "null", 1))
		}
		res := r.check(pypiPkg("3.6.1", sigstoreWheel, sigstoreSdist))
		if res.Outcome != Published || len(res.Attestations) == 0 || !strings.Contains(res.Detail, "1 of 2") {
			t.Errorf("%+v", res)
		}
	})
}

func TestCargo(t *testing.T) {
	r := newRegistry(t)
	r.raw["/se/rd/serde"] = `{"name":"serde","vers":"1.0.209","cksum":"aa"}` + "\n" + `{"name":"serde","vers":"1.0.210","cksum":"C8E3"}` + "\n"
	pkg := func(v, sum string) lockfile.Package {
		return lockfile.Package{Ecosystem: "cargo", Name: "serde", Version: v, Archives: []string{"sha256:" + sum}}
	}
	for _, c := range []struct {
		p    lockfile.Package
		want string
	}{
		{pkg("1.0.210", "c8e3"), Published},
		{pkg("1.0.210", "aa"), Mismatch},
		{pkg("9.9.9", "c8e3"), NotFound},
		{lockfile.Package{Ecosystem: "cargo", Name: "serde", Version: "1.0.210"}, Unhashed},
	} {
		if res := r.check(c.p); res.Outcome != c.want {
			t.Errorf("%+v: %+v, want %s", c.p, res, c.want)
		}
	}
	for name, want := range map[string]string{"a": "1/a", "ab": "2/ab", "abc": "3/a/abc", "Serde_JSON": "se/rd/serde_json"} {
		if got := crateIndexPath(name); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
}

func TestGoChecksumDatabase(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "sum.test")
	if err != nil {
		t.Fatal(err)
	}
	gosum := func(path, vers string) ([]byte, error) {
		if path == "example.com/private" {
			return nil, os.ErrNotExist
		}
		return []byte(path + " " + vers + " h1:good=\n" + path + " " + vers + "/go.mod h1:mod=\n"), nil
	}
	srv := httptest.NewServer(sumdb.NewServer(sumdb.NewTestServer(skey, gosum)))
	defer srv.Close()
	check := func(key string, p lockfile.Package) Result {
		c := NewChecker(Registries{GoSum: srv.URL, GoSumKey: key}, nil)
		return c.Check(context.Background(), []lockfile.Package{p})[0]
	}
	mod := func(name, hash string) lockfile.Package {
		return lockfile.Package{Ecosystem: "golang", Name: name, Version: "v1.0.0", Hash: hash}
	}
	for _, c := range []struct {
		key  string
		p    lockfile.Package
		want string
	}{
		{vkey, mod("example.com/a", "h1:good="), Logged},
		{vkey, mod("example.com/a", "h1:evil="), Mismatch},
		{vkey, mod("example.com/private", "h1:good="), NotFound},
		{"sum.test+00000000+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", mod("example.com/a", "h1:good="), Error},
	} {
		if res := check(c.key, c.p); res.Outcome != c.want {
			t.Errorf("%s %s: %+v, want %s", c.p.Name, c.p.Hash, res, c.want)
		}
	}
}

func TestCheckDeduplicates(t *testing.T) {
	r := npmRegistry(t)
	p := npmPkg(t, semverIntegrity)
	res := r.checker().Check(context.Background(), []lockfile.Package{p, p})
	if len(res) != 1 {
		t.Errorf("the same locked package was checked %d times", len(res))
	}
}

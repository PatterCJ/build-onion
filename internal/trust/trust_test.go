package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `apiVersion: build-onion/trust/v1
builders:
  # build-onion itself
  - repository: PatterCJ/build-onion
    tagSigners:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFJ3KAvvJbVkYNEbTcSipRyJVpjRqqSJJrGLeG2862oF maintainer
    releases: []
`

// key is a tag signer in authorized_keys form, quoted for a YAML flow list.
const key = `"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFJ3KAvvJbVkYNEbTcSipRyJVpjRqqSJJrGLeG2862oF maintainer"`

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "trust.yml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAppendAndTrusted(t *testing.T) {
	p := write(t, sample)
	commit := strings.Repeat("a", 40)
	if err := Append(p, "pattercj/build-onion", Release{Tag: "v0.1.0", Commit: commit, Added: "2026-10-01"}); err != nil {
		t.Fatal(err)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := f.Trusted("PatterCJ/build-onion", commit); !ok || r.Tag != "v0.1.0" {
		t.Errorf("appended release not trusted: %+v", f.Builders)
	}
	if _, ok := f.Trusted("PatterCJ/build-onion", strings.Repeat("b", 40)); ok {
		t.Error("unknown commit trusted")
	}
	if _, ok := f.Trusted("someone/fork", commit); ok {
		t.Error("commit trusted for another repository")
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), "# build-onion itself") {
		t.Errorf("comments lost:\n%s", raw)
	}
	if err := Append(p, "PatterCJ/build-onion", Release{Tag: "again", Commit: commit}); err == nil || !strings.Contains(err.Error(), "already trusted") {
		t.Errorf("duplicate appended: %v", err)
	}
	if err := Append(p, "other/repo", Release{Tag: "v1", Commit: commit}); err == nil {
		t.Error("appended to a builder that isn't listed")
	}
}

func TestValidate(t *testing.T) {
	for name, body := range map[string]string{
		"bad version":                 strings.Replace(sample, "trust/v1", "trust/v0", 1),
		"bad key":                     strings.Replace(sample, "ssh-ed25519 AAAA", "ssh-ed25519 !!!", 1),
		"short commit":                strings.Replace(sample, "releases: []", "releases: [{tag: v1, commit: abc}]", 1),
		"unknown key":                 sample + "extra: 1\n",
		"bad repo":                    strings.Replace(sample, "PatterCJ/build-onion", "not a repo", 1),
		"app twice, written two ways": sample + "apps:\n  - repository: gitlab.com/acme/app\n    tagSigners: [" + key + "]\n  - repository: https://GitLab.com/acme/app\n    tagSigners: [" + key + "]\n",
		"bad app repo":                sample + "apps:\n  - repository: gitlab.com/app\n    tagSigners: [" + key + "]\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	f, err := Load(write(t, sample+"apps:\n  - repository: gitlab.com/acme/group/app\n    tagSigners: ["+key+"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if f.App("https://gitlab.com/acme/group/app") == nil || f.App("acme/group") != nil || f.App("github.com/acme/group/app") != nil {
		t.Error("app on another host matched wrongly")
	}
}

func TestKeyBuilders(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	indent := "        " + strings.ReplaceAll(strings.TrimSpace(pemKey), "\n", "\n        ")
	body := sample + "  - name: acme-kms\n    key: |\n" + indent + "\n"
	f, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if k := f.Keys(); len(k) != 1 || k["acme-kms"] == nil || !k["acme-kms"].Equal(&key.PublicKey) {
		t.Errorf("keys = %v", k)
	}
	priv, _ := x509.MarshalECPrivateKey(key)
	privPEM := "        " + strings.ReplaceAll(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv}))), "\n", "\n        ")
	for name, b := range map[string]string{
		"key without name":   sample + "  - key: |\n" + indent + "\n",
		"private key":        sample + "  - name: oops\n    key: |\n" + privPEM + "\n",
		"key and repository": sample + "  - name: k\n    repository: a/b\n    key: |\n" + indent + "\n",
	} {
		if _, err := Load(write(t, b)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

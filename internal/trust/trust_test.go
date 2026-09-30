package trust

import (
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
		"bad version":  strings.Replace(sample, "trust/v1", "trust/v0", 1),
		"bad key":      strings.Replace(sample, "ssh-ed25519 AAAA", "ssh-ed25519 !!!", 1),
		"short commit": strings.Replace(sample, "releases: []", "releases: [{tag: v1, commit: abc}]", 1),
		"unknown key":  sample + "extra: 1\n",
		"bad repo":     strings.Replace(sample, "PatterCJ/build-onion", "not a repo", 1),
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

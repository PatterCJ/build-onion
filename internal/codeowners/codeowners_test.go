package codeowners

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, loc, body string) *File {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, filepath.FromSlash(loc))
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(dir)
	if err != nil || f == nil {
		t.Fatalf("load: %v %v", f, err)
	}
	return f
}

func TestOwners(t *testing.T) {
	f := load(t, ".github/CODEOWNERS", `
# default owner
*                     @acme/devs
*.m4                  @acme/build
/build-onion.yml      @acme/build   # the manifest
docs/                 @acme/writers
/scripts/release/     @acme/release
/config/*             @acme/config
vendor/generated.go
`)
	cases := map[string]string{
		"main.go":                    "@acme/devs",
		"m4/build-to-host.m4":        "@acme/build", // unanchored: any depth
		"build-onion.yml":            "@acme/build",
		"sub/build-onion.yml":        "@acme/devs", // anchored to the root
		"docs/guide.md":              "@acme/writers",
		"api/docs/x.md":              "@acme/writers", // unanchored directory
		"scripts/release/publish.sh": "@acme/release",
		"vendor/generated.go":        "", // listed with no owners: unowned
		"config/app.yml":             "@acme/config",
		"config/nested/app.yml":      "@acme/devs", // config/* covers one level only
	}
	for p, want := range cases {
		if got := strings.Join(f.Owners(p), " "); got != want {
			t.Errorf("%s: owners %q, want %q", p, got, want)
		}
	}
	if got := f.Unowned([]string{"main.go", "vendor/generated.go"}); len(got) != 1 || got[0] != "vendor/generated.go" {
		t.Errorf("unowned = %v", got)
	}
}

func TestLocationsAndErrors(t *testing.T) {
	if f := load(t, "docs/CODEOWNERS", "* @a\n"); f.Path != "docs/CODEOWNERS" {
		t.Errorf("path = %s", f.Path)
	}
	dir := t.TempDir()
	if f, err := Load(dir); f != nil || err != nil {
		t.Errorf("no file: %v %v", f, err)
	}
	os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte("!*.md @a\n"), 0o644)
	if _, err := Load(dir); err == nil {
		t.Error("negation accepted")
	}
}

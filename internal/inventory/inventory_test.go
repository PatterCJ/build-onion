package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/digest"
)

const manifestYAML = `apiVersion: build-onion/v1
name: widget
builder:
  image: docker.io/library/golang:1.27.1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
dependencies:
  lockfiles: [go.sum]
  fetch: go mod download
  cache: /go/pkg/mod
build:
  run: go build -o dist/widget .
outputs:
  files: [dist/widget]
`

const goSum = `gopkg.in/yaml.v3 v3.0.1 h1:aaa=
gopkg.in/yaml.v3 v3.0.1/go.mod h1:bbb=
github.com/only/gomod v1.0.0/go.mod h1:ccc=
github.com/a/b v1.2.0 h1:ddd=
`

func TestGenerate(t *testing.T) {
	src, files := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(src, "build-onion.yml"), []byte(manifestYAML), 0o644)
	os.WriteFile(filepath.Join(src, "go.sum"), []byte(goSum), 0o644)
	os.WriteFile(filepath.Join(src, "go.mod"), []byte("module github.com/acme/widget\n\ngo 1.27\n"), 0o644)
	os.WriteFile(filepath.Join(files, "widget"), []byte("binary"), 0o755)

	inv, _, err := Generate(Params{
		SourceDir: src, ManifestPath: "build-onion.yml",
		Repository: "https://github.com/acme/widget", Commit: "c", Tree: "t", FilesDir: files,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := inv.Outputs; len(got) != 1 || got[0].Digest != digest.Bytes([]byte("binary")) || got[0].Kind != "file" {
		t.Errorf("outputs = %+v", got)
	}
	if inv.Manifest.Digest != digest.Bytes([]byte(manifestYAML)) {
		t.Error("manifest digest is not over the committed bytes")
	}
	if inv.Build.Network != "none" {
		t.Errorf("network = %q", inv.Build.Network)
	}
	var names []string
	for _, d := range inv.Dependencies {
		names = append(names, d.Name+"@"+d.Version)
	}
	// go.mod-only entries are not linked code and must not be listed.
	if strings.Join(names, ",") != "github.com/a/b@v1.2.0,gopkg.in/yaml.v3@v3.0.1" {
		t.Errorf("dependencies = %v", names)
	}
	if len(inv.MainModules) != 1 || inv.MainModules[0] != "github.com/acme/widget" {
		t.Errorf("main modules = %v", inv.MainModules)
	}
}

func TestGenerateMissingOutput(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "build-onion.yml"), []byte(manifestYAML), 0o644)
	os.WriteFile(filepath.Join(src, "go.sum"), []byte(goSum), 0o644)
	os.WriteFile(filepath.Join(src, "go.mod"), []byte("module m\n"), 0o644)
	_, _, err := Generate(Params{SourceDir: src, ManifestPath: "build-onion.yml", FilesDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "output dist/widget") {
		t.Fatalf("err = %v", err)
	}
}

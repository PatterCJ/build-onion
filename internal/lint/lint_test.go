package lint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pin = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func write(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDockerfile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "Dockerfile")
	write(t, p, "FROM golang:1.27"+pin+" AS build\nFROM build AS test\nFROM scratch\nFROM --platform=linux/amd64 alpine:3\n")
	err := Dockerfile(p)
	if err == nil || !strings.Contains(err.Error(), "Dockerfile:4: FROM alpine:3") {
		t.Fatalf("err = %v", err)
	}
	if strings.Count(err.Error(), "not pinned") != 1 {
		t.Fatalf("stage references or scratch were flagged: %v", err)
	}
}

func TestWorkflows(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "ci.yml"), `jobs:
  a:
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - uses: actions/setup-go@v7
      - uses: ./.github/actions/local
      - uses: "docker://alpine:3"
  b:
    uses: ./.github/workflows/onion-build.yml
`)
	err := Workflows(dir)
	if err == nil {
		t.Fatal("unpinned uses accepted")
	}
	for _, want := range []string{"ci.yml:5: actions/setup-go@v7", "ci.yml:7: docker://alpine:3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	if strings.Count(err.Error(), "\n")+1 != 2 {
		t.Errorf("want exactly 2 findings, got %v", err)
	}
}

func TestWorkflowsMissingDirIsFine(t *testing.T) {
	if err := Workflows(filepath.Join(t.TempDir(), "nope")); err != nil {
		t.Fatal(err)
	}
}

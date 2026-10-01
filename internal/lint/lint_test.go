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

func TestFinalBase(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "Dockerfile")
	cases := map[string]string{
		"FROM golang:1.27" + pin + " AS build\nRUN go build\nFROM gcr.io/distroless/static" + pin + "\nCOPY --from=build /app /app\n": "gcr.io/distroless/static" + pin,
		"FROM alpine" + pin + " AS base\nFROM base AS final\n":                                                                        "alpine" + pin,
		"FROM golang:1.27" + pin + " AS build\nFROM scratch\n":                                                                        "",
	}
	for body, want := range cases {
		write(t, p, body)
		got, err := FinalBase(p)
		if err != nil || got != want {
			t.Errorf("%q => %q, %v; want %q", body, got, err, want)
		}
	}
}

func TestSensitiveCoverage(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "Makefile"), "all:\n")
	write(t, filepath.Join(dir, "m4/build-to-host.m4"), "dnl\n")
	if err := sensitiveCoverage(dir, []string{"Makefile", "**/*.m4"}); err != nil {
		t.Fatal(err)
	}
	if err := sensitiveCoverage(dir, []string{"Makefile", "scripts/**"}); err == nil || !strings.Contains(err.Error(), `"scripts/**"`) {
		t.Fatalf("stale pattern accepted: %v", err)
	}
}

func TestGitLabCI(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".gitlab-ci.yml")
	if err := GitLabCI(p); err != nil {
		t.Errorf("no pipeline file: %v", err)
	}
	pinned := "include:\n  - local: ci/x.yml\nbuild:\n  image: docker.io/library/alpine@sha256:" + strings.Repeat("a", 64) + "\n  script: [true]\n"
	os.WriteFile(p, []byte(pinned), 0o644)
	if err := GitLabCI(p); err != nil {
		t.Errorf("pinned pipeline: %v", err)
	}
	os.WriteFile(p, []byte(pinned+"scan:\n  image: alpine:3\n  services: [docker:dind]\n"), 0o644)
	err := GitLabCI(p)
	if err == nil || !strings.Contains(err.Error(), "docker://alpine:3 is not pinned") || !strings.Contains(err.Error(), "docker://docker:dind is not pinned") {
		t.Errorf("unpinned images: %v", err)
	}
}

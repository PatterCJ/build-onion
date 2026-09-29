package manifest

import (
	"strings"
	"testing"
)

const valid = `apiVersion: build-onion/v1
name: demo
builder:
  image: docker.io/library/golang:1.27@sha256:` + sixtyFour + `
dependencies:
  lockfiles: [go.sum]
  fetch: go mod download
  cache: /go/pkg/mod
build:
  run: go build -o dist/demo .
  env:
    CGO_ENABLED: "0"
outputs:
  files: [dist/demo]
  image:
    name: ghcr.io/example/demo
    dockerfile: Dockerfile
`

const sixtyFour = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestValid(t *testing.T) {
	m, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	if m.Outputs.Image.Context != "." {
		t.Errorf("image context default = %q", m.Outputs.Image.Context)
	}
}

func TestEgressAccepted(t *testing.T) {
	src := strings.Replace(valid, "  cache: /go/pkg/mod\n", `  cache: /go/pkg/mod
  env: {GOPROXY: "https://artifactory.acme.internal/go"}
  egress:
    - host: proxy.golang.org
    - host: "*.googleusercontent.com"
    - host: artifactory.acme.internal
      port: 8443
      private: true
`, 1)
	m, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(m.Dependencies.Egress) != 3 || m.Dependencies.Egress[0].EffectivePort() != 443 || !m.Dependencies.Egress[2].Private {
		t.Fatalf("egress = %+v", m.Dependencies.Egress)
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	if _, err := Parse([]byte(valid + "extra: true\n")); err == nil {
		t.Fatal("unknown top-level key accepted")
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"builder by tag":      {"golang:1.27@sha256:" + sixtyFour, "golang:1.27", "builder.image"},
		"wrong api":           {"build-onion/v1", "build-onion/v0", "apiVersion"},
		"lockfile escapes":    {"[go.sum]", "[../go.sum]", "escapes the repo root"},
		"absolute output":     {"[dist/demo]", "[/tmp/demo]", "must be relative"},
		"fetch without cache": {"  cache: /go/pkg/mod\n", "", "set together"},
		"relative cache":      {"cache: /go/pkg/mod", "cache: go/pkg/mod", "absolute path"},
		"image with tag":      {"ghcr.io/example/demo", "ghcr.io/example/demo:latest", "outputs.image.name"},
		"empty run":           {"run: go build -o dist/demo .", "run: \"\"", "build.run"},
		"output with space":   {"[dist/demo]", "[\"dist/my demo\"]", "may only contain"},
		"output with newline": {"[dist/demo]", "[\"dist/demo\\nevil\"]", "may only contain"},
		"output with glob":    {"[dist/demo]", "[\"dist/*\"]", "may only contain"},
		"lockfile with quote": {"[go.sum]", "[\"go'.sum\"]", "may only contain"},
		"egress IP literal":   {"  cache: /go/pkg/mod\n", "  cache: /go/pkg/mod\n  egress: [{host: 10.0.0.5}]\n", "no IP addresses"},
		"egress with scheme":  {"  cache: /go/pkg/mod\n", "  cache: /go/pkg/mod\n  egress: [{host: 'https://proxy.golang.org'}]\n", "lowercase DNS name"},
		"egress uppercase":    {"  cache: /go/pkg/mod\n", "  cache: /go/pkg/mod\n  egress: [{host: Proxy.Golang.org}]\n", "lowercase DNS name"},
		"egress bare TLD":     {"  cache: /go/pkg/mod\n", "  cache: /go/pkg/mod\n  egress: [{host: localhost}]\n", "lowercase DNS name"},
		"egress duplicate":    {"  cache: /go/pkg/mod\n", "  cache: /go/pkg/mod\n  egress: [{host: a.example.com}, {host: a.example.com, port: 443}]\n", "listed twice"},
		"egress bad port":     {"  cache: /go/pkg/mod\n", "  cache: /go/pkg/mod\n  egress: [{host: a.example.com, port: 70000}]\n", "out of range"},
		"proxy env override":  {"  cache: /go/pkg/mod\n", "  cache: /go/pkg/mod\n  env: {https_proxy: http://evil:1}\n", "can't be overridden"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			src := strings.Replace(valid, tc.from, tc.to, 1)
			if src == valid {
				t.Fatalf("replacement %q not found", tc.from)
			}
			m, err := Parse([]byte(src))
			if err == nil {
				err = m.Validate()
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestDigestIsOverExactBytes(t *testing.T) {
	if Digest([]byte(valid)) == Digest([]byte(valid+"\n")) {
		t.Fatal("digest ignored a byte change")
	}
}

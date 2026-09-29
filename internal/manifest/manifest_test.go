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

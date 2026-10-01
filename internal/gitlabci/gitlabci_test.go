package gitlabci

import (
	"reflect"
	"strings"
	"testing"
)

var (
	sha      = strings.Repeat("a", 40)
	digest   = "@sha256:" + strings.Repeat("b", 64)
	sri      = "sha256-" + strings.Repeat("A", 43) + "="
	pipeline = `
spec:
  inputs:
    stage: {default: test}
---
include:
  - local: /ci/common.yml
  - project: acme/ci
    ref: ` + sha + `
    file: [/build.yml, deploy.yml]
  - component: gitlab.com/acme/scan@` + sha + `
  - remote: https://example.com/ci.yml
    integrity: ` + sri + `
  - template: Jobs/SAST.gitlab-ci.yml
image: docker.io/library/alpine` + digest + `
default:
  image:
    name: docker.io/library/docker` + digest + `
  services:
    - docker.io/library/docker:27-dind
    - name: registry.example.com/db` + digest + `
variables:
  image: not-an-image
.base:
  image: $CI_REGISTRY_IMAGE/builder:latest
build:
  extends: .base
  image: !reference [.base, image]
  script: [make]
child:
  trigger:
    include: child.yml
`
)

func TestReferences(t *testing.T) {
	got, err := References([]byte(pipeline))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"./ci/common.yml",
		"project:acme/ci/build.yml@" + sha,
		"project:acme/ci/deploy.yml@" + sha,
		"component:gitlab.com/acme/scan@" + sha,
		"remote:https://example.com/ci.yml@" + sri,
		"template:Jobs/SAST.gitlab-ci.yml",
		"docker://docker.io/library/alpine" + digest,
		"docker://docker.io/library/docker" + digest,
		"docker://docker.io/library/docker:27-dind",
		"docker://registry.example.com/db" + digest,
		"docker://$CI_REGISTRY_IMAGE/builder:latest",
		"./child.yml",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("references:\n got %q\nwant %q", got, want)
	}
	var loose []string
	for _, r := range got {
		if !Pinned(r) {
			loose = append(loose, r)
		}
	}
	wantLoose := []string{
		"template:Jobs/SAST.gitlab-ci.yml",
		"docker://docker.io/library/docker:27-dind",
		"docker://$CI_REGISTRY_IMAGE/builder:latest",
	}
	if !reflect.DeepEqual(loose, wantLoose) {
		t.Errorf("unpinned:\n got %q\nwant %q", loose, wantLoose)
	}
}

func TestPinned(t *testing.T) {
	for ref, want := range map[string]bool{
		"project:acme/ci/x.yml@main":                     false,
		"project:acme/ci/x.yml":                          false,
		"project:acme/ci/x.yml@" + sha:                   true,
		"project:$GROUP/ci/x.yml@" + sha:                 false,
		"component:gitlab.com/acme/scan@1.2.0":           false,
		"component:gitlab.com/acme/scan@~latest":         false,
		"remote:https://example.com/ci.yml":              false,
		"remote:https://example.com/ci.yml@sha256-short": false,
		"./$FILE":                 false,
		"docker://alpine:3":       false,
		"actions/checkout@" + sha: false,
	} {
		if got := Pinned(ref); got != want {
			t.Errorf("Pinned(%q) = %v, want %v", ref, got, want)
		}
	}
}

func TestReferencesErrors(t *testing.T) {
	for name, body := range map[string]string{
		"unknown include": "include:\n  - foo: bar\n",
		"bad yaml":        "include: [\n",
	} {
		if _, err := References([]byte(body)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

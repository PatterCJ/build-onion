package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/PatterCJ/build-onion/internal/attest"
)

// bundleAbout re-targets a real bundle's statement at another digest. The
// signature no longer verifies, which doesn't matter for storing it.
func bundleAbout(t *testing.T, digest string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/v0.2.1-onion-provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var b map[string]any
	json.Unmarshal(raw, &b)
	env := b["dsseEnvelope"].(map[string]any)
	payload, _ := base64.StdEncoding.DecodeString(env["payload"].(string))
	var st map[string]any
	json.Unmarshal(payload, &st)
	st["subject"] = []any{map[string]any{"name": "ghcr.io/acme/widget", "digest": map[string]any{"sha256": strings.TrimPrefix(digest, "sha256:")}}}
	payload, _ = json.Marshal(st)
	env["payload"] = base64.StdEncoding.EncodeToString(payload)
	out, _ := json.Marshal(b)
	return out
}

func TestPushBundlesAndFindAttestations(t *testing.T) {
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	img, _ := random.Image(128, 1)
	tag, _ := name.NewTag(u.Host + "/acme/widget:v1")
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	d, _ := img.Digest()
	ref := tag.Context().Name() + "@" + d.String()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "image.jsonl"), append(bundleAbout(t, d.String()), '\n'), 0o644)
	// A bundle about something else in the same directory isn't pushed.
	other, _ := os.ReadFile("testdata/v0.2.1-onion-provenance.json")
	os.WriteFile(filepath.Join(dir, "file.json"), other, 0o644)

	if err := cmdPushBundles([]string{"--image", ref, "--bundles", dir}); err != nil {
		t.Fatal(err)
	}
	if err := cmdPushBundles([]string{"--image", ref, "--bundles", dir}); err != nil {
		t.Fatalf("second push: %v", err)
	}
	cands, err := findAttestations("registry", "acme/widget", ref, d.String(), false)
	if err != nil || len(cands) != 1 {
		t.Fatalf("registry: %d candidate(s), %v", len(cands), err)
	}
	if about, _ := cands[0].About(d.String()); !about {
		t.Error("fetched bundle isn't about the image")
	}
	if _, err := findAttestations("registry", "acme/widget", "testdata/v0.2.1-onion-provenance.json", d.String(), false); err == nil {
		t.Error("registry source accepted a local file")
	}

	empty := t.TempDir()
	if err := cmdPushBundles([]string{"--image", ref, "--bundles", empty}); err == nil {
		t.Error("nothing to push, but no error")
	}
	if got := attest.Dedupe(append(cands, cands...)); len(got) != 1 {
		t.Errorf("dedupe kept %d", len(got))
	}
}

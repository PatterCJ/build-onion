package main

import (
	"os"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/signer"
)

// The check after signing uses peel's verifier: a real bundle passes for its
// subject's digest and fails for any other.
func TestCheckBundle(t *testing.T) {
	raw, err := os.ReadFile("testdata/v0.2.1-onion-provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := attest.NewAnyIdentityVerifier("testdata/trusted-root.json")
	if err != nil {
		t.Fatal(err)
	}
	sub := func(d string) []signer.Subject {
		return []signer.Subject{{Name: "onion", Digest: map[string]string{"sha256": d}}}
	}
	if err := checkBundle(v, raw, sub("8a39b80ea38fe480176d89b21c8ddf04c194c16848523559bcc13c02d8cd0edf")); err != nil {
		t.Fatalf("real bundle rejected: %v", err)
	}
	if err := checkBundle(v, raw, sub(strings.Repeat("0", 64))); err == nil {
		t.Error("bundle accepted for another digest")
	}
	if err := checkBundle(v, []byte(`{"mediaType":"nope"}`), sub(strings.Repeat("0", 64))); err == nil {
		t.Error("malformed bundle accepted")
	}
}

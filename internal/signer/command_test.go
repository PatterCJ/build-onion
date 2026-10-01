package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/PatterCJ/build-onion/internal/attest"
)

// TestHelperSigner is the "external signer" in these tests: the test binary
// run again, signing stdin with a throwaway key from $SIGNER_KEY. It is not
// a test on its own.
func TestHelperSigner(t *testing.T) {
	path := os.Getenv("SIGNER_KEY")
	if path == "" {
		return
	}
	raw, _ := os.ReadFile(path)
	block, _ := pem.Decode(raw)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	data, _ := io.ReadAll(os.Stdin)
	if os.Getenv("SIGNER_GARBAGE") != "" {
		fmt.Println("not base64!")
		os.Exit(0)
	}
	sum := sha256.Sum256(data)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, sum[:])
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
	os.Exit(0)
}

// newKey writes a throwaway private key to a temp dir (deleted after the
// test) and returns the signer command for it and its public key.
func newKey(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	path := filepath.Join(t.TempDir(), "key.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
	return fmt.Sprintf("SIGNER_KEY=%s %s -test.run='^TestHelperSigner$'", path, os.Args[0]), &key.PublicKey
}

func statementFor(t *testing.T, d string) []byte {
	st, err := NewStatement([]Subject{{Name: "widget", Digest: map[string]string{"sha256": d}}}, "https://example.com/p", []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestCommandSigner(t *testing.T) {
	script, pub := newKey(t)
	d := strings.Repeat("d", 64)
	raw, err := (&Command{Script: script, PublicKey: pub}).Sign(context.Background(), statementFor(t, d))
	if err != nil {
		t.Fatal(err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	v, err := attest.NewKeyVerifier(map[string]*ecdsa.PublicKey{"acme release key": pub})
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(attest.Candidate{Bundle: &b}, "sha256:"+d)
	if err != nil || got.Key != "acme release key" || got.Statement.PredicateType != "https://example.com/p" {
		t.Fatalf("verify: %+v %v", got, err)
	}
	if _, err := v.Verify(attest.Candidate{Bundle: &b}, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Error("verified for another digest")
	}
	_, otherPub := newKey(t)
	other, _ := attest.NewKeyVerifier(map[string]*ecdsa.PublicKey{"other": otherPub})
	if _, err := other.Verify(attest.Candidate{Bundle: &b}, "sha256:"+d); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("verified with an untrusted key: %v", err)
	}
}

// The signer's output is checked before it's used: a different key, or
// something that isn't a signature, fails.
func TestCommandSignerChecksTheSignature(t *testing.T) {
	script, _ := newKey(t)
	_, otherPub := newKey(t)
	st := statementFor(t, strings.Repeat("d", 64))
	if _, err := (&Command{Script: script, PublicKey: otherPub}).Sign(context.Background(), st); err == nil || !strings.Contains(err.Error(), "doesn't verify") {
		t.Errorf("signature from another key accepted: %v", err)
	}
	_, pub := newKey(t)
	if _, err := (&Command{Script: "SIGNER_GARBAGE=1 " + script, PublicKey: pub}).Sign(context.Background(), st); err == nil {
		t.Error("garbage accepted as a signature")
	}
	if _, err := (&Command{Script: "exit 3", PublicKey: pub}).Sign(context.Background(), st); err == nil || !strings.Contains(err.Error(), "signer command") {
		t.Errorf("failing command: %v", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if _, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err != nil {
		t.Errorf("P-256 public key: %v", err)
	}
	priv, _ := x509.MarshalECPrivateKey(ec)
	if _, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv})); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Errorf("private key accepted: %v", err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rder, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	if _, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rder})); err == nil {
		t.Error("RSA key accepted")
	}
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/signer"
)

// TestHelperKeySigner is the external signer for TestAttestWithKey: this
// test binary run again, with a throwaway key from $SIGNER_KEY.
func TestHelperKeySigner(t *testing.T) {
	path := os.Getenv("SIGNER_KEY")
	if path == "" {
		return
	}
	raw, _ := os.ReadFile(path)
	block, _ := pem.Decode(raw)
	key, _ := x509.ParseECPrivateKey(block.Bytes)
	data, _ := io.ReadAll(os.Stdin)
	sum := sha256.Sum256(data)
	sig, _ := ecdsa.SignASN1(rand.Reader, key, sum[:])
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
	os.Exit(0)
}

func TestAttestWithKey(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(key)
	keyPath := filepath.Join(dir, "key.pem")
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPath := filepath.Join(dir, "key.pub")
	os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644)
	pred := filepath.Join(dir, "p.json")
	os.WriteFile(pred, []byte(`{"x":1}`), 0o644)
	out := filepath.Join(dir, "bundle.json")
	d := strings.Repeat("e", 64)
	script := fmt.Sprintf("SIGNER_KEY=%s %s -test.run='^TestHelperKeySigner$'", keyPath, os.Args[0])

	err := cmdAttest([]string{"--subject", "ghcr.io/acme/widget@sha256:" + d, "--predicate", pred,
		"--predicate-type", "https://example.com/p", "--signer-command", script, "--public-key", pubPath, "--out", out})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	v, _ := attest.NewKeyVerifier(map[string]*ecdsa.PublicKey{"k": &key.PublicKey})
	if err := checkBundle(v, raw, []signer.Subject{{Name: "x", Digest: map[string]string{"sha256": d}}}); err != nil {
		t.Errorf("written bundle doesn't verify: %v", err)
	}

	if err := cmdAttest([]string{"--subject", "x@sha256:" + d, "--predicate", pred, "--predicate-type", "t",
		"--signer-command", script, "--out", out}); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Errorf("--signer-command without --public-key: %v", err)
	}
	if err := cmdAttest([]string{"--subject", "x@sha256:" + d, "--predicate", pred, "--predicate-type", "t",
		"--signer-command", script, "--public-key", keyPath, "--out", out}); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Errorf("private key as --public-key: %v", err)
	}
}

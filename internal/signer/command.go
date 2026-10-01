package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
)

// Command signs with a key onion never holds: the bytes to sign go to an
// external command's stdin (a KMS or HSM client, cosign, an in-house
// signer), which writes the signature, base64-encoded, to stdout. Every
// signature is checked against PublicKey before it is used, so a signer
// that used another key, or returned garbage, fails here.
type Command struct {
	// Shell command run with /bin/sh -c, inheriting onion's environment
	// (where the KMS credentials are).
	Script    string
	PublicKey *ecdsa.PublicKey
}

// LoadPublicKey reads a PEM public key. ECDSA P-256 and P-384 are supported.
func LoadPublicKey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(raw)
}

// ParsePublicKey parses a PEM public key.
func ParsePublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM public key")
	}
	if block.Type == "PRIVATE KEY" || strings.Contains(block.Type, "PRIVATE") {
		return nil, errors.New("this is a private key; give onion only the public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok || (ec.Curve != elliptic.P256() && ec.Curve != elliptic.P384()) {
		return nil, errors.New("unsupported key: use ECDSA P-256 or P-384")
	}
	return ec, nil
}

// KeyHint is how a bundle names its verification key: base64(sha256(DER)).
func KeyHint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

func (c *Command) Sign(ctx context.Context, statement []byte) ([]byte, error) {
	if len(statement) == 0 {
		return nil, errors.New("empty statement")
	}
	if c.Script == "" || c.PublicKey == nil {
		return nil, errors.New("a signer command and its public key are required")
	}
	b, err := sign.Bundle(&sign.DSSEData{Data: statement, PayloadType: InTotoPayloadType}, &commandKeypair{c}, sign.BundleOptions{Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return protojson.Marshal(b)
}

// commandKeypair adapts Command to sigstore-go's signing.
type commandKeypair struct{ c *Command }

func (k *commandKeypair) p384() bool { return k.c.PublicKey.Curve == elliptic.P384() }

func (k *commandKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	if k.p384() {
		return protocommon.HashAlgorithm_SHA2_384
	}
	return protocommon.HashAlgorithm_SHA2_256
}

func (k *commandKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	if k.p384() {
		return protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384
	}
	return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256
}

func (k *commandKeypair) GetHint() []byte {
	h, _ := KeyHint(k.c.PublicKey)
	return []byte(h)
}

func (k *commandKeypair) GetKeyAlgorithm() string        { return "ECDSA" }
func (k *commandKeypair) GetPublicKey() crypto.PublicKey { return k.c.PublicKey }

func (k *commandKeypair) GetPublicKeyPem() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(k.c.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// SignData runs the command over data and checks the signature it returns.
func (k *commandKeypair) SignData(ctx context.Context, data []byte) ([]byte, []byte, error) {
	var digest []byte
	if k.p384() {
		s := sha512.Sum384(data)
		digest = s[:]
	} else {
		s := sha256.Sum256(data)
		digest = s[:]
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", k.c.Script)
	cmd.Stdin = bytes.NewReader(data)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, nil, fmt.Errorf("signer command: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(stdout.String()))
	if err != nil || len(sig) == 0 {
		return nil, nil, errors.New("signer command must print the signature, base64-encoded, on stdout")
	}
	if !ecdsa.VerifyASN1(k.c.PublicKey, digest, sig) {
		return nil, nil, errors.New("the signer command's signature doesn't verify with the given public key")
	}
	return sig, digest, nil
}

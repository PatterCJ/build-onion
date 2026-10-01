// Package signer turns an in-toto statement into a signed Sigstore bundle.
// How it is signed is a choice of Signer, so the same records can be sealed
// on any CI platform; the bundle format, and how peel verifies it, stay the
// same.
package signer

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/sign"
	"google.golang.org/protobuf/encoding/protojson"
)

// InTotoPayloadType is the DSSE payload type of an in-toto statement.
const InTotoPayloadType = "application/vnd.in-toto+json"

// Public-good Sigstore, which GitHub also uses for public repositories.
const (
	PublicFulcio = "https://fulcio.sigstore.dev"
	PublicRekor  = "https://rekor.sigstore.dev"
)

// Signer signs an in-toto statement and returns a Sigstore bundle (JSON).
type Signer interface {
	Sign(ctx context.Context, statement []byte) ([]byte, error)
}

// Keyless signs with a key that exists only for this signature. A
// certificate authority (Fulcio) certifies it for the CI job's OIDC
// identity, and the signature is recorded in a transparency log (Rekor),
// so the bundle names the job that signed it and when.
type Keyless struct {
	// Token returns the CI job's OIDC token, with audience "sigstore".
	Token func(ctx context.Context) (string, error)
	// Certificates issues the signing certificate; Fulcio in production.
	Certificates sign.CertificateProvider
	// Logs record the signature; Rekor in production. A bundle without a
	// transparency log entry is refused by peel's default verifier.
	Logs []sign.Transparency
}

// NewKeyless signs through the given Fulcio and Rekor instances.
func NewKeyless(token func(context.Context) (string, error), fulcioURL, rekorURL string) *Keyless {
	return &Keyless{
		Token:        token,
		Certificates: sign.NewFulcio(&sign.FulcioOptions{BaseURL: fulcioURL, Timeout: 30 * time.Second, Retries: 2}),
		Logs:         []sign.Transparency{sign.NewRekor(&sign.RekorOptions{BaseURL: rekorURL, Timeout: 90 * time.Second, Retries: 2})},
	}
}

func (k *Keyless) Sign(ctx context.Context, statement []byte) ([]byte, error) {
	if len(statement) == 0 {
		return nil, errors.New("empty statement")
	}
	token, err := k.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("OIDC token: %w", err)
	}
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, err
	}
	b, err := sign.Bundle(&sign.DSSEData{Data: statement, PayloadType: InTotoPayloadType}, keypair, sign.BundleOptions{
		CertificateProvider:        k.Certificates,
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: token},
		TransparencyLogs:           k.Logs,
		Context:                    ctx,
	})
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return protojson.Marshal(b)
}

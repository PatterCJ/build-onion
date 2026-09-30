// Package attest finds Sigstore bundles for an artifact digest and verifies
// them: signature, transparency log, certificate identity, and that the
// signed statement names the artifact as its subject.
package attest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/golang/snappy"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/PatterCJ/build-onion/internal/digest"
)

// GitHubIssuer is the OIDC issuer for GitHub Actions workload identities.
const GitHubIssuer = "https://token.actions.githubusercontent.com"

// Statement is an in-toto v1 statement with the predicate left raw.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Verified is a statement whose signature and identity checked out.
type Verified struct {
	Statement   Statement
	Certificate certificate.Summary
	Source      string // where the bundle came from, for the report
}

// Identity pins who may have signed: the build-onion reusable workflow.
type Identity struct {
	// SignerWorkflow is owner/repo/.github/workflows/file.yml; any ref is
	// accepted unless SignerRef is also set.
	SignerWorkflow string
	SignerRef      string
}

func (id Identity) sanRegex() string {
	ref := `.+`
	if id.SignerRef != "" {
		ref = regexp.QuoteMeta(id.SignerRef)
	}
	return `^https://github\.com/` + regexp.QuoteMeta(id.SignerWorkflow) + `@` + ref + `$`
}

// Verifier checks bundles against a Sigstore trust root.
type Verifier struct {
	sev *verify.Verifier
	id  *verify.CertificateIdentity // nil: any identity, recorded by the caller
}

// NewVerifier uses trustedRootPath if set, otherwise fetches the Sigstore
// public-good root over TUF (what GitHub uses for public repositories).
func NewVerifier(trustedRootPath string, id Identity) (*Verifier, error) {
	v, err := NewAnyIdentityVerifier(trustedRootPath)
	if err != nil {
		return nil, err
	}
	certID, err := verify.NewShortCertificateIdentity(GitHubIssuer, "", "", id.sanRegex())
	if err != nil {
		return nil, err
	}
	v.id = &certID
	return v, nil
}

// NewAnyIdentityVerifier checks signature, certificate chain and
// transparency log, but accepts any signer. It is for third-party bundles
// (a dependency's provenance) where the caller records who signed rather
// than requiring someone in particular.
func NewAnyIdentityVerifier(trustedRootPath string) (*Verifier, error) {
	var tm root.TrustedMaterial
	var err error
	if trustedRootPath != "" {
		tm, err = root.NewTrustedRootFromPath(trustedRootPath)
	} else {
		tm, err = root.FetchTrustedRoot()
	}
	if err != nil {
		return nil, fmt.Errorf("trusted root: %w", err)
	}
	sev, err := verify.NewVerifier(tm,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, err
	}
	return &Verifier{sev: sev}, nil
}

// Verify checks one candidate bundle for the given artifact digest.
func (v *Verifier) Verify(c Candidate, artifactDigest string) (*Verified, error) {
	alg, raw, err := splitDigest(artifactDigest)
	if err != nil {
		return nil, err
	}
	idOpt := verify.WithoutIdentitiesUnsafe()
	if v.id != nil {
		idOpt = verify.WithCertificateIdentity(*v.id)
	}
	res, err := v.sev.Verify(c.Bundle, verify.NewPolicy(verify.WithArtifactDigest(alg, raw), idOpt))
	if err != nil {
		return nil, err
	}
	if res.Statement == nil {
		return nil, errors.New("bundle carries no in-toto statement")
	}
	if res.Signature == nil || res.Signature.Certificate == nil {
		return nil, errors.New("bundle not signed by a Fulcio certificate")
	}
	js, err := protojson.Marshal(res.Statement)
	if err != nil {
		return nil, err
	}
	var st Statement
	if err := json.Unmarshal(js, &st); err != nil {
		return nil, err
	}
	return &Verified{Statement: st, Certificate: *res.Signature.Certificate, Source: c.Source}, nil
}

// IdentityMismatch reports whether a verification error means the bundle is
// validly signed, but by an identity other than the expected signer.
// sigstore-go checks identity only after the signature and transparency log
// verify, so this error implies a genuine bundle from someone else, which is
// different from a bundle whose signature is invalid.
func IdentityMismatch(err error) bool {
	var e *verify.ErrNoMatchingCertificateIdentity
	return errors.As(err, &e)
}

// Candidate is an unverified bundle and where it came from.
type Candidate struct {
	Bundle *bundle.Bundle
	Source string
}

// About reports, without verifying anything, whether the bundle's statement
// names artifactDigest as a subject. It only routes bundles that are plainly
// for other artifacts away from verification (a bundles directory usually
// holds several artifacts' bundles); a bundle that does name the artifact
// must still pass Verify. known is false when the statement can't be read,
// in which case the caller should verify.
func (c Candidate) About(artifactDigest string) (about, known bool) {
	if c.Bundle == nil {
		return false, false
	}
	env, err := c.Bundle.Envelope()
	if err != nil {
		return false, false
	}
	st, err := env.Statement()
	if err != nil {
		return false, false
	}
	alg, h, _ := strings.Cut(artifactDigest, ":")
	for _, s := range st.GetSubject() {
		if s.GetDigest()[alg] == h {
			return true, true
		}
	}
	return false, true
}

// FromDir loads every *.json and *.jsonl bundle under dir. Unparseable files
// are reported, not skipped silently.
func FromDir(dir string) ([]Candidate, error) {
	var out []Candidate
	var errs []error
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var docs [][]byte
		switch filepath.Ext(p) {
		case ".json":
			docs = [][]byte{raw}
		case ".jsonl":
			for _, line := range strings.Split(string(raw), "\n") {
				if strings.TrimSpace(line) != "" {
					docs = append(docs, []byte(line))
				}
			}
		default:
			return nil
		}
		for i, doc := range docs {
			var b bundle.Bundle
			if err := b.UnmarshalJSON(doc); err != nil {
				errs = append(errs, fmt.Errorf("%s[%d]: %w", p, i, err))
				continue
			}
			out = append(out, Candidate{Bundle: &b, Source: p})
		}
		return nil
	})
	return out, errors.Join(append(errs, err)...)
}

// FromGitHub lists attestations for a digest in owner/repo via the REST API.
// token may be empty for public repositories.
func FromGitHub(ctx context.Context, repo, artifactDigest, token string) ([]Candidate, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/attestations/%s?per_page=100", repo, artifactDigest)
	body, err := get(ctx, url, token, true)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Attestations []struct {
			Bundle    json.RawMessage `json:"bundle"`
			BundleURL string          `json:"bundle_url"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("attestations response: %w", err)
	}
	var out []Candidate
	for i, a := range resp.Attestations {
		raw := []byte(a.Bundle)
		if len(raw) == 0 || string(raw) == "null" {
			if a.BundleURL == "" {
				continue
			}
			// Bundles served by URL are snappy-compressed.
			comp, err := get(ctx, a.BundleURL, "", false)
			if err != nil {
				return nil, err
			}
			if raw, err = snappy.Decode(nil, comp); err != nil {
				return nil, fmt.Errorf("attestation %d: decompress bundle: %w", i, err)
			}
		}
		var b bundle.Bundle
		if err := b.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("attestation %d: %w", i, err)
		}
		out = append(out, Candidate{Bundle: &b, Source: fmt.Sprintf("github:%s#%d", repo, i)})
	}
	return out, nil
}

func get(ctx context.Context, url, token string, api bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if api {
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("GET %s: no attestations found", url)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return body, nil
}

// splitDigest accepts "sha256:<hex>" (what build-onion produces) and
// "sha512:<hex>" (what some other signers use).
func splitDigest(d string) (string, []byte, error) {
	alg, h, _ := strings.Cut(d, ":")
	if alg != "sha256" && alg != "sha512" {
		return "", nil, fmt.Errorf("unsupported digest %q", d)
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (alg == "sha256" && !digest.Valid(d)) || (alg == "sha512" && len(raw) != 64) {
		return "", nil, fmt.Errorf("invalid digest %q", d)
	}
	return alg, raw, nil
}

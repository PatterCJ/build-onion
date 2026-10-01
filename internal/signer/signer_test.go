package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// The predicate GitHub's actions/attest wrote for v0.2.1, rebuilt from the
// same run's environment, must come out identical.
func TestGitHubProvenanceMatchesGitHub(t *testing.T) {
	env := map[string]string{
		"GITHUB_SERVER_URL":          "https://github.com",
		"GITHUB_REPOSITORY":          "PatterCJ/build-onion",
		"GITHUB_REF":                 "refs/tags/v0.2.1",
		"GITHUB_SHA":                 "eef9130eb38ada0d8c6ab0ea0dcc716974020fd4",
		"GITHUB_WORKFLOW_REF":        "PatterCJ/build-onion/.github/workflows/release.yml@refs/tags/v0.2.1",
		"GITHUB_EVENT_NAME":          "push",
		"GITHUB_RUN_ID":              "36792116882",
		"GITHUB_RUN_ATTEMPT":         "1",
		"GITHUB_REPOSITORY_ID":       "1396531592",
		"GITHUB_REPOSITORY_OWNER_ID": "89419020",
		"RUNNER_ENVIRONMENT":         "github-hosted",
	}
	claims := map[string]any{"job_workflow_ref": "PatterCJ/build-onion/.github/workflows/onion-verify.yml@refs/tags/v0.2.1"}
	got, err := GitHubProvenance(func(k string) string { return env[k] }, claims)
	if err != nil {
		t.Fatal(err)
	}
	wantRaw, err := os.ReadFile("testdata/github-provenance-v0.2.1.json")
	if err != nil {
		t.Fatal(err)
	}
	var g, w any
	json.Unmarshal(got, &g)
	json.Unmarshal(wantRaw, &w)
	if !reflect.DeepEqual(g, w) {
		t.Errorf("provenance differs from GitHub's\n got: %s\nwant: %s", got, wantRaw)
	}

	delete(env, "RUNNER_ENVIRONMENT")
	if _, err := GitHubProvenance(func(k string) string { return env[k] }, claims); err == nil || !strings.Contains(err.Error(), "RUNNER_ENVIRONMENT") {
		t.Errorf("missing variable not reported: %v", err)
	}
	env["RUNNER_ENVIRONMENT"] = "github-hosted"
	if _, err := GitHubProvenance(func(k string) string { return env[k] }, map[string]any{}); err == nil {
		t.Error("missing job_workflow_ref claim accepted")
	}
}

func TestStatement(t *testing.T) {
	d := strings.Repeat("a", 64)
	subs, err := SubjectsFromChecksums([]byte(d + "  onion\n" + strings.Repeat("b", 64) + " *other.tar\n\n"))
	if err != nil || len(subs) != 2 || subs[0].Name != "onion" || subs[1].Name != "other.tar" {
		t.Fatalf("checksums: %+v %v", subs, err)
	}
	img, err := SubjectFromRef("ghcr.io/acme/widget@sha256:" + d)
	if err != nil || img.Name != "ghcr.io/acme/widget" {
		t.Fatalf("ref: %+v %v", img, err)
	}
	st, err := NewStatement(subs, "https://example.com/p", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	var s Statement
	json.Unmarshal(st, &s)
	if s.Type != StatementType || len(s.Subject) != 2 || string(s.Predicate) != `{"a":1}` {
		t.Errorf("statement = %s", st)
	}
	for name, f := range map[string]func() error{
		"no subjects":     func() error { _, e := NewStatement(nil, "t", []byte(`{}`)); return e },
		"no type":         func() error { _, e := NewStatement(subs, "", []byte(`{}`)); return e },
		"array predicate": func() error { _, e := NewStatement(subs, "t", []byte(`[1]`)); return e },
		"bad checksum":    func() error { _, e := SubjectsFromChecksums([]byte("xyz  onion\n")); return e },
		"tag, not digest": func() error { _, e := SubjectFromRef("ghcr.io/acme/widget:v1"); return e },
	} {
		if f() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// testCA issues Fulcio-style certificates for whatever key it is asked to
// certify, for a fixed identity.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test fulcio"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key}
}

const (
	testIdentity = "https://github.com/PatterCJ/build-onion/.github/workflows/onion-verify.yml@refs/tags/v9.9.9"
	testIssuer   = "https://token.actions.githubusercontent.com"
)

func (ca *testCA) GetCertificate(_ context.Context, kp sign.Keypair, opts *sign.CertificateProviderOptions) ([]byte, error) {
	if opts == nil || opts.IDToken != "test-token" {
		return nil, os.ErrPermission
	}
	san, _ := url.Parse(testIdentity)
	issuerExt, _ := asn1.Marshal(testIssuer)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(10 * time.Minute),
		URIs: []*url.URL{san}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: issuerExt}},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.cert, kp.GetPublicKey().(crypto.PublicKey), ca.key)
}

type testRoot struct {
	root.BaseTrustedMaterial
	ca *testCA
}

func (r *testRoot) FulcioCertificateAuthorities() []root.CertificateAuthority {
	return []root.CertificateAuthority{&root.FulcioCertificateAuthority{Root: r.ca.cert,
		ValidityPeriodStart: time.Now().Add(-time.Hour), ValidityPeriodEnd: time.Now().Add(time.Hour)}}
}

// A keyless bundle verifies for the certified identity, with the statement
// as its signed payload, and names the subject's digest.
func TestKeylessSign(t *testing.T) {
	ca := newTestCA(t)
	d := strings.Repeat("c", 64)
	st, _ := NewStatement([]Subject{{Name: "onion", Digest: map[string]string{"sha256": d}}}, "https://example.com/p", []byte(`{"x":1}`))
	k := &Keyless{Token: func(context.Context) (string, error) { return "test-token", nil }, Certificates: ca}
	raw, err := k.Sign(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	v, err := verify.NewVerifier(&testRoot{ca: ca}, verify.WithCurrentTime())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := verify.NewShortCertificateIdentity(testIssuer, "", testIdentity, "")
	digest, _ := hex.DecodeString(d)
	res, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(id)))
	if err != nil {
		t.Fatalf("bundle doesn't verify: %v", err)
	}
	if res.Statement.GetPredicateType() != "https://example.com/p" {
		t.Errorf("statement = %v", res.Statement)
	}

	// Another digest, or another identity, doesn't verify.
	if _, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", make([]byte, 32)), verify.WithCertificateIdentity(id))); err == nil {
		t.Error("verified for another digest")
	}
	other, _ := verify.NewShortCertificateIdentity(testIssuer, "", "https://github.com/evil/x/.github/workflows/y.yml@refs/heads/main", "")
	if _, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest), verify.WithCertificateIdentity(other))); err == nil {
		t.Error("verified for another identity")
	}

	// No token, no signature.
	k.Token = func(context.Context) (string, error) { return "", os.ErrNotExist }
	if _, err := k.Sign(context.Background(), st); err == nil {
		t.Error("signed without a token")
	}
}

// The token is requested from GitHub's endpoint with audience "sigstore",
// keeping the query GitHub's URL already has.
func TestGitHubToken(t *testing.T) {
	var gotQuery url.Values
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery, gotAuth = r.URL.Query(), r.Header.Get("Authorization")
		if gotAuth != "Bearer req-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"value":"the.oidc.token"}`))
	}))
	defer srv.Close()
	env := map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": srv.URL + "/token?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "req-token"}
	old := getenv
	getenv = func(k string) string { return env[k] }
	defer func() { getenv = old }()

	tok, err := GitHubToken(context.Background())
	if err != nil || tok != "the.oidc.token" {
		t.Fatalf("token %q, %v", tok, err)
	}
	if gotQuery.Get("audience") != "sigstore" || gotQuery.Get("api-version") != "2.0" {
		t.Errorf("query = %v", gotQuery)
	}
	env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "wrong"
	if _, err := GitHubToken(context.Background()); err == nil {
		t.Error("rejected request accepted")
	}
	delete(env, "ACTIONS_ID_TOKEN_REQUEST_URL")
	if _, err := GitHubToken(context.Background()); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Errorf("missing token endpoint: %v", err)
	}
}

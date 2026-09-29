package attest

import (
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// The fixtures are a real GitHub Actions–signed bundle (npm provenance for
// sigstore-js 1.3.0) and the public-good trusted root, both copied from
// sigstore-go's examples. They exercise the full crypto path offline.
const (
	fixtureDigest = "sha512:76176ffa33808b54602c7c35de5c6e9a4deb96066dba6533f50ac234f4f1f4c6b3527515dc17c06fbe2860030f410eee69ea20079bd3a2c6f3dcf3b329b10751"
	fixtureSigner = "sigstore/sigstore-js/.github/workflows/release.yml"
)

func load(t *testing.T) Candidate {
	t.Helper()
	b, err := bundle.LoadJSONFromPath("testdata/bundle-provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	return Candidate{Bundle: b, Source: "fixture"}
}

func verifier(t *testing.T, id Identity) *Verifier {
	t.Helper()
	v, err := NewVerifier("testdata/trusted-root-public-good.json", id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyRealBundle(t *testing.T) {
	v := verifier(t, Identity{SignerWorkflow: fixtureSigner, SignerRef: "refs/heads/main"})
	got, err := v.Verify(load(t), fixtureDigest)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Statement.PredicateType != "https://slsa.dev/provenance/v0.2" {
		t.Errorf("predicate type %q", got.Statement.PredicateType)
	}
	if got.Certificate.SourceRepositoryURI != "https://github.com/sigstore/sigstore-js" {
		t.Errorf("source repo %q", got.Certificate.SourceRepositoryURI)
	}
	if got.Source != "fixture" {
		t.Errorf("source %q", got.Source)
	}
}

func TestVerifyRejects(t *testing.T) {
	cases := map[string]struct {
		id     Identity
		digest string
		want   string
	}{
		"wrong signer workflow": {
			id:     Identity{SignerWorkflow: "PatterCJ/build-onion/.github/workflows/onion-build.yml"},
			digest: fixtureDigest,
			want:   "no matching CertificateIdentity",
		},
		"wrong signer ref": {
			id:     Identity{SignerWorkflow: fixtureSigner, SignerRef: "refs/tags/v9"},
			digest: fixtureDigest,
			want:   "no matching CertificateIdentity",
		},
		"different artifact": {
			id:     Identity{SignerWorkflow: fixtureSigner},
			digest: "sha512:" + strings.Repeat("0", 128),
			want:   "digest",
		},
		"malformed digest": {
			id:     Identity{SignerWorkflow: fixtureSigner},
			digest: "md5:abc",
			want:   "unsupported digest",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := verifier(t, tc.id).Verify(load(t), tc.digest)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if got, want := IdentityMismatch(err), tc.want == "no matching CertificateIdentity"; got != want {
				t.Errorf("IdentityMismatch = %v, want %v (%v)", got, want, err)
			}
		})
	}
}

func TestFromDir(t *testing.T) {
	cands, err := FromDir("testdata")
	// trusted-root-public-good.json is not a bundle and must be reported.
	if err == nil || !strings.Contains(err.Error(), "trusted-root-public-good.json") {
		t.Fatalf("want error naming the non-bundle file, got %v", err)
	}
	if len(cands) != 1 {
		t.Fatalf("got %d candidates, want 1", len(cands))
	}
}

func TestAbout(t *testing.T) {
	c := load(t)
	if about, known := c.About(fixtureDigest); !about || !known {
		t.Errorf("fixture digest: about=%v known=%v", about, known)
	}
	if about, known := c.About("sha256:" + strings.Repeat("0", 64)); about || !known {
		t.Errorf("other digest: about=%v known=%v", about, known)
	}
	if _, known := (Candidate{}).About(fixtureDigest); known {
		t.Error("empty candidate reported as known")
	}
}

package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/signer"
)

// onion attest: sign an in-toto statement about one or more artifacts and
// write the Sigstore bundle. The same command seals on any CI that can give
// the job an OIDC token.
func cmdAttest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ExitOnError)
	out := fs.String("out", "", "write the bundle here (required)")
	checksums := fs.String("subject-checksums", "", "sha256sum-format file naming the subjects")
	var refs stringList
	fs.Var(&refs, "subject", "subject as name@sha256:<hex> (repeatable)")
	predicate := fs.String("predicate", "", "predicate JSON file")
	predicateType := fs.String("predicate-type", "", "predicate type URI")
	provenance := fs.String("provenance", "", "generate SLSA v1 provenance for this CI instead of --predicate: github, or gitlab (with --signer-command)")
	token := fs.String("token", "github", "where the OIDC token comes from: github, or env:NAME")
	fulcio := fs.String("fulcio", signer.PublicFulcio, "Fulcio URL")
	rekor := fs.String("rekor", signer.PublicRekor, "Rekor URL")
	signerCommand := fs.String("signer-command", "", "sign with an external command instead of keyless: the bytes to sign go to its stdin, and it prints the signature, base64-encoded, on stdout (a KMS or HSM client)")
	publicKeyPath := fs.String("public-key", "", "with --signer-command: the PEM public key of the key it signs with (ECDSA P-256 or P-384)")
	trustedRoot := fs.String("trusted-root", "", "Sigstore trusted_root.json to check the new bundle against (default: public-good via TUF; required with --fulcio or --rekor)")
	fs.Parse(args)
	if *out == "" {
		return errors.New("--out is required")
	}
	keyMode := *signerCommand != "" || *publicKeyPath != ""
	if keyMode && (*signerCommand == "" || *publicKeyPath == "") {
		return errors.New("--signer-command and --public-key go together")
	}
	// peel verifies certificates only from GitHub Actions; on GitLab the
	// seal is a key's.
	if *provenance == "gitlab" && !keyMode {
		return errors.New("--provenance gitlab needs key signing (--signer-command and --public-key)")
	}
	if !keyMode && (*fulcio != signer.PublicFulcio || *rekor != signer.PublicRekor) && *trustedRoot == "" {
		return errors.New("with a private --fulcio or --rekor, pass --trusted-root so the bundle can be checked")
	}

	var subjects []signer.Subject
	if *checksums != "" {
		data, err := os.ReadFile(*checksums)
		if err != nil {
			return err
		}
		s, err := signer.SubjectsFromChecksums(data)
		if err != nil {
			return fmt.Errorf("%s: %w", *checksums, err)
		}
		subjects = append(subjects, s...)
	}
	for _, r := range refs {
		s, err := signer.SubjectFromRef(r)
		if err != nil {
			return err
		}
		subjects = append(subjects, s)
	}

	var tokenSource func(context.Context) (string, error)
	switch {
	case *token == "github":
		tokenSource = signer.GitHubToken
	case strings.HasPrefix(*token, "env:"):
		tokenSource = signer.EnvToken(strings.TrimPrefix(*token, "env:"))
	default:
		return fmt.Errorf("--token %q: want github or env:NAME", *token)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	// Fetch the token once: the provenance describes the run it names, and
	// Fulcio certifies the same token. A key signer needs one only to
	// describe a GitHub run.
	var tok string
	var err error
	if !keyMode || *provenance == "github" {
		if tok, err = tokenSource(ctx); err != nil {
			return err
		}
	}

	var pred []byte
	switch {
	case *provenance != "" && *predicate != "":
		return errors.New("use --predicate or --provenance, not both")
	case *provenance == "github":
		claims, err := signer.Claims(tok)
		if err != nil {
			return err
		}
		if pred, err = signer.GitHubProvenance(os.Getenv, claims); err != nil {
			return err
		}
		*predicateType = "https://slsa.dev/provenance/v1"
	case *provenance == "gitlab":
		if pred, err = signer.GitLabProvenance(os.Getenv); err != nil {
			return err
		}
		*predicateType = "https://slsa.dev/provenance/v1"
	case *provenance != "":
		return fmt.Errorf("--provenance %q: want github or gitlab", *provenance)
	case *predicate != "":
		if pred, err = os.ReadFile(*predicate); err != nil {
			return err
		}
	default:
		return errors.New("--predicate or --provenance is required")
	}

	statement, err := signer.NewStatement(subjects, *predicateType, pred)
	if err != nil {
		return err
	}
	var s signer.Signer
	var v bundleVerifier
	if keyMode {
		pub, err := signer.LoadPublicKey(*publicKeyPath)
		if err != nil {
			return fmt.Errorf("--public-key: %w", err)
		}
		s = &signer.Command{Script: *signerCommand, PublicKey: pub}
		if v, err = attest.NewKeyVerifier(map[string]*ecdsa.PublicKey{"signing key": pub}); err != nil {
			return err
		}
	} else {
		s = signer.NewKeyless(func(context.Context) (string, error) { return tok, nil }, *fulcio, *rekor)
		if v, err = attest.NewAnyIdentityVerifier(*trustedRoot); err != nil {
			return err
		}
	}
	b, err := s.Sign(ctx, statement)
	if err != nil {
		return err
	}
	// Never write a bundle peel wouldn't accept: check it now, with peel's
	// own verifier and rules, for every subject.
	if err := checkBundle(v, b, subjects); err != nil {
		return fmt.Errorf("the new bundle doesn't verify: %w", err)
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "attest: signed %s for %d subject(s) → %s\n", *predicateType, len(subjects), *out)
	return nil
}

type bundleVerifier interface {
	Verify(c attest.Candidate, digest string) (*attest.Verified, error)
}

// checkBundle verifies a bundle for each subject's digest.
func checkBundle(v bundleVerifier, raw []byte, subjects []signer.Subject) error {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return err
	}
	for _, s := range subjects {
		if _, err := v.Verify(attest.Candidate{Bundle: &b}, "sha256:"+s.Digest["sha256"]); err != nil {
			return fmt.Errorf("%s: %w", s.Name, err)
		}
	}
	return nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

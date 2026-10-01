package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

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
	provenance := fs.String("provenance", "", "generate SLSA v1 provenance for this CI instead of --predicate (github)")
	token := fs.String("token", "github", "where the OIDC token comes from: github, or env:NAME")
	fulcio := fs.String("fulcio", signer.PublicFulcio, "Fulcio URL")
	rekor := fs.String("rekor", signer.PublicRekor, "Rekor URL")
	fs.Parse(args)
	if *out == "" {
		return errors.New("--out is required")
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
	// Fulcio certifies the same token.
	tok, err := tokenSource(ctx)
	if err != nil {
		return err
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
	case *provenance != "":
		return fmt.Errorf("--provenance %q: only github is supported", *provenance)
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
	s := signer.NewKeyless(func(context.Context) (string, error) { return tok, nil }, *fulcio, *rekor)
	b, err := s.Sign(ctx, statement)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "attest: signed %s for %d subject(s) → %s\n", *predicateType, len(subjects), *out)
	return nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

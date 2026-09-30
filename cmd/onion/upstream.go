package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/source"
	"github.com/PatterCJ/build-onion/internal/upstream"
)

// onion upstream: check every locked dependency against its public registry
// and record what was found. It reports; peel grades.
func cmdUpstream(args []string) error {
	fs := flag.NewFlagSet("upstream", flag.ExitOnError)
	var s sourceFlags
	s.register(fs)
	snap := fs.String("snapshot", "", "verify the source against this snapshot first")
	out := fs.String("out", "", "write the record JSON here")
	trustedRoot := fs.String("trusted-root", "", "Sigstore trusted_root.json (default: public-good via TUF)")
	reg := upstream.DefaultRegistries()
	fs.StringVar(&reg.Npm, "npm-registry", reg.Npm, "npm registry")
	fs.StringVar(&reg.PyPI, "pypi", reg.PyPI, "PyPI (simple API and provenance)")
	fs.StringVar(&reg.Crates, "crates-index", reg.Crates, "crates.io sparse index")
	fs.StringVar(&reg.GoSum, "gosumdb", reg.GoSum, "Go checksum database (sum.golang.org or a proxy of it)")
	fs.StringVar(&reg.GoSumKey, "gosumdb-key", reg.GoSumKey, "verifier key for --gosumdb")
	verbose := fs.Bool("v", false, "list every package, not only the ones that need attention")
	fs.Parse(args)
	m, err := s.load()
	if err != nil {
		return err
	}
	if *snap != "" {
		var sn source.Snapshot
		if err := readJSON(*snap, &sn); err != nil {
			return err
		}
		if err := sn.Check(); err != nil {
			return err
		}
		d, err := source.Verify(s.source, &sn, nil)
		if err != nil {
			return err
		}
		if !d.Empty() {
			return d
		}
	}
	locks, err := inventory.ReadLockfiles(s.source, m)
	if err != nil {
		return err
	}
	v, err := attest.NewAnyIdentityVerifier(*trustedRoot)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	rec := upstream.Record{
		CheckedAt:  time.Now().UTC().Format(time.RFC3339),
		Registries: reg.Map(),
		Results:    upstream.NewChecker(reg, v).Check(ctx, locks.Packages),
	}
	for _, f := range locks.Files {
		if f.Ecosystem != "" {
			rec.Lockfiles = append(rec.Lockfiles, upstream.Lockfile{Path: f.Path, Digest: f.Digest})
		}
	}
	printUpstream(rec, *verbose)
	if *out != "" {
		return writeJSON(*out, rec)
	}
	return nil
}

func printUpstream(rec upstream.Record, all bool) {
	counts := map[string]int{}
	tw := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ECOSYSTEM\tPACKAGE\tVERSION\tOUTCOME\tDETAIL")
	for _, r := range rec.Results {
		counts[r.Outcome]++
		quiet := r.Outcome == upstream.Attested || r.Outcome == upstream.Logged || r.Outcome == upstream.Published
		if quiet && !all {
			continue
		}
		detail := r.Detail
		if len(r.Attestations) > 0 {
			detail = r.Attestations[0].Repository
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Ecosystem, r.Name, r.Version, r.Outcome, detail)
	}
	tw.Flush()
	fmt.Fprintf(os.Stderr, "upstream: %d package(s):", len(rec.Results))
	for _, o := range []string{upstream.Attested, upstream.Logged, upstream.Published, upstream.Unhashed, upstream.NotFound, upstream.Mismatch, upstream.Invalid, upstream.Error} {
		if counts[o] > 0 {
			fmt.Fprintf(os.Stderr, " %d %s", counts[o], o)
		}
	}
	fmt.Fprintln(os.Stderr)
}

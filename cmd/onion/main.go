// Command onion builds artifacts in layers and peels them back to prove how
// they were built.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/builder"
	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/egress"
	"github.com/PatterCJ/build-onion/internal/gate"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/lint"
	"github.com/PatterCJ/build-onion/internal/lockfile"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/peel"
	"github.com/PatterCJ/build-onion/internal/source"
	"github.com/PatterCJ/build-onion/internal/trust"
	"github.com/PatterCJ/build-onion/internal/upstream"
	"github.com/PatterCJ/build-onion/internal/verify"
)

// version is set in source, so a tag and the commit it points at build the
// same bytes.
var version = "0.1.0"

// defaultSigner is the security line: the only workflow that seals builds.
const defaultSigner = "PatterCJ/build-onion/.github/workflows/onion-verify.yml"

const usage = `onion — layered builds you can peel back

Usage:
  onion validate  [--source DIR] [--manifest FILE]
  onion source    snapshot --out FILE | verify --snapshot FILE [--expect DIGEST]
  onion gate      --snapshot FILE --event E --ref REF [--policy FILE] [--base SHA] [--out FILE]
  onion fetch     [--source DIR] [--manifest FILE] --cache DIR [--snapshot FILE] [--egress-out FILE]
  onion build     [--source DIR] [--manifest FILE] --cache DIR --out DIR [--snapshot FILE] [--stage-dir DIR]
  onion record    job|workflow|build-onion|scan --out FILE [flags]
  onion compare   --staged DIR --rebuilt DIR [--out FILE]
  onion upstream  [--source DIR] [--manifest FILE] [--snapshot FILE] [--out FILE] [-v]
  onion digest    [--oci] PATH...
  onion attest    (--subject NAME@sha256:HEX | --subject-checksums FILE) (--predicate FILE --predicate-type URI | --provenance github) --out FILE
  onion inventory --snapshot FILE --records DIR --repository URL --commit SHA --tree SHA --files DIR [flags]
  onion peel      ARTIFACT --repo OWNER/REPO [--commit SHA] [--ref REFS] [--baseline ARTIFACT] [--trust FILE] [--bundles DIR] [--source DIR] [--rebuild] [--oci] [--packages] [--json]
  onion trust     add --trust FILE --tag TAG [--repo OWNER/REPO]
  onion version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"validate":  cmdValidate,
		"source":    cmdSource,
		"gate":      cmdGate,
		"record":    cmdRecord,
		"compare":   cmdCompare,
		"upstream":  cmdUpstream,
		"attest":    cmdAttest,
		"trust":     cmdTrust,
		"proxy":     cmdProxy,
		"fetch":     cmdFetch,
		"build":     cmdBuild,
		"digest":    cmdDigest,
		"inventory": cmdInventory,
		"peel":      cmdPeel,
		"version":   func([]string) error { fmt.Println(version); return nil },
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		var exit exitCode
		if errors.As(err, &exit) {
			os.Exit(int(exit))
		}
		fmt.Fprintln(os.Stderr, "onion:", err)
		annotate("error", "onion "+os.Args[1], err.Error())
		os.Exit(1)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

type sourceFlags struct{ source, manifest string }

func (s *sourceFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.source, "source", ".", "source checkout")
	fs.StringVar(&s.manifest, "manifest", "build-onion.yml", "manifest path, relative to --source")
}

func (s *sourceFlags) load() (*manifest.Manifest, error) {
	m, _, err := manifest.Load(filepath.Join(s.source, s.manifest))
	if err != nil {
		return nil, err
	}
	return m, m.Validate()
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	var s sourceFlags
	s.register(fs)
	ghOut := fs.String("github-output", "", "append the build plan as key=value lines (for $GITHUB_OUTPUT)")
	fs.Parse(args)
	m, err := s.load()
	if err != nil {
		return err
	}
	if err := lint.Repo(s.source, m); err != nil {
		return err
	}
	if *ghOut != "" {
		if err := writePlan(*ghOut, m); err != nil {
			return err
		}
	}
	fmt.Printf("manifest %s ok: builder %s, %d lockfile(s), %d output file(s), image=%t\n",
		m.Name, m.Builder.Image, len(m.Dependencies.Lockfiles), len(m.Outputs.Files), m.Outputs.Image != nil)
	for _, l := range m.Dependencies.Lockfiles {
		if eco := lockfile.Ecosystem(l); eco != "" {
			fmt.Printf("  lockfile %s: %s packages will be proven against the artifact\n", l, eco)
		} else {
			fmt.Printf("  lockfile %s: hashed, but no parser; packages from it will grade UNSUPPORTED (supported: %s)\n",
				l, strings.Join(lockfile.Supported(), ", "))
		}
	}
	return nil
}

// writePlan exposes the manifest fields later workflow jobs branch on.
func writePlan(p string, m *manifest.Manifest) error {
	lines := []string{"name=" + m.Name, fmt.Sprintf("has_image=%t", m.Outputs.Image != nil)}
	if img := m.Outputs.Image; img != nil {
		lines = append(lines, "image_name="+img.Name, "dockerfile="+img.Dockerfile, "context="+img.Context)
	}
	return appendLines(p, lines...)
}

func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	var s sourceFlags
	s.register(fs)
	cache := fs.String("cache", "", "dependency cache directory to populate")
	snap := fs.String("snapshot", "", "verify the source against this snapshot before and after")
	egressOut := fs.String("egress-out", "", "write the fetch network record (mode, rules, connections) here")
	fs.Parse(args)
	if *cache == "" {
		return errors.New("--cache is required")
	}
	m, err := s.load()
	if err != nil {
		return err
	}
	var rec *egress.Record
	_, cleanup, err := guarded(s, *snap, "", m, func(dir string) error {
		var ferr error
		rec, ferr = builder.Runner{Stdout: os.Stderr, Stderr: os.Stderr}.Fetch(dir, *cache, m)
		return ferr
	})
	cleanup()
	// Written even when fetch failed: the record of what was attempted is
	// the evidence.
	if rec != nil {
		printEgress(rec)
		if *egressOut != "" {
			if werr := writeJSON(*egressOut, rec); werr != nil && err == nil {
				err = werr
			}
		}
	}
	return err
}

func printEgress(rec *egress.Record) {
	fmt.Fprintf(os.Stderr, "egress: %s\n", rec.Mode)
	if rec.Summary == nil {
		return
	}
	for _, c := range rec.Summary.Connections {
		verdict := "allowed"
		if !c.Allowed {
			verdict = "DENIED"
		}
		fmt.Fprintf(os.Stderr, "egress: %-7s %s:%d ×%d  out %d B  in %d B  %s\n", verdict, c.Host, c.Port, c.Count, c.BytesOut, c.BytesIn, c.Reason)
	}
}

// guarded runs a step against a staged copy of the declared build inputs:
// the checkout is verified against the snapshot, the inputs (build.inputs
// plus the manifest, lockfiles and Dockerfile) are copied into a stage and
// re-hashed, the step runs there, and afterwards every staged input must be
// unchanged and every new file declared. Without a snapshot (local use), the
// step runs in the checkout directly. cleanup removes a stage guarded made.
func guarded(s sourceFlags, snapPath, stageDir string, m *manifest.Manifest, step func(dir string) error) (string, func(), error) {
	noop := func() {}
	if snapPath == "" {
		return s.source, noop, step(s.source)
	}
	if err := verifySource(s.source, snapPath, "", m.Writable()); err != nil {
		return "", noop, fmt.Errorf("before step: %w", err)
	}
	snap, err := loadSnapshot(snapPath, "")
	if err != nil {
		return "", noop, err
	}
	inputs, err := snap.Subset(m.Build.Inputs, m.AlwaysInputs(s.manifest))
	if err != nil {
		return "", noop, err
	}
	cleanup := noop
	if stageDir == "" {
		if stageDir, err = os.MkdirTemp("", "onion-stage-"); err != nil {
			return "", noop, err
		}
		dir := stageDir
		cleanup = func() { os.RemoveAll(dir) }
	} else if entries, err := os.ReadDir(stageDir); err == nil && len(entries) > 0 {
		return "", noop, fmt.Errorf("stage directory %s is not empty", stageDir)
	}
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return "", cleanup, err
	}
	if err := source.Stage(s.source, stageDir, inputs); err != nil {
		return "", cleanup, err
	}
	fmt.Fprintf(os.Stderr, "stage: %d of %d tracked files are build inputs\n", len(inputs), len(snap.Files))
	if err := step(stageDir); err != nil {
		return stageDir, cleanup, err
	}
	d, err := source.VerifyStage(stageDir, inputs, m.Writable())
	if err != nil {
		return stageDir, cleanup, err
	}
	if !d.Empty() {
		return stageDir, cleanup, fmt.Errorf("after step: %w", d)
	}
	return stageDir, cleanup, nil
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	var s sourceFlags
	s.register(fs)
	cache := fs.String("cache", "", "dependency cache directory populated by fetch")
	out := fs.String("out", "", "directory to collect declared output files into")
	snap := fs.String("snapshot", "", "stage the declared inputs from this snapshot and verify them after the build")
	stageDir := fs.String("stage-dir", "", "keep the staged tree here (the image build's context); default: a temporary directory")
	fs.Parse(args)
	if *cache == "" || *out == "" {
		return errors.New("--cache and --out are required")
	}
	m, err := s.load()
	if err != nil {
		return err
	}
	dir, cleanup, err := guarded(s, *snap, *stageDir, m, func(dir string) error {
		return builder.Runner{Stdout: os.Stderr, Stderr: os.Stderr}.Build(dir, *cache, m)
	})
	defer cleanup()
	if err != nil {
		return err
	}
	digests, err := builder.Collect(dir, *out, m)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(digests))
	for n := range digests {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("%s  %s\n", digest.Hex(digests[n]), n)
	}
	return nil
}

func cmdDigest(args []string) error {
	fs := flag.NewFlagSet("digest", flag.ExitOnError)
	oci := fs.Bool("oci", false, "print the image manifest digest of an OCI layout tarball")
	fs.Parse(args)
	for _, p := range fs.Args() {
		var d string
		var err error
		if *oci {
			d, err = digest.OCIArchive(p)
		} else {
			d, err = digest.File(p)
		}
		if err != nil {
			return err
		}
		fmt.Println(d)
	}
	return nil
}

func cmdInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	var p inventory.Params
	fs.StringVar(&p.SourceDir, "source", ".", "checkout of the commit being built")
	fs.StringVar(&p.ManifestPath, "manifest", "build-onion.yml", "manifest path, relative to --source")
	fs.StringVar(&p.Repository, "repository", "", "source repository URL")
	fs.StringVar(&p.Commit, "commit", "", "source commit SHA")
	fs.StringVar(&p.Tree, "tree", "", "source tree SHA")
	fs.StringVar(&p.FilesDir, "files", "", "directory of built output files")
	fs.StringVar(&p.ImageArchive, "image-archive", "", "OCI layout tarball of the built image")
	fs.StringVar(&p.InvocationURL, "invocation", "", "URL of the run that built this")
	snapPath := fs.String("snapshot", "", "source snapshot taken before the build (required)")
	expect := fs.String("expect-snapshot", "", "require the snapshot to have this digest")
	records := fs.String("records", "", "directory of build-onion's own 'onion record' files (required)")
	scanRecords := fs.String("scan-records", "", "directory of scan records from the pipeline's own jobs (scan records only)")
	platform := fs.String("platform", "local", "CI platform name")
	gatePath := fs.String("gate", "", "gate verdict JSON from 'onion gate'")
	rebuildPath := fs.String("rebuild", "", "comparison JSON from 'onion compare'")
	upstreamPath := fs.String("upstream", "", "registry check JSON from 'onion upstream'")
	egressPath := fs.String("egress", "", "fetch network record from 'onion fetch --egress-out'")
	fs.Parse(args)
	if p.Repository == "" || p.Commit == "" || p.Tree == "" || p.FilesDir == "" || *snapPath == "" || *records == "" {
		return errors.New("--repository, --commit, --tree, --files, --snapshot and --records are required")
	}
	var err error
	if p.Snapshot, err = loadSnapshot(*snapPath, *expect); err != nil {
		return err
	}
	if p.Pipeline, err = inventory.ReadPipeline(*records, *platform); err != nil {
		return err
	}
	if *scanRecords != "" {
		scans, err := inventory.ReadScans(*scanRecords)
		if err != nil {
			return err
		}
		p.Pipeline.Scans = append(p.Pipeline.Scans, scans...)
	}
	if *gatePath != "" {
		p.Gate = new(gate.Verdict)
		if err := readJSON(*gatePath, p.Gate); err != nil {
			return err
		}
	}
	if *egressPath != "" {
		p.Egress = new(egress.Record)
		if err := readJSON(*egressPath, p.Egress); err != nil {
			return err
		}
	}
	if *rebuildPath != "" {
		p.Verification = &inventory.Verification{Rebuild: new(verify.Rebuild)}
		if err := readJSON(*rebuildPath, p.Verification.Rebuild); err != nil {
			return err
		}
	}
	if *upstreamPath != "" {
		p.Upstream = new(upstream.Record)
		if err := readJSON(*upstreamPath, p.Upstream); err != nil {
			return err
		}
	}
	p.ResolveBase = resolveBaseLayers
	inv, _, err := inventory.Generate(p)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(inv)
}

func cmdPeel(args []string) error {
	fs := flag.NewFlagSet("peel", flag.ExitOnError)
	repo := fs.String("repo", "", "OWNER/REPO the artifact claims to be built from (required)")
	commit := fs.String("commit", "", "commit the artifact claims to be built from")
	signer := fs.String("signer", defaultSigner, "reusable workflow allowed to sign (OWNER/REPO/PATH)")
	signerRef := fs.String("signer-ref", "", "exact signer ref, e.g. refs/tags/v1.0.0 (default: any)")
	bundles := fs.String("bundles", "", "directory of Sigstore bundles (default: GitHub attestations API)")
	trustedRoot := fs.String("trusted-root", "", "Sigstore trusted_root.json (default: public-good via TUF)")
	source := fs.String("source", "", "local checkout to peel down to the source layer")
	rebuild := fs.Bool("rebuild", false, "rebuild from --source and compare digests (needs docker)")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	allowDegraded := fs.Bool("allow-degraded", false, "exit 0 when the verdict is DEGRADED or UNSUPPORTED")
	packages := fs.Bool("packages", false, "list every package found in the artifact and its outcome")
	refs := fs.String("ref", "", "comma-separated refs the artifact must have been built from, e.g. 'refs/heads/main,refs/tags/v*'")
	oci := fs.Bool("oci", false, "ARTIFACT is an OCI image-layout tarball; verify its image digest")
	baseline := fs.String("baseline", "", "a previously sealed artifact (usually the last release) to compare with")
	trustPath := fs.String("trust", "", "trust file listing the build-onion releases allowed to have sealed the artifact")
	baselineBundles := fs.String("baseline-bundles", "", "directory of the baseline's Sigstore bundles (default: GitHub attestations API)")
	acceptSignerChanges := fs.Bool("accept-signer-changes", false, "with --baseline: report dependencies that lost provenance or changed signer as notes, not findings")
	artifact, rest := splitPositional(args)
	fs.Parse(rest)
	if artifact == "" && fs.NArg() == 1 {
		artifact = fs.Arg(0)
	}
	if artifact == "" || *repo == "" {
		return errors.New("usage: onion peel ARTIFACT --repo OWNER/REPO [flags]")
	}
	if *rebuild && *source == "" {
		return errors.New("--rebuild needs --source")
	}

	var d string
	var err error
	if *oci {
		d, err = digest.OCIArchive(artifact)
	} else {
		d, err = resolveDigest(artifact)
	}
	if err != nil {
		return err
	}
	id := attest.Identity{SignerWorkflow: *signer, SignerRef: *signerRef}
	v, err := attest.NewVerifier(*trustedRoot, id)
	if err != nil {
		return err
	}
	var trusted *trust.File
	if *trustPath != "" {
		if trusted, err = trust.Load(*trustPath); err != nil {
			return err
		}
	}
	candidates := func(dir, d string) ([]attest.Candidate, error) {
		if dir != "" {
			return attest.FromDir(dir)
		}
		return attest.FromGitHub(context.Background(), *repo, d, os.Getenv("GITHUB_TOKEN"))
	}
	cands, err := candidates(*bundles, d)
	if err != nil {
		return err
	}
	in := peel.Input{
		Artifact:   artifact,
		Digest:     d,
		Claim:      peel.Claim{Repository: *repo, Commit: *commit},
		Signer:     id,
		Verifier:   v,
		Candidates: cands,
		SourceDir:  *source,
		Rebuild:    *rebuild,
		Refs:       splitList(*refs),
		Trust:      trusted,
	}
	rep := peel.Run(in)
	if *baseline != "" {
		// The baseline is verified the same way, minus the claims about
		// this artifact's commit and checkout.
		base := &peel.Report{Artifact: *baseline, Verdict: peel.Failed}
		bd, err := resolveDigest(*baseline)
		if err == nil {
			var bc []attest.Candidate
			if bc, err = candidates(*baselineBundles, bd); err == nil {
				bin := in
				bin.Artifact, bin.Digest, bin.Candidates = *baseline, bd, bc
				bin.Claim.Commit, bin.SourceDir, bin.Rebuild = "", "", false
				base = peel.Run(bin)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "onion: baseline %s: %v\n", *baseline, err)
		}
		peel.Differential(rep, base, *acceptSignerChanges)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		printReport(os.Stdout, rep)
		if *packages {
			printPackages(os.Stdout, rep)
		}
	}
	annotateReport(rep)
	if code := rep.ExitCode(*allowDegraded); code != 0 {
		return exitCode(code)
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// splitPositional lets the artifact come before or after the flags.
func splitPositional(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

// resolveBaseLayers fetches a pinned base image's config for the platform the
// pipeline builds (linux/amd64) and returns its layer diffIDs. The reference
// is a digest, and go-containerregistry verifies every blob it reads.
func resolveBaseLayers(ref string) ([]string, error) {
	r, err := name.ParseReference(ref, name.StrictValidation)
	if err != nil {
		return nil, err
	}
	if _, ok := r.(name.Digest); !ok {
		return nil, fmt.Errorf("%s is not pinned by digest", ref)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	img, err := remote.Image(r, remote.WithContext(ctx),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}),
		remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(cfg.RootFS.DiffIDs))
	for i, d := range cfg.RootFS.DiffIDs {
		out[i] = d.String()
	}
	return out, nil
}

// resolveDigest hashes a local file, or resolves an image reference to its
// manifest digest (a tag is resolved once, then only the digest is trusted).
func resolveDigest(artifact string) (string, error) {
	if st, err := os.Stat(artifact); err == nil && !st.IsDir() {
		return digest.File(artifact)
	}
	ref, err := name.ParseReference(artifact, name.StrictValidation)
	if err != nil {
		return "", fmt.Errorf("%s is neither a file nor an image reference: %w", artifact, err)
	}
	if dig, ok := ref.(name.Digest); ok {
		return dig.DigestStr(), nil
	}
	desc, err := remote.Head(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", artifact, err)
	}
	return desc.Digest.String(), nil
}

func printPackages(w io.Writer, r *peel.Report) {
	fmt.Fprintf(w, "\npackages in %s (%d)\n", r.Artifact, len(r.Packages))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	up := map[string]string{}
	for _, u := range r.Upstream {
		up[upstream.Key(u.Ecosystem, u.Name, u.Version)] = u.Outcome
	}
	fmt.Fprintln(tw, "ECOSYSTEM\tPACKAGE\tVERSION\tOUTCOME\tUPSTREAM\tDETAIL")
	fmt.Fprintln(tw, "---------\t-------\t-------\t-------\t--------\t------")
	for _, p := range r.Packages {
		u := up[upstream.Key(p.Ecosystem, p.Name, p.Version)]
		if u == "" {
			u = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p.Ecosystem, p.Name, p.Version, p.Outcome, u, p.Detail)
	}
	tw.Flush()
}

func printReport(w io.Writer, r *peel.Report) {
	fmt.Fprintf(w, "peeling %s\n  %s\n\n", r.Artifact, r.Digest)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SECTION\tRESULT\tCHECK\tDETAIL")
	fmt.Fprintln(tw, "-------\t------\t-----\t------")
	layer := ""
	counts := map[peel.Status]int{}
	for _, res := range r.Results {
		l := ""
		if res.Layer != layer {
			layer, l = res.Layer, res.Layer
		}
		counts[res.Status]++
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l, res.Status, res.Check, res.Detail)
	}
	tw.Flush()
	if len(r.NotPerformed) > 0 {
		fmt.Fprintln(w)
	}
	for _, np := range r.NotPerformed {
		fmt.Fprintf(w, "not performed: %s\n", np)
	}
	var tally []string
	for _, st := range []peel.Status{peel.Finding, peel.Failed, peel.Unsupported, peel.Degraded, peel.Passed, peel.Note} {
		if counts[st] > 0 {
			tally = append(tally, fmt.Sprintf("%d %s", counts[st], strings.ToLower(string(st))))
		}
	}
	meaning := map[peel.Status]string{
		peel.Passed:      "built as claimed; every check completed",
		peel.Degraded:    "no violations found, but some coverage is incomplete",
		peel.Unsupported: "no violations found, but some inputs could not be analyzed",
		peel.Finding:     "a violation was found",
		peel.Failed:      "trustworthy evidence could not be produced",
	}
	fmt.Fprintf(w, "\n%s: %s (%s)\n", r.Verdict, meaning[r.Verdict], strings.Join(tally, ", "))
}

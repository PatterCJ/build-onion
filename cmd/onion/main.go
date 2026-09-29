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

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/builder"
	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/lint"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/peel"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

const defaultSigner = "PatterCJ/build-onion/.github/workflows/onion-build.yml"

const usage = `onion — layered builds you can peel back

Usage:
  onion validate  [--source DIR] [--manifest FILE]
  onion fetch     [--source DIR] [--manifest FILE] --cache DIR
  onion build     [--source DIR] [--manifest FILE] --cache DIR --out DIR
  onion digest    [--oci] PATH...
  onion inventory --source DIR --repository URL --commit SHA --tree SHA --files DIR [--image-archive TAR] [--invocation URL]
  onion peel      ARTIFACT --repo OWNER/REPO [--commit SHA] [--bundles DIR] [--source DIR] [--rebuild] [--json]
  onion version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"validate":  cmdValidate,
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
	return nil
}

// writePlan exposes the manifest fields later workflow jobs branch on.
func writePlan(p string, m *manifest.Manifest) error {
	lines := []string{"name=" + m.Name, fmt.Sprintf("has_image=%t", m.Outputs.Image != nil)}
	if img := m.Outputs.Image; img != nil {
		lines = append(lines, "image_name="+img.Name, "dockerfile="+img.Dockerfile, "context="+img.Context)
	}
	for _, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			return fmt.Errorf("plan value contains a newline: %q", l)
		}
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, strings.Join(lines, "\n"))
	return err
}

func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	var s sourceFlags
	s.register(fs)
	cache := fs.String("cache", "", "dependency cache directory to populate")
	fs.Parse(args)
	if *cache == "" {
		return errors.New("--cache is required")
	}
	m, err := s.load()
	if err != nil {
		return err
	}
	return builder.Runner{Stdout: os.Stderr, Stderr: os.Stderr}.Fetch(s.source, *cache, m)
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	var s sourceFlags
	s.register(fs)
	cache := fs.String("cache", "", "dependency cache directory populated by fetch")
	out := fs.String("out", "", "directory to collect declared output files into")
	fs.Parse(args)
	if *cache == "" || *out == "" {
		return errors.New("--cache and --out are required")
	}
	m, err := s.load()
	if err != nil {
		return err
	}
	if err := (builder.Runner{Stdout: os.Stderr, Stderr: os.Stderr}).Build(s.source, *cache, m); err != nil {
		return err
	}
	digests, err := builder.Collect(s.source, *out, m)
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
	fs.Parse(args)
	if p.Repository == "" || p.Commit == "" || p.Tree == "" || p.FilesDir == "" {
		return errors.New("--repository, --commit, --tree and --files are required")
	}
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

	d, err := resolveDigest(artifact)
	if err != nil {
		return err
	}
	var cands []attest.Candidate
	if *bundles != "" {
		cands, err = attest.FromDir(*bundles)
	} else {
		cands, err = attest.FromGitHub(context.Background(), *repo, d, os.Getenv("GITHUB_TOKEN"))
	}
	if err != nil {
		return err
	}
	id := attest.Identity{SignerWorkflow: *signer, SignerRef: *signerRef}
	v, err := attest.NewVerifier(*trustedRoot, id)
	if err != nil {
		return err
	}
	rep := peel.Run(peel.Input{
		Artifact:   artifact,
		Digest:     d,
		Claim:      peel.Claim{Repository: *repo, Commit: *commit},
		Signer:     id,
		Verifier:   v,
		Candidates: cands,
		SourceDir:  *source,
		Rebuild:    *rebuild,
	})
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		printReport(os.Stdout, rep)
	}
	if !rep.OK() {
		return exitCode(1)
	}
	return nil
}

// splitPositional lets the artifact come before or after the flags.
func splitPositional(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
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

func printReport(w io.Writer, r *peel.Report) {
	fmt.Fprintf(w, "peeling %s\n  %s\n\n", r.Artifact, r.Digest)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	layer := ""
	for _, res := range r.Results {
		l := ""
		if res.Layer != layer {
			layer, l = res.Layer, res.Layer
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", l, res.Status, res.Check, res.Detail)
	}
	tw.Flush()
	verdict := "VERIFIED: built as claimed"
	if !r.OK() {
		verdict = "NOT VERIFIED"
	}
	fmt.Fprintf(w, "\n%s\n", verdict)
}

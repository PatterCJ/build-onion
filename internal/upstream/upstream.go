// Package upstream checks each locked dependency against its public
// registry: that the bytes the lockfile pins are the bytes the registry
// publishes, and, where the registry carries it, that signed provenance ties
// those bytes to a source repository and build.
//
// It is an independent view. Where a build fetches through a mirror or proxy,
// the public registry is what the mirror should agree with.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/lockfile"
)

// Outcomes, strongest first.
const (
	// Attested: signed provenance verified, and its subject is an archive the
	// lockfile pins.
	Attested = "attested"
	// Logged: the lockfile's hash is the one in the ecosystem's public
	// checksum transparency log (Go's sum.golang.org).
	Logged = "logged"
	// Published: the lockfile's archives are the ones the registry publishes;
	// the registry has no provenance for them.
	Published = "published"
	// Unhashed: the lockfile pins no archive hash to compare.
	Unhashed = "unhashed"
	// NotFound: the package or version isn't on the public registry: a
	// private package, or one only a mirror serves.
	NotFound = "not-found"
	// Mismatch: the lockfile pins bytes the public registry doesn't publish
	// under that name and version.
	Mismatch = "mismatch"
	// Invalid: the registry serves provenance that fails verification, or
	// that is about other bytes.
	Invalid = "invalid"
	// Error: the registry couldn't be asked.
	Error = "error"
)

// Result is one package's outcome.
type Result struct {
	Ecosystem    string        `json:"ecosystem"`
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Outcome      string        `json:"outcome"`
	Detail       string        `json:"detail,omitempty"`
	Attestations []Attestation `json:"attestations,omitempty"`
}

// Attestation is one verified provenance bundle: the archive it is about and
// who signed it. The bundle itself isn't kept (a wheel-heavy package has
// dozens); its transparency log entry is public at LogIndex.
type Attestation struct {
	// Subject is the archive digest the bundle is about (alg:hex).
	Subject string `json:"subject"`
	File    string `json:"file,omitempty"`
	Signer
}

// Signer is who a verified bundle says built the archive, from its signing
// certificate, and where the signature is logged.
type Signer struct {
	Issuer     string `json:"issuer"`
	Repository string `json:"repository,omitempty"`
	Commit     string `json:"commit,omitempty"`
	Workflow   string `json:"workflow,omitempty"`
	LogIndex   int64  `json:"logIndex"`
}

// Record is what the check found, sealed into the inventory.
type Record struct {
	CheckedAt  string            `json:"checkedAt"`
	Registries map[string]string `json:"registries"`
	Lockfiles  []Lockfile        `json:"lockfiles"`
	Results    []Result          `json:"results"`
}

type Lockfile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// Registries are the public endpoints consulted.
type Registries struct {
	Npm    string // https://registry.npmjs.org
	PyPI   string // https://pypi.org
	Crates string // https://index.crates.io
	GoSum  string // https://sum.golang.org
	// GoSumKey verifies the checksum database's signed tree heads.
	GoSumKey string
}

func DefaultRegistries() Registries {
	return Registries{
		Npm:    "https://registry.npmjs.org",
		PyPI:   "https://pypi.org",
		Crates: "https://index.crates.io",
		GoSum:  "https://sum.golang.org",
		// As built into the go command (cmd/go/internal/modfetch/key.go).
		GoSumKey: "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8",
	}
}

func (r Registries) Map() map[string]string {
	return map[string]string{"npm": r.Npm, "pypi": r.PyPI, "cargo": r.Crates, "golang": r.GoSum}
}

// Checker queries registries. It is safe for concurrent use.
type Checker struct {
	Registries Registries
	Verifier   *attest.Verifier
	HTTP       *http.Client
	Workers    int

	sumdb *sumdbClient
}

func NewChecker(reg Registries, v *attest.Verifier) *Checker {
	c := &Checker{Registries: reg, Verifier: v, HTTP: &http.Client{Timeout: 30 * time.Second}, Workers: 8}
	c.sumdb = newSumdb(reg.GoSum, reg.GoSumKey, c.get)
	return c
}

// Check looks up every package. The same package locked by two lockfiles is
// looked up once per distinct set of archives.
func (c *Checker) Check(ctx context.Context, pkgs []lockfile.Package) []Result {
	seen := map[string]bool{}
	var todo []lockfile.Package
	for _, p := range pkgs {
		k := Key(p.Ecosystem, p.Name, p.Version) + " " + p.Hash + " " + strings.Join(p.Archives, ",")
		if !seen[k] {
			seen[k] = true
			todo = append(todo, p)
		}
	}
	out := make([]Result, len(todo))
	var wg sync.WaitGroup
	jobs := make(chan int)
	for range max(c.Workers, 1) {
		wg.Go(func() {
			for i := range jobs {
				out[i] = c.check(ctx, todo[i])
			}
		})
	}
	for i := range todo {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	sort.SliceStable(out, func(i, j int) bool {
		return Key(out[i].Ecosystem, out[i].Name, out[i].Version) < Key(out[j].Ecosystem, out[j].Name, out[j].Version)
	})
	return out
}

func (c *Checker) check(ctx context.Context, p lockfile.Package) Result {
	r := Result{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version}
	switch p.Ecosystem {
	case "golang":
		c.checkGo(p, &r)
	case "npm":
		c.checkNpm(ctx, p, &r)
	case "pypi":
		c.checkPyPI(ctx, p, &r)
	case "cargo":
		c.checkCargo(ctx, p, &r)
	default:
		r.Outcome, r.Detail = Error, "no registry check for this ecosystem"
	}
	return r
}

// Key identifies a package version across tools.
func Key(eco, name, version string) string {
	return eco + ":" + lockfile.Normalize(eco, name) + "@" + version
}

// errNotFound is a 404 or 410 from a registry.
var errNotFound = errors.New("not found")

func (c *Checker) get(ctx context.Context, url, accept string) ([]byte, error) {
	var last error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		req.Header.Set("User-Agent", "build-onion")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		switch {
		case err != nil:
			last = err
		case resp.StatusCode == http.StatusOK:
			return body, nil
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
			return nil, errNotFound
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			last = fmt.Errorf("%s: %s", url, resp.Status)
		default:
			return nil, fmt.Errorf("%s: %s", url, resp.Status)
		}
	}
	return nil, last
}

// fail records a lookup error: not found, or couldn't ask.
func fail(r *Result, err error, what string) {
	if errors.Is(err, errNotFound) {
		r.Outcome, r.Detail = NotFound, what+" not on the public registry"
		return
	}
	r.Outcome, r.Detail = Error, err.Error()
}

// verify checks a bundle for an archive and records who signed it.
func (c *Checker) verify(bundleJSON []byte, subject, file string) (Attestation, error) {
	signer, err := Verify(c.Verifier, bundleJSON, subject)
	return Attestation{Subject: subject, File: file, Signer: signer}, err
}

// Verify checks a bundle: signature, certificate chain and transparency log,
// and that its in-toto subject is the given archive digest. It returns the
// signer from the certificate.
func Verify(v *attest.Verifier, bundleJSON []byte, subject string) (Signer, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return Signer{}, fmt.Errorf("bundle: %w", err)
	}
	res, err := v.Verify(attest.Candidate{Bundle: &b}, subject)
	if err != nil {
		return Signer{}, err
	}
	ext := res.Certificate.Extensions
	if ext.Issuer == "" {
		return Signer{}, errors.New("certificate names no OIDC issuer")
	}
	entries := b.GetVerificationMaterial().GetTlogEntries()
	if len(entries) == 0 {
		return Signer{}, errors.New("bundle has no transparency log entry")
	}
	return Signer{Issuer: ext.Issuer, Repository: ext.SourceRepositoryURI, Commit: ext.SourceRepositoryDigest,
		Workflow: ext.BuildConfigURI, LogIndex: entries[0].GetLogIndex()}, nil
}

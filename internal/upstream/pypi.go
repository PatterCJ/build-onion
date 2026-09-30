package upstream

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/PatterCJ/build-onion/internal/lockfile"
)

// checkPyPI finds each locked archive among the files PyPI publishes for the
// project, then verifies the PEP 740 attestations PyPI serves for them. A
// lock names every wheel and sdist it allows, and the installer picks one,
// so every locked file is checked.
func (c *Checker) checkPyPI(ctx context.Context, p lockfile.Package, r *Result) {
	if len(p.Archives) == 0 {
		r.Outcome, r.Detail = Unhashed, "lockfile has no hashes for it"
		return
	}
	name := lockfile.Normalize("pypi", p.Name)
	body, err := c.get(ctx, c.Registries.PyPI+"/simple/"+name+"/", "application/vnd.pypi.simple.v1+json")
	if err != nil {
		fail(r, err, p.Name)
		return
	}
	var index struct {
		Files []struct {
			Filename   string            `json:"filename"`
			Hashes     map[string]string `json:"hashes"`
			Provenance *string           `json:"provenance"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &index); err != nil {
		r.Outcome, r.Detail = Error, fmt.Sprintf("index response: %v", err)
		return
	}
	type file struct{ name, provenance string }
	bySHA := map[string]file{}
	for _, f := range index.Files {
		if h := strings.ToLower(f.Hashes["sha256"]); h != "" {
			ff := file{name: f.Filename}
			if f.Provenance != nil {
				ff.provenance = *f.Provenance
			}
			bySHA["sha256:"+h] = ff
		}
	}
	hasVersion := false
	for _, f := range index.Files {
		if pypiVersion(pypiFileVersion(f.Filename)) == pypiVersion(p.Version) {
			hasVersion = true
		}
	}
	attested := 0
	for _, locked := range p.Archives {
		if !strings.HasPrefix(locked, "sha256:") {
			r.Outcome, r.Detail = Error, fmt.Sprintf("PyPI publishes sha256 digests only; can't compare %s", short(locked))
			return
		}
		f, ok := bySHA[locked]
		if !ok && !hasVersion {
			r.Outcome, r.Detail = NotFound, fmt.Sprintf("%s %s not on the public registry", name, p.Version)
			return
		}
		if !ok {
			r.Outcome, r.Detail = Mismatch, fmt.Sprintf("lockfile pins %s, which PyPI doesn't publish for %s", short(locked), name)
			return
		}
		if v := pypiFileVersion(f.name); v != "" && pypiVersion(v) != pypiVersion(p.Version) {
			r.Outcome, r.Detail = Mismatch, fmt.Sprintf("lockfile pins %s as %s, but PyPI publishes it as %s", short(locked), p.Version, f.name)
			return
		}
		if f.provenance == "" {
			continue
		}
		atts, err := c.pypiAttestations(ctx, f.provenance, locked, f.name)
		if err != nil {
			r.Outcome, r.Detail = Invalid, fmt.Sprintf("%s: %v", f.name, err)
			var fe fetchError
			if errors.As(err, &fe) {
				r.Outcome = Error
			}
			return
		}
		r.Attestations = append(r.Attestations, atts...)
		attested++
	}
	switch {
	case attested == len(p.Archives):
		r.Outcome = Attested
	case attested == 0:
		r.Outcome, r.Detail = Published, "no provenance published"
	default:
		r.Outcome, r.Detail = Published, fmt.Sprintf("%d of %d locked files have provenance", attested, len(p.Archives))
	}
}

// pypiAttestations fetches and verifies a file's PEP 740 provenance. Every
// attestation it carries must verify and be about this file.
func (c *Checker) pypiAttestations(ctx context.Context, url, subject, filename string) ([]Attestation, error) {
	body, err := c.get(ctx, url, "application/json")
	if err != nil {
		return nil, fetchError{fmt.Errorf("provenance advertised but not served: %w", err)}
	}
	var prov struct {
		Bundles []struct {
			Attestations []pep740Attestation `json:"attestations"`
		} `json:"attestation_bundles"`
	}
	if err := json.Unmarshal(body, &prov); err != nil {
		return nil, fmt.Errorf("provenance: %w", err)
	}
	var out []Attestation
	for _, b := range prov.Bundles {
		for _, a := range b.Attestations {
			sb, err := a.sigstoreBundle()
			if err != nil {
				return nil, err
			}
			att, err := c.verify(sb, subject, filename)
			if err != nil {
				return nil, err
			}
			out = append(out, att)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("provenance has no attestations")
	}
	return out, nil
}

// fetchError is a failure to get provenance, as opposed to provenance that
// fails verification.
type fetchError struct{ error }

func (e fetchError) Unwrap() error { return e.error }

// pep740Attestation is PyPI's attestation form: a DSSE envelope and its
// verification material, which map one to one onto a Sigstore bundle.
type pep740Attestation struct {
	Version  int `json:"version"`
	Material struct {
		Certificate string            `json:"certificate"` // base64 DER
		Entries     []json.RawMessage `json:"transparency_entries"`
	} `json:"verification_material"`
	Envelope struct {
		Statement string `json:"statement"` // base64
		Signature string `json:"signature"` // base64
	} `json:"envelope"`
}

func (a pep740Attestation) sigstoreBundle() ([]byte, error) {
	if a.Version != 1 {
		return nil, fmt.Errorf("unsupported attestation version %d", a.Version)
	}
	for _, s := range []string{a.Material.Certificate, a.Envelope.Statement, a.Envelope.Signature} {
		if _, err := base64.StdEncoding.DecodeString(s); err != nil {
			return nil, fmt.Errorf("attestation: %w", err)
		}
	}
	type sig struct {
		Sig string `json:"sig"`
	}
	return json.Marshal(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]string{"rawBytes": a.Material.Certificate},
			"tlogEntries": a.Material.Entries,
		},
		"dsseEnvelope": map[string]any{
			"payload":     a.Envelope.Statement,
			"payloadType": "application/vnd.in-toto+json",
			"signatures":  []sig{{a.Envelope.Signature}},
		},
	})
}

// pypiFileVersion reads the version from a wheel or sdist filename, or ""
// for other kinds of file.
func pypiFileVersion(filename string) string {
	switch {
	case strings.HasSuffix(filename, ".whl"):
		if parts := strings.Split(filename, "-"); len(parts) >= 5 {
			return parts[1]
		}
	case strings.HasSuffix(filename, ".tar.gz"), strings.HasSuffix(filename, ".zip"):
		base := strings.TrimSuffix(strings.TrimSuffix(filename, ".tar.gz"), ".zip")
		if i := strings.LastIndex(base, "-"); i >= 0 {
			return base[i+1:]
		}
	}
	return ""
}

// pypiVersion is a light normalization: case, a leading v, and the
// separators wheel filenames rewrite.
func pypiVersion(v string) string {
	v = strings.TrimPrefix(strings.ToLower(v), "v")
	return strings.ReplaceAll(v, "_", "-")
}

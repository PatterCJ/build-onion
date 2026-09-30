// Package inventory produces the bottom-up record of everything that went into
// a build: the source tree, the manifest, the builder, every locked dependency,
// and every output. It is signed as an in-toto predicate next to the SLSA
// provenance, and `onion peel` checks each layer of it in reverse.
package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/egress"
	"github.com/PatterCJ/build-onion/internal/gate"
	"github.com/PatterCJ/build-onion/internal/lint"
	"github.com/PatterCJ/build-onion/internal/lockfile"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/source"
	"github.com/PatterCJ/build-onion/internal/verify"
)

const PredicateType = "https://github.com/PatterCJ/build-onion/inventory/v1"

type Inventory struct {
	Manifest     FileRef            `json:"manifest"`
	Source       Source             `json:"source"`
	Builder      Builder            `json:"builder"`
	Lockfiles    []FileRef          `json:"lockfiles"`
	Dependencies []lockfile.Package `json:"dependencies"`
	// Local are packages built from this source rather than fetched.
	Local []lockfile.Local `json:"local,omitempty"`
	// MainModules is the pre-Local form, read from older inventories only.
	MainModules []string `json:"mainModules,omitempty"`
	Build       Build    `json:"build"`
	Outputs     []Output `json:"outputs"`
	Run         Run      `json:"run"`
	Pipeline    Pipeline `json:"pipeline"`
	// Gate is the pre-build verdict: release policy and sensitive changes.
	Gate *gate.Verdict `json:"gate,omitempty"`
	// Verification is the security line's result: the independent rebuild.
	// Present on everything the security line seals.
	Verification *Verification `json:"verification,omitempty"`
	// Egress is the network the fetch step had, and every connection it made
	// when it ran behind the egress proxy.
	Egress *egress.Record `json:"egress,omitempty"`
}

type Verification struct {
	Rebuild *verify.Rebuild `json:"rebuild"`
}

type FileRef struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	// Ecosystem is set on lockfiles build-onion can read; empty means the
	// lockfile is hashed but its packages can't be cross-checked.
	Ecosystem string `json:"ecosystem,omitempty"`
}

type Source struct {
	Repository string `json:"repository"` // https://github.com/owner/repo
	Commit     string `json:"commit"`
	Tree       string `json:"tree"`
	// Snapshot is the digest of the sha256-per-file source snapshot, taken
	// before the build and re-verified in every job.
	Snapshot string `json:"snapshot"`
	Files    int    `json:"files"`
}

type Builder struct {
	Image string `json:"image"`
}

type Build struct {
	Fetch   string            `json:"fetch,omitempty"`
	Run     string            `json:"run"`
	Env     map[string]string `json:"env,omitempty"`
	Network string            `json:"network"`
	Image   *ImageBuild       `json:"image,omitempty"`
	// Inputs is the part of the source the build could read.
	Inputs *Inputs `json:"inputs,omitempty"`
}

// Inputs records the staged subset of the snapshot that fetch and build saw.
type Inputs struct {
	Patterns []string `json:"patterns,omitempty"` // empty: every tracked file
	Files    int      `json:"files"`
	Of       int      `json:"of"`     // tracked files in the snapshot
	Digest   string   `json:"digest"` // canonical digest of the staged subset
}

// ImageBuild records how the image output was assembled. With every base
// pinned and no network in RUN steps, every file in the image comes from a
// pinned base image or from the snapshotted source and build outputs.
type ImageBuild struct {
	Dockerfile FileRef  `json:"dockerfile"`
	BaseImages []string `json:"baseImages"`
	RunNetwork string   `json:"runNetwork"`
	// FinalBase is the pinned image the final stage builds on ("" for scratch).
	FinalBase string `json:"finalBase"`
	// BaseLayers are FinalBase's layer diffIDs, and Layers the built image's.
	// The image must start with its base's layers; a package in one of those
	// layers came from the pinned base.
	BaseLayers []string `json:"baseLayers"`
	Layers     []string `json:"layers"`
}

type Output struct {
	Kind   string `json:"kind"` // file | oci-image
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type Run struct {
	InvocationURL string `json:"invocationUrl,omitempty"`
}

// Params are the facts the seal job knows from outside the source tree.
type Params struct {
	SourceDir     string // checkout of the commit being built
	ManifestPath  string // relative to SourceDir
	Repository    string
	Commit        string
	Tree          string
	FilesDir      string // directory holding the declared output files by basename
	ImageArchive  string // OCI layout tarball, when the manifest declares an image
	InvocationURL string
	// Snapshot is the source snapshot taken before the build. Generate
	// re-verifies SourceDir against it.
	Snapshot     *source.Snapshot
	Pipeline     Pipeline
	Gate         *gate.Verdict
	Verification *Verification
	// Egress is the fetch network record from the fetch whose cache produced
	// these outputs. Required when the manifest declares an allow-list.
	Egress *egress.Record
	// ResolveBase returns a pinned image's layer diffIDs (linux/amd64).
	ResolveBase func(ref string) ([]string, error)
}

// Generate builds the inventory. It hashes everything itself; it never trusts
// digests reported by the build job.
func Generate(p Params) (*Inventory, *manifest.Manifest, error) {
	m, raw, err := manifest.Load(filepath.Join(p.SourceDir, p.ManifestPath))
	if err != nil {
		return nil, nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	if err := checkSnapshot(p); err != nil {
		return nil, nil, err
	}
	egressRec := p.Egress
	if egressRec == nil {
		switch {
		case m.Dependencies.Fetch == "":
			egressRec = &egress.Record{Mode: egress.ModeNone}
		case len(m.Dependencies.Egress) == 0:
			egressRec = &egress.Record{Mode: egress.ModeUnrestricted}
		default:
			return nil, nil, errors.New("the manifest declares an egress allow-list, but no egress record was given; the fetch network can't be vouched for")
		}
	}
	if err := egressRec.Check(m); err != nil {
		return nil, nil, fmt.Errorf("egress: %w", err)
	}
	if v := p.Verification; v != nil {
		if v.Rebuild == nil || !v.Rebuild.Matched {
			return nil, nil, errors.New("independent rebuild did not match the build line; refusing to inventory for sealing")
		}
	}
	inv := &Inventory{
		Manifest: FileRef{Path: p.ManifestPath, Digest: manifest.Digest(raw)},
		Source: Source{Repository: p.Repository, Commit: p.Commit, Tree: p.Tree,
			Snapshot: p.Snapshot.Digest, Files: len(p.Snapshot.Files)},
		Pipeline:     p.Pipeline,
		Gate:         p.Gate,
		Verification: p.Verification,
		Egress:       egressRec,
		Builder:      Builder{Image: m.Builder.Image},
		Build: Build{
			Fetch:   m.Dependencies.Fetch,
			Run:     m.Build.Run,
			Env:     m.Build.Env,
			Network: "none",
		},
		Run: Run{InvocationURL: p.InvocationURL},
	}
	for _, l := range m.Dependencies.Lockfiles {
		d, err := digest.File(filepath.Join(p.SourceDir, l))
		if err != nil {
			return nil, nil, fmt.Errorf("lockfile: %w", err)
		}
		ref := FileRef{Path: l, Digest: d}
		full := filepath.Join(p.SourceDir, l)
		data, err := os.ReadFile(full)
		if err != nil {
			return nil, nil, err
		}
		sibling := func(name string) ([]byte, error) { return os.ReadFile(filepath.Join(filepath.Dir(full), name)) }
		res, ok, err := lockfile.Parse(l, data, sibling)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			ref.Ecosystem = lockfile.Ecosystem(l)
			inv.Dependencies = append(inv.Dependencies, res.Packages...)
			inv.Local = append(inv.Local, res.Local...)
		}
		inv.Lockfiles = append(inv.Lockfiles, ref)
	}
	for _, f := range m.Outputs.Files {
		name := filepath.Base(f)
		d, err := digest.File(filepath.Join(p.FilesDir, name))
		if err != nil {
			return nil, nil, fmt.Errorf("output %s: %w", f, err)
		}
		inv.Outputs = append(inv.Outputs, Output{Kind: "file", Name: name, Digest: d})
	}
	if img := m.Outputs.Image; img != nil {
		dfPath := filepath.Join(p.SourceDir, img.Dockerfile)
		bases, err := lint.BaseImages(dfPath)
		if err != nil {
			return nil, nil, err
		}
		dfDigest, err := digest.File(dfPath)
		if err != nil {
			return nil, nil, err
		}
		final, err := lint.FinalBase(dfPath)
		if err != nil {
			return nil, nil, err
		}
		if p.ImageArchive == "" {
			return nil, nil, errors.New("manifest declares an image but no image archive was given")
		}
		d, err := digest.OCIArchive(p.ImageArchive)
		if err != nil {
			return nil, nil, err
		}
		layers, err := digest.OCILayers(p.ImageArchive)
		if err != nil {
			return nil, nil, err
		}
		var baseLayers []string
		if final != "" {
			if p.ResolveBase == nil {
				return nil, nil, errors.New("image builds on a base image, but no way to resolve its layers was given")
			}
			if baseLayers, err = p.ResolveBase(final); err != nil {
				return nil, nil, fmt.Errorf("resolve base %s: %w", final, err)
			}
		}
		// The image must be its base's layers plus its own, in that order:
		// proof it was built FROM the pinned base and nothing else.
		if len(layers) < len(baseLayers) || !equalStrings(layers[:len(baseLayers)], baseLayers) {
			return nil, nil, fmt.Errorf("image does not start with the layers of its declared base %s", final)
		}
		inv.Build.Image = &ImageBuild{
			Dockerfile: FileRef{Path: img.Dockerfile, Digest: dfDigest},
			BaseImages: bases,
			RunNetwork: "none",
			FinalBase:  final,
			BaseLayers: baseLayers,
			Layers:     layers,
		}
		inv.Outputs = append(inv.Outputs, Output{Kind: "oci-image", Name: img.Name, Digest: d})
	}
	inputs, err := p.Snapshot.Subset(m.Build.Inputs, m.AlwaysInputs(p.ManifestPath))
	if err != nil {
		return nil, nil, err
	}
	inv.Build.Inputs = &Inputs{Patterns: m.Build.Inputs, Files: len(inputs), Of: len(p.Snapshot.Files), Digest: source.SubsetDigest(inputs)}
	if err := checkScans(inv); err != nil {
		return nil, nil, err
	}
	return inv, m, nil
}

// checkScans requires every recorded scan to be about this build's bytes:
// the source snapshot or one of the outputs. A report from another build or
// an older commit can't be recorded against this one.
func checkScans(inv *Inventory) error {
	var errs []error
	for _, s := range inv.Pipeline.Scans {
		switch s.Subject.Kind {
		case "source":
			if s.Subject.Digest != inv.Source.Snapshot {
				errs = append(errs, fmt.Errorf("scan %s examined source %s, but this build's snapshot is %s", s.Name, s.Subject.Digest, inv.Source.Snapshot))
			}
		case "artifact":
			if _, ok := inv.Subject(s.Subject.Digest); !ok {
				errs = append(errs, fmt.Errorf("scan %s examined artifact %s, which this build did not produce", s.Name, s.Subject.Digest))
			}
		}
	}
	return errors.Join(errs...)
}

// checkSnapshot requires the pre-build snapshot to describe this commit and
// the checkout being inventoried to still match it byte for byte.
func checkSnapshot(p Params) error {
	s := p.Snapshot
	if s == nil {
		return errors.New("a source snapshot is required")
	}
	if err := s.Check(); err != nil {
		return err
	}
	if s.Commit != p.Commit || s.Tree != p.Tree {
		return fmt.Errorf("snapshot is of %s (tree %s), building %s (tree %s)", s.Commit, s.Tree, p.Commit, p.Tree)
	}
	d, err := source.Verify(p.SourceDir, s, nil)
	if err != nil {
		return err
	}
	if !d.Empty() {
		return d
	}
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Subject returns the output with the given digest, if the inventory has one.
func (inv *Inventory) Subject(d string) (Output, bool) {
	for _, o := range inv.Outputs {
		if o.Digest == d {
			return o, true
		}
	}
	return Output{}, false
}

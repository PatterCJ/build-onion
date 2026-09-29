// Package verify is the security line's core check: an independent rebuild
// must reproduce, byte for byte, what the build line staged. Nothing is
// sealed unless it does.
//
// The rebuild matters because hashing the source before and after a build
// cannot see a file that was swapped only while the compiler read it. A second
// build from the same hashed inputs, on separate runners, produces different
// bytes if the first build environment injected anything.
package verify

import (
	"fmt"
	"path/filepath"

	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/manifest"
)

// ImageArchive is the file name the pipeline gives a built OCI image.
const ImageArchive = "image.tar"

// Rebuild records the comparison between the build line and the security
// line's independent rebuild.
type Rebuild struct {
	Runner  string  `json:"runner"`
	Matched bool    `json:"matched"`
	Outputs []Match `json:"outputs"`
}

type Match struct {
	Kind    string `json:"kind"` // file | oci-image
	Name    string `json:"name"`
	Staged  string `json:"staged"`  // digest the build line produced
	Rebuilt string `json:"rebuilt"` // digest the security line produced
	Match   bool   `json:"match"`
}

// Output is one declared output as found on disk.
type Output struct {
	Kind   string `json:"kind"` // file | oci-image
	Name   string `json:"name"` // file basename, or image repository
	Path   string `json:"path"` // relative to the outputs directory
	Digest string `json:"digest"`
}

// Outputs lists the manifest's outputs as found in an outputs directory laid
// out by the pipeline: files/<basename> and image.tar.
func Outputs(m *manifest.Manifest, dir string) ([]Output, error) {
	var out []Output
	for _, f := range m.Outputs.Files {
		rel := filepath.Join("files", filepath.Base(f))
		d, err := digest.File(filepath.Join(dir, rel))
		if err != nil {
			return nil, fmt.Errorf("output %s: %w", f, err)
		}
		out = append(out, Output{Kind: "file", Name: filepath.Base(f), Path: filepath.ToSlash(rel), Digest: d})
	}
	if img := m.Outputs.Image; img != nil {
		d, err := digest.OCIArchive(filepath.Join(dir, ImageArchive))
		if err != nil {
			return nil, err
		}
		out = append(out, Output{Kind: "oci-image", Name: img.Name, Path: ImageArchive, Digest: d})
	}
	return out, nil
}

// Compare checks every declared output in stagedDir against rebuiltDir.
func Compare(m *manifest.Manifest, stagedDir, rebuiltDir, runner string) (*Rebuild, error) {
	staged, err := Outputs(m, stagedDir)
	if err != nil {
		return nil, fmt.Errorf("build line outputs: %w", err)
	}
	rebuilt, err := Outputs(m, rebuiltDir)
	if err != nil {
		return nil, fmt.Errorf("rebuilt outputs: %w", err)
	}
	r := &Rebuild{Runner: runner, Matched: true}
	for i := range staged {
		mt := Match{Kind: staged[i].Kind, Name: staged[i].Name, Staged: staged[i].Digest, Rebuilt: rebuilt[i].Digest}
		mt.Match = mt.Staged == mt.Rebuilt
		r.Matched = r.Matched && mt.Match
		r.Outputs = append(r.Outputs, mt)
	}
	return r, nil
}

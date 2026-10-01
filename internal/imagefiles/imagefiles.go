// Package imagefiles lists every file in a container image's final
// filesystem and the layer it came from: the image's own pinned base, or a
// layer the build added. It is a fact for cross-referencing (SBOM package
// locations, source files, declared outputs); it grades nothing.
package imagefiles

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// Listing is an image's final filesystem.
type Listing struct {
	Image  string  `json:"image"` // manifest digest
	Layers []Layer `json:"layers"`
	Files  []File  `json:"files"`
}

type Layer struct {
	Index  int    `json:"index"`
	DiffID string `json:"diffID"`
	// Base: one of the leading layers that are the declared base image's.
	Base bool `json:"base"`
}

// File is one path in the final filesystem.
type File struct {
	Path   string `json:"path"`
	Type   string `json:"type"` // file, dir, symlink, hardlink, other
	Mode   string `json:"mode"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"` // regular files
	Link   string `json:"link,omitempty"`   // symlink and hardlink targets
	Layer  int    `json:"layer"`            // index of the layer that last wrote it
	Base   bool   `json:"base"`             // that layer is a base layer
}

const (
	whiteoutPrefix = ".wh."
	opaqueMarker   = ".wh..wh..opq"
	maxEntries     = 1 << 20
)

// List walks img's layers in order, applying whiteouts, and returns the
// final filesystem. baseDiffIDs, if given, are the declared base image's
// layers; the image must start with them, and they are marked as base.
func List(img v1.Image, baseDiffIDs []string) (*Listing, error) {
	d, err := img.Digest()
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	out := &Listing{Image: d.String()}
	for i, l := range layers {
		id, err := l.DiffID()
		if err != nil {
			return nil, err
		}
		out.Layers = append(out.Layers, Layer{Index: i, DiffID: id.String()})
	}
	if len(baseDiffIDs) > len(out.Layers) {
		return nil, fmt.Errorf("the image has %d layers, fewer than its base's %d", len(out.Layers), len(baseDiffIDs))
	}
	for i, id := range baseDiffIDs {
		if out.Layers[i].DiffID != id {
			return nil, fmt.Errorf("layer %d is %s, not the base's %s: the image doesn't start with its base", i, out.Layers[i].DiffID, id)
		}
		out.Layers[i].Base = true
	}

	fs := map[string]File{}
	for i, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
		err = applyLayer(fs, rc, i, out.Layers[i].Base)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
	}
	for _, f := range fs {
		out.Files = append(out.Files, f)
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })
	return out, nil
}

// applyLayer reads one layer: its whiteouts remove what lower layers wrote,
// then its own entries are added. A layer's own entries are never hidden by
// its own whiteouts.
func applyLayer(fs map[string]File, r io.Reader, index int, base bool) error {
	tr := tar.NewReader(r)
	var added []File
	var whiteouts, opaque []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		p, err := clean(h.Name)
		if err != nil {
			return err
		}
		if p == "" {
			continue // the root itself
		}
		dir, name := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		switch {
		case name == opaqueMarker:
			opaque = append(opaque, dir)
			continue
		case strings.HasPrefix(name, whiteoutPrefix):
			whiteouts = append(whiteouts, path.Join(dir, strings.TrimPrefix(name, whiteoutPrefix)))
			continue
		}
		f := File{Path: p, Mode: fmt.Sprintf("%04o", h.Mode&0o7777), Layer: index, Base: base}
		switch h.Typeflag {
		case tar.TypeReg:
			f.Type, f.Size = "file", h.Size
			sum := sha256.New()
			if _, err := io.Copy(sum, tr); err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			f.SHA256 = "sha256:" + hex.EncodeToString(sum.Sum(nil))
		case tar.TypeDir:
			f.Type = "dir"
		case tar.TypeSymlink:
			f.Type, f.Link = "symlink", h.Linkname
		case tar.TypeLink:
			f.Type = "hardlink"
			if f.Link, err = clean(h.Linkname); err != nil {
				return err
			}
		default:
			f.Type = "other"
		}
		added = append(added, f)
	}
	for _, d := range opaque {
		for p := range fs {
			if d == "" || strings.HasPrefix(p, d+"/") {
				delete(fs, p)
			}
		}
	}
	for _, w := range whiteouts {
		for p := range fs {
			if p == w || strings.HasPrefix(p, w+"/") {
				delete(fs, p)
			}
		}
	}
	for _, f := range added {
		// A hardlink takes its target's content as it is now.
		if f.Type == "hardlink" {
			if t, ok := fs[f.Link]; ok && t.Type == "file" {
				f.Size, f.SHA256 = t.Size, t.SHA256
			}
		}
		fs[f.Path] = f
	}
	if len(fs) > maxEntries {
		return fmt.Errorf("more than %d paths", maxEntries)
	}
	return nil
}

// clean normalizes a tar entry name to a path relative to the image root.
// Cleaning it as an absolute path keeps ".." from climbing above the root,
// as container runtimes do when they unpack it.
func clean(name string) (string, error) {
	return strings.TrimPrefix(path.Clean("/"+name), "/"), nil
}

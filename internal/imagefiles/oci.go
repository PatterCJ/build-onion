package imagefiles

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
)

var blobRe = regexp.MustCompile(`^blobs/sha256/[0-9a-f]{64}$`)

// FromOCIArchive opens the single image in an OCI image-layout tarball (as
// the build writes image.tar). Only index.json, oci-layout and sha256 blobs
// are unpacked, under a temporary directory that cleanup removes; layers are
// checked against their digests as they are read.
func FromOCIArchive(p string) (img v1.Image, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "onion-oci-")
	if err != nil {
		return nil, nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	defer func() {
		if err != nil {
			cleanup()
		}
	}()
	f, err := os.Open(p)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		name := strings.TrimPrefix(h.Name, "./")
		if h.Typeflag != tar.TypeReg || (name != "index.json" && name != "oci-layout" && !blobRe.MatchString(name)) {
			continue
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, nil, err
		}
		out, err := os.Create(dst)
		if err != nil {
			return nil, nil, err
		}
		_, err = io.Copy(out, tr)
		out.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	idx, err := layout.ImageIndexFromPath(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", p, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, nil, err
	}
	if len(im.Manifests) != 1 {
		return nil, nil, fmt.Errorf("%s: expected one image, found %d", p, len(im.Manifests))
	}
	img, err = idx.Image(im.Manifests[0].Digest)
	if err != nil {
		return nil, nil, err
	}
	return img, cleanup, nil
}

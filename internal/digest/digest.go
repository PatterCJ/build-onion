// Package digest computes the content addresses build-onion signs and checks.
package digest

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

var sha256Re = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Valid reports whether d is a well-formed "sha256:<hex>" digest.
func Valid(d string) bool { return sha256Re.MatchString(d) }

// Hex strips the algorithm prefix.
func Hex(d string) string { return strings.TrimPrefix(d, "sha256:") }

func Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// OCIArchive returns the image manifest digest recorded in an OCI image-layout
// tarball (as written by `docker buildx build --output type=oci`). This is the
// digest the image has once pushed with its manifest bytes preserved.
func OCIArchive(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("%s: no index.json; not an OCI image layout", p)
		} else if err != nil {
			return "", err
		}
		if strings.TrimPrefix(h.Name, "./") != "index.json" {
			continue
		}
		var idx struct {
			Manifests []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
			} `json:"manifests"`
		}
		if err := json.NewDecoder(tr).Decode(&idx); err != nil {
			return "", fmt.Errorf("%s: index.json: %w", p, err)
		}
		if len(idx.Manifests) != 1 {
			return "", fmt.Errorf("%s: index.json has %d manifests; build single-platform with --provenance=false --sbom=false", p, len(idx.Manifests))
		}
		if d := idx.Manifests[0].Digest; Valid(d) {
			return d, nil
		}
		return "", fmt.Errorf("%s: invalid manifest digest", p)
	}
}

// OCILayers returns the diffIDs (uncompressed layer digests, bottom first)
// from the image config inside an OCI layout tarball with a single manifest.
func OCILayers(p string) ([]string, error) {
	manifestDigest, err := OCIArchive(p)
	if err != nil {
		return nil, err
	}
	blob := func(d string) ([]byte, error) {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		want := "blobs/sha256/" + Hex(d)
		tr := tar.NewReader(f)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("%s: blob %s not in archive", p, d)
			} else if err != nil {
				return nil, err
			}
			if strings.TrimPrefix(h.Name, "./") == want {
				if h.Size > 4<<20 {
					return nil, fmt.Errorf("%s: blob %s too large for a manifest or config", p, d)
				}
				b, err := io.ReadAll(tr)
				if err != nil {
					return nil, err
				}
				if Bytes(b) != d {
					return nil, fmt.Errorf("%s: blob %s does not match its digest", p, d)
				}
				return b, nil
			}
		}
	}
	mb, err := blob(manifestDigest)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(mb, &manifest); err != nil || !Valid(manifest.Config.Digest) {
		return nil, fmt.Errorf("%s: image manifest has no valid config digest", p)
	}
	cb, err := blob(manifest.Config.Digest)
	if err != nil {
		return nil, err
	}
	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if err := json.Unmarshal(cb, &config); err != nil {
		return nil, fmt.Errorf("%s: image config: %w", p, err)
	}
	return config.RootFS.DiffIDs, nil
}

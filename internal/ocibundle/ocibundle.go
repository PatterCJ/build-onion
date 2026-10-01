// Package ocibundle stores Sigstore bundles in an OCI registry next to the
// image they are about, and reads them back, in the layout Sigstore defines
// for bundles in OCI: one manifest per bundle, with the image as its
// subject, found through the registry's referrers API (or, where a registry
// lacks it, the sha256-<digest> fallback tag).
package ocibundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	// BundleMediaType is the artifact type and layer media type of a bundle.
	BundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	emptyMediaType  = "application/vnd.oci.empty.v1+json"
	// maxBundle bounds what is read from a registry for one bundle, and
	// maxReferrers how many referrers of one image are examined.
	maxBundle    = 16 << 20
	maxTotal     = 64 << 20
	maxReferrers = 200
)

var emptyConfig = []byte("{}")

type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     types.MediaType   `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        v1.Descriptor     `json:"config"`
	Layers        []v1.Descriptor   `json:"layers"`
	Subject       *v1.Descriptor    `json:"subject,omitempty"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type rawManifest []byte

func (r rawManifest) RawManifest() ([]byte, error)        { return r, nil }
func (r rawManifest) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }

// Push stores a bundle as a referrer of the image at subject, and returns the
// bundle manifest's digest. predicateType is recorded as an annotation so
// clients can pick bundles without downloading them.
func Push(subject name.Digest, bundleJSON []byte, predicateType string, opts ...remote.Option) (name.Digest, error) {
	desc, err := remote.Head(subject, opts...)
	if err != nil {
		return name.Digest{}, fmt.Errorf("subject %s: %w", subject, err)
	}
	repo := subject.Context()
	config := static.NewLayer(emptyConfig, emptyMediaType)
	layer := static.NewLayer(bundleJSON, BundleMediaType)
	for _, l := range []v1.Layer{config, layer} {
		if err := remote.WriteLayer(repo, l, opts...); err != nil {
			return name.Digest{}, fmt.Errorf("upload: %w", err)
		}
	}
	m := manifest{
		SchemaVersion: 2,
		MediaType:     types.OCIManifestSchema1,
		ArtifactType:  BundleMediaType,
		Config:        descriptorOf(emptyConfig, emptyMediaType),
		Layers:        []v1.Descriptor{descriptorOf(bundleJSON, BundleMediaType)},
		Subject:       &v1.Descriptor{MediaType: desc.MediaType, Digest: desc.Digest, Size: desc.Size},
		Annotations: map[string]string{
			"dev.sigstore.bundle.content":       "dsse-envelope",
			"dev.sigstore.bundle.predicateType": predicateType,
		},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return name.Digest{}, err
	}
	sum := sha256.Sum256(raw)
	ref := repo.Digest("sha256:" + hex.EncodeToString(sum[:]))
	if err := remote.Put(ref, rawManifest(raw), opts...); err != nil {
		return name.Digest{}, fmt.Errorf("push bundle manifest: %w", err)
	}
	return ref, nil
}

// Fetch returns every bundle stored as a referrer of the image at subject.
// Each referrer's own manifest decides whether it is a bundle: registries
// differ in how they report a referrer's type, so neither the referrers
// list nor server-side filtering is relied on. Blobs are checked against
// their digests as they are read.
//
// A referrer that can't be read is skipped and described in skipped, so one
// broken or hostile entry doesn't hide the others; err is for failures that
// leave nothing to read.
func Fetch(subject name.Digest, opts ...remote.Option) (bundles [][]byte, skipped []string, err error) {
	idx, err := remote.Referrers(subject, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("referrers of %s: %w", subject, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return nil, nil, err
	}
	if len(im.Manifests) > maxReferrers {
		return nil, nil, fmt.Errorf("%s has %d referrers; refusing to examine more than %d", subject, len(im.Manifests), maxReferrers)
	}
	repo := subject.Context()
	var total int64
	skip := func(f string, a ...any) { skipped = append(skipped, fmt.Sprintf(f, a...)) }
	for _, d := range im.Manifests {
		if d.MediaType != types.OCIManifestSchema1 {
			continue
		}
		desc, err := remote.Get(repo.Digest(d.Digest.String()), opts...)
		if err != nil {
			skip("referrer %s: %v", d.Digest, err)
			continue
		}
		var m manifest
		if err := json.Unmarshal(desc.Manifest, &m); err != nil {
			skip("referrer %s: %v", d.Digest, err)
			continue
		}
		if m.ArtifactType != BundleMediaType || m.Subject == nil || m.Subject.Digest.String() != subject.DigestStr() {
			continue
		}
		for _, l := range m.Layers {
			if string(l.MediaType) != BundleMediaType {
				continue
			}
			if l.Size > maxBundle || total+l.Size > maxTotal {
				skip("bundle %s: %d bytes is over the size limit", l.Digest, l.Size)
				continue
			}
			blob, err := readBlob(repo, l, opts)
			if err != nil {
				skip("bundle %s: %v", l.Digest, err)
				continue
			}
			total += int64(len(blob))
			bundles = append(bundles, blob)
		}
	}
	return bundles, skipped, nil
}

func readBlob(repo name.Repository, l v1.Descriptor, opts []remote.Option) ([]byte, error) {
	layer, err := remote.Layer(repo.Digest(l.Digest.String()), opts...)
	if err != nil {
		return nil, err
	}
	rc, err := layer.Compressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxBundle+1))
	if err != nil {
		return nil, fmt.Errorf("bundle %s: %w", l.Digest, err)
	}
	sum := sha256.Sum256(b)
	if l.Digest.Algorithm != "sha256" || hex.EncodeToString(sum[:]) != l.Digest.Hex || int64(len(b)) != l.Size {
		return nil, fmt.Errorf("bundle %s: content doesn't match its digest", l.Digest)
	}
	return b, nil
}

func descriptorOf(b []byte, mt types.MediaType) v1.Descriptor {
	sum := sha256.Sum256(b)
	return v1.Descriptor{MediaType: mt, Size: int64(len(b)), Digest: v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(sum[:])}}
}

package ocibundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// pushImage puts a random image in a test registry and returns its digest
// reference.
func pushImage(t *testing.T, referrers bool) name.Digest {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(referrers)))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	tag, _ := name.NewTag(u.Host + "/acme/widget:v1")
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	d, _ := img.Digest()
	return tag.Context().Digest(d.String())
}

func TestPushAndFetch(t *testing.T) {
	for _, referrers := range []bool{true, false} {
		subject := pushImage(t, referrers)
		bundles := [][]byte{[]byte(`{"bundle":"provenance"}`), []byte(`{"bundle":"sbom"}`)}
		for i, b := range bundles {
			if _, err := Push(subject, b, []string{"https://slsa.dev/provenance/v1", "https://cyclonedx.org/bom"}[i]); err != nil {
				t.Fatalf("referrers=%v: push: %v", referrers, err)
			}
		}
		// An unrelated referrer (not a Sigstore bundle) is ignored.
		if err := pushOtherReferrer(subject); err != nil {
			t.Fatal(err)
		}

		got, err := Fetch(subject)
		if err != nil {
			t.Fatalf("referrers=%v: fetch: %v", referrers, err)
		}
		var gs []string
		for _, g := range got {
			gs = append(gs, string(g))
		}
		sort.Strings(gs)
		if len(gs) != 2 || gs[0] != `{"bundle":"provenance"}` || gs[1] != `{"bundle":"sbom"}` {
			t.Errorf("referrers=%v: fetched %v", referrers, gs)
		}
	}
}

// Bundles are attached to one image; another image in the same repository
// sees none of them.
func TestFetchIsPerSubject(t *testing.T) {
	subject := pushImage(t, true)
	if _, err := Push(subject, []byte(`{"bundle":1}`), "t"); err != nil {
		t.Fatal(err)
	}
	img, _ := random.Image(64, 1)
	d, _ := img.Digest()
	otherRef := subject.Context().Digest(d.String())
	if err := remote.Write(otherRef, img); err != nil {
		t.Fatal(err)
	}
	got, err := Fetch(otherRef)
	if err != nil || len(got) != 0 {
		t.Errorf("other image got %d bundle(s), err %v", len(got), err)
	}
	if _, err := Push(subject.Context().Digest("sha256:"+"0000000000000000000000000000000000000000000000000000000000000000"), []byte(`{}`), "t"); err == nil {
		t.Error("pushed a bundle for an image the registry doesn't have")
	}
}

// pushOtherReferrer attaches a non-bundle artifact to the image.
func pushOtherReferrer(subject name.Digest) error {
	desc, err := remote.Head(subject)
	if err != nil {
		return err
	}
	blob := []byte("not a bundle")
	l := static.NewLayer(blob, "application/vnd.example.signature")
	if err := remote.WriteLayer(subject.Context(), l); err != nil {
		return err
	}
	if err := remote.WriteLayer(subject.Context(), static.NewLayer(emptyConfig, emptyMediaType)); err != nil {
		return err
	}
	raw, _ := json.Marshal(manifest{
		SchemaVersion: 2, MediaType: types.OCIManifestSchema1, ArtifactType: "application/vnd.example.signature",
		Config:  descriptorOf(emptyConfig, emptyMediaType),
		Layers:  []v1.Descriptor{descriptorOf(blob, "application/vnd.example.signature")},
		Subject: &v1.Descriptor{MediaType: desc.MediaType, Digest: desc.Digest, Size: desc.Size},
	})
	sum := sha256.Sum256(raw)
	return remote.Put(subject.Context().Digest("sha256:"+hex.EncodeToString(sum[:])), rawManifest(raw))
}

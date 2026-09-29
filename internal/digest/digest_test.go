package digest

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTar(t *testing.T, files map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.tar")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	f.Close()
	return p
}

func TestOCIArchive(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	p := writeTar(t, map[string]string{
		"oci-layout": `{"imageLayoutVersion":"1.0.0"}`,
		"index.json": `{"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"` + d + `"}]}`,
	})
	got, err := OCIArchive(p)
	if err != nil || got != d {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestOCIArchiveRejectsMultiManifest(t *testing.T) {
	d := `{"digest":"sha256:` + strings.Repeat("ab", 32) + `"}`
	p := writeTar(t, map[string]string{"index.json": `{"manifests":[` + d + `,` + d + `]}`})
	if _, err := OCIArchive(p); err == nil || !strings.Contains(err.Error(), "2 manifests") {
		t.Fatalf("err = %v", err)
	}
}

func TestFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("onion"), 0o644)
	got, err := File(p)
	if err != nil || got != Bytes([]byte("onion")) || !Valid(got) {
		t.Fatalf("got %q, %v", got, err)
	}
}

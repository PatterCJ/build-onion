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

func TestOCILayers(t *testing.T) {
	config := `{"rootfs":{"type":"layers","diff_ids":["sha256:` + strings.Repeat("1", 64) + `","sha256:` + strings.Repeat("2", 64) + `"]}}`
	configD := Bytes([]byte(config))
	manifest := `{"config":{"digest":"` + configD + `"}}`
	manifestD := Bytes([]byte(manifest))
	p := writeTar(t, map[string]string{
		"index.json":                     `{"manifests":[{"digest":"` + manifestD + `"}]}`,
		"blobs/sha256/" + Hex(manifestD): manifest,
		"blobs/sha256/" + Hex(configD):   config,
	})
	got, err := OCILayers(p)
	if err != nil || len(got) != 2 || !strings.HasSuffix(got[1], "2222") {
		t.Fatalf("got %v, %v", got, err)
	}
	// A config whose bytes don't match its digest is refused.
	bad := writeTar(t, map[string]string{
		"index.json":                     `{"manifests":[{"digest":"` + manifestD + `"}]}`,
		"blobs/sha256/" + Hex(manifestD): manifest,
		"blobs/sha256/" + Hex(configD):   config + " ",
	})
	if _, err := OCILayers(bad); err == nil {
		t.Fatal("tampered config accepted")
	}
}

func TestTree(t *testing.T) {
	mk := func() string {
		d := t.TempDir()
		os.MkdirAll(filepath.Join(d, "a", "b"), 0o755)
		os.WriteFile(filepath.Join(d, "a", "b", "f"), []byte("x"), 0o644)
		os.WriteFile(filepath.Join(d, "run.sh"), []byte("#!/bin/sh"), 0o755)
		os.Symlink("a/b/f", filepath.Join(d, "link"))
		return d
	}
	d1, d2 := mk(), mk()
	t1, n, err := Tree(d1)
	t2, _, _ := Tree(d2)
	if err != nil || n != 2 || t1 != t2 {
		t.Fatalf("same contents differ: %s %s (%d files, %v)", t1, t2, n, err)
	}
	for name, change := range map[string]func(string){
		"content":        func(d string) { os.WriteFile(filepath.Join(d, "a", "b", "f"), []byte("y"), 0o644) },
		"mode":           func(d string) { os.Chmod(filepath.Join(d, "run.sh"), 0o644) },
		"extra file":     func(d string) { os.WriteFile(filepath.Join(d, "extra"), nil, 0o644) },
		"symlink target": func(d string) { os.Remove(filepath.Join(d, "link")); os.Symlink("run.sh", filepath.Join(d, "link")) },
		"empty dir":      func(d string) { os.Mkdir(filepath.Join(d, "empty"), 0o755) },
	} {
		d := mk()
		change(d)
		if got, _, _ := Tree(d); got == t1 {
			t.Errorf("%s change not detected", name)
		}
	}
}

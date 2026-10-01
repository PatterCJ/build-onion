package imagefiles

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type entry struct {
	name, body, link string
	typ              byte
}

func layer(t *testing.T, entries ...entry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typ, Linkname: e.link}
		if e.typ == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if h.Typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		tw.WriteHeader(h)
		tw.Write([]byte(e.body))
	}
	tw.Close()
	data := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(h[:])
}

func TestList(t *testing.T) {
	base := layer(t,
		entry{name: "etc/", typ: tar.TypeDir},
		entry{name: "etc/passwd", body: "root"},
		entry{name: "bin/sh", typ: tar.TypeSymlink, link: "/bin/busybox"},
		entry{name: "usr/lib/old.so", body: "old"},
		entry{name: "cfg/a", body: "a"},
	)
	build := layer(t,
		entry{name: "./app/run", body: "binary"},
		entry{name: "usr/lib/.wh.old.so"},            // deletes a base file
		entry{name: "etc/passwd", body: "root\napp"}, // overwrites one
		entry{name: "app/run-link", typ: tar.TypeLink, link: "app/run"},
		entry{name: "../../escape", body: "x"}, // can't climb above the root
	)
	opaque := layer(t,
		entry{name: "cfg/.wh..wh..opq"}, // hides everything lower under cfg/
		entry{name: "cfg/b", body: "b"},
	)
	img, err := mutate.AppendLayers(empty.Image, base, build, opaque)
	if err != nil {
		t.Fatal(err)
	}
	baseID, _ := base.DiffID()
	got, err := List(img, []string{baseID.String()})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]File{}
	for _, f := range got.Files {
		files[f.Path] = f
	}
	want := map[string]File{
		"etc":          {Type: "dir", Layer: 0, Base: true},
		"etc/passwd":   {Type: "file", Layer: 1, SHA256: sum("root\napp"), Size: 8},
		"bin/sh":       {Type: "symlink", Layer: 0, Base: true, Link: "/bin/busybox"},
		"app/run":      {Type: "file", Layer: 1, SHA256: sum("binary"), Size: 6},
		"app/run-link": {Type: "hardlink", Layer: 1, Link: "app/run", SHA256: sum("binary"), Size: 6},
		"escape":       {Type: "file", Layer: 1, SHA256: sum("x"), Size: 1},
		"cfg/b":        {Type: "file", Layer: 2, SHA256: sum("b"), Size: 1},
	}
	if len(files) != len(want) {
		var paths []string
		for p := range files {
			paths = append(paths, p)
		}
		t.Errorf("paths = %v", paths)
	}
	for p, w := range want {
		g, ok := files[p]
		if !ok {
			t.Errorf("%s missing", p)
			continue
		}
		if g.Type != w.Type || g.Layer != w.Layer || g.Base != w.Base || g.SHA256 != w.SHA256 || g.Size != w.Size || g.Link != w.Link {
			t.Errorf("%s = %+v, want %+v", p, g, w)
		}
	}
	for _, gone := range []string{"usr/lib/old.so", "cfg/a"} {
		if _, ok := files[gone]; ok {
			t.Errorf("%s survived its whiteout", gone)
		}
	}
	if !got.Layers[0].Base || got.Layers[1].Base || len(got.Layers) != 3 {
		t.Errorf("layers = %+v", got.Layers)
	}

	// An image that doesn't start with its declared base is refused.
	other, _ := layer(t, entry{name: "x", body: "y"}).DiffID()
	if _, err := List(img, []string{other.String()}); err == nil || !strings.Contains(err.Error(), "doesn't start with its base") {
		t.Errorf("wrong base: %v", err)
	}
}

// An OCI layout tarball opens as its image; entries other than the layout's
// own files, including ones that try to escape, are never written.
func TestFromOCIArchive(t *testing.T) {
	img, _ := mutate.AppendLayers(empty.Image, layer(t, entry{name: "app/run", body: "binary"}))
	dir := t.TempDir()
	if _, err := layout.Write(dir, empty.Index); err != nil {
		t.Fatal(err)
	}
	p, _ := layout.FromPath(dir)
	if err := p.AppendImage(img); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		data, _ := os.ReadFile(path)
		tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(rel), Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		tw.Write(data)
		return nil
	})
	for _, hostile := range []string{"../../escaped", "blobs/sha256/../../../escaped2"} {
		tw.WriteHeader(&tar.Header{Name: hostile, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		tw.Write([]byte("x"))
	}
	tw.Close()
	archive := filepath.Join(t.TempDir(), "image.tar")
	os.WriteFile(archive, buf.Bytes(), 0o644)

	got, cleanup, err := FromOCIArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	want, _ := img.Digest()
	if d, _ := got.Digest(); d != want {
		t.Errorf("digest %s, want %s", d, want)
	}
	listing, err := List(got, nil)
	if err != nil || len(listing.Files) != 1 || listing.Files[0].Path != "app/run" {
		t.Errorf("listing = %+v, %v", listing, err)
	}
	for _, p := range []string{filepath.Join(os.TempDir(), "escaped"), filepath.Join(os.TempDir(), "escaped2")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was written outside the unpack directory", p)
		}
	}
}

// A hardlink listed before its target still gets the target's content; an
// empty whiteout name removes nothing; a root opaque marker hides every
// lower path.
func TestEdgeCases(t *testing.T) {
	l1 := layer(t, entry{name: "keep/a", body: "a"}, entry{name: "deep/x/y/z", body: "z"})
	l2 := layer(t,
		entry{name: "bin/link", typ: tar.TypeLink, link: "bin/real"},
		entry{name: "bin/real", body: "real"},
		entry{name: "keep/.wh."},
		entry{name: "deep/.wh.x"},
	)
	img, _ := mutate.AppendLayers(empty.Image, l1, l2)
	got, err := List(img, nil)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]File{}
	for _, f := range got.Files {
		files[f.Path] = f
	}
	if files["bin/link"].SHA256 != sum("real") {
		t.Errorf("hardlink before its target: %+v", files["bin/link"])
	}
	if _, ok := files["keep/a"]; !ok {
		t.Error("an empty whiteout name removed a file")
	}
	if _, ok := files["deep/x/y/z"]; ok {
		t.Error("whiteout of a directory left a file deep under it")
	}

	root := layer(t, entry{name: ".wh..wh..opq"}, entry{name: "new", body: "n"})
	img2, _ := mutate.AppendLayers(empty.Image, l1, root)
	got2, _ := List(img2, nil)
	if len(got2.Files) != 1 || got2.Files[0].Path != "new" {
		t.Errorf("root opaque: %+v", got2.Files)
	}
}

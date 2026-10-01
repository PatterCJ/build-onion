package main

import (
	"archive/tar"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"

	"github.com/PatterCJ/build-onion/internal/chain"
	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/source"
)

// ociTarball writes a random image as an OCI layout tarball.
func ociTarball(t *testing.T) string {
	t.Helper()
	img, _ := random.Image(64, 1)
	dir := t.TempDir()
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
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
	tw.Close()
	out := filepath.Join(t.TempDir(), "image.tar")
	os.WriteFile(out, buf.Bytes(), 0o644)
	return out
}

func TestLinkImage(t *testing.T) {
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	os.MkdirAll(repo, 0o755)
	os.WriteFile(filepath.Join(repo, "main.go"), []byte("package main\n"), 0o644)
	for _, a := range [][]string{{"init", "-q"}, {"add", "."}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, a...)...).CombinedOutput(); err != nil {
			t.Skipf("git: %v %s", err, out)
		}
	}
	snap, err := source.Take(repo)
	if err != nil {
		t.Fatal(err)
	}
	snapPath := filepath.Join(dir, "source.json")
	writeJSON(snapPath, snap)
	snapDigest := snap.Digest

	context := filepath.Join(dir, "context")
	os.MkdirAll(filepath.Join(context, "dist"), 0o755)
	os.WriteFile(filepath.Join(context, "dist", "app"), []byte("app"), 0o755)
	ctx, _, _ := digest.Tree(context)

	s := chain.Link{Step: chain.StepSnapshot, Run: "r1", Snapshot: snapDigest, Products: []chain.Resource{{Name: "source-snapshot", Digest: snapDigest}}}
	b, _ := chain.Next(s, chain.StepBuild, "r1", snapDigest)
	b.Materials = []chain.Resource{{Name: "source-snapshot", Digest: snapDigest}}
	b.Products = []chain.Resource{{Name: "image-context", Digest: ctx}}
	buildLink := filepath.Join(dir, "links", "build.json")
	os.MkdirAll(filepath.Dir(buildLink), 0o755)
	chain.Write(buildLink, b)
	chain.Write(filepath.Join(dir, "links", "snapshot.json"), s)
	imageLink := filepath.Join(dir, "links", "image.json")
	oci := ociTarball(t)

	args := []string{"image", "--oci", oci, "--context", context, "--snapshot", snapPath, "--link-in", buildLink, "--link-out", imageLink, "--run", "r1"}
	if err := cmdLinkImage(args); err != nil {
		t.Fatal(err)
	}
	links, err := readLinks(filepath.Join(dir, "links"))
	if err != nil || len(links) != 3 || links[2].Step != chain.StepImage {
		t.Fatalf("links: %+v %v", links, err)
	}
	want, _ := digest.OCIArchive(oci)
	if d, _ := links[2].Product("image"); d != want {
		t.Errorf("image product %s, want %s", d, want)
	}
	if err := chain.Verify(links, chain.Expected(false, true), snapDigest); err != nil {
		t.Errorf("chain: %v", err)
	}

	// The context changed after the build step recorded it.
	os.WriteFile(filepath.Join(context, "dist", "injected"), []byte("x"), 0o644)
	if err := cmdLinkImage(args); err == nil || !strings.Contains(err.Error(), "changed between phases") {
		t.Errorf("tampered context: %v", err)
	}
	// A record from another run.
	os.Remove(filepath.Join(context, "dist", "injected"))
	args[len(args)-1] = "r2"
	if err := cmdLinkImage(args); err == nil || !strings.Contains(err.Error(), "from run") {
		t.Errorf("other run: %v", err)
	}
	// A record that isn't a regular file.
	os.Symlink(buildLink, filepath.Join(dir, "links", "link.json"))
	if _, err := readLinks(filepath.Join(dir, "links")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("symlinked record accepted: %v", err)
	}
	os.Remove(filepath.Join(dir, "links", "link.json"))
	// Two records for one step.
	chain.Write(filepath.Join(dir, "links", "build2.json"), b)
	if _, err := readLinks(filepath.Join(dir, "links")); err == nil {
		t.Error("duplicate build records accepted")
	}
}

package source

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func repo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	write := func(p, body string) {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(p)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("main.go", "package main\n")
	write("go.sum", "x v1 h1:y\n")
	write("scripts/run.sh", "#!/bin/sh\n")
	write(".gitignore", "dist/\nsecret.txt\n")
	os.Chmod(filepath.Join(dir, "scripts/run.sh"), 0o755)
	os.Symlink("main.go", filepath.Join(dir, "link"))
	for _, args := range [][]string{{"init", "-q"}, {"add", "."}, {"commit", "-qm", "init"}} {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	return dir
}

func TestTakeAndVerifyClean(t *testing.T) {
	dir := repo(t)
	snap, err := Take(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Files) != 5 {
		t.Fatalf("got %d files: %+v", len(snap.Files), snap.Files)
	}
	modes := map[string]string{}
	for _, f := range snap.Files {
		modes[f.Path] = f.Mode
	}
	if modes["scripts/run.sh"] != "100755" || modes["link"] != "120000" {
		t.Errorf("modes = %v", modes)
	}
	if err := snap.Check(); err != nil {
		t.Fatal(err)
	}
	// Declared outputs may appear; nothing else changed.
	os.MkdirAll(filepath.Join(dir, "dist"), 0o755)
	os.WriteFile(filepath.Join(dir, "dist/app"), []byte("bin"), 0o755)
	d, err := Verify(dir, snap, []string{"dist/app"})
	if err != nil || !d.Empty() {
		t.Fatalf("drift = %+v, err = %v", d, err)
	}
	again, _ := Take(dir)
	if again.Digest != snap.Digest {
		t.Error("snapshot is not deterministic")
	}
}

func TestVerifyCatchesSwapAndPlants(t *testing.T) {
	dir := repo(t)
	snap, err := Take(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Swap a source file in place, keeping its size and mtime.
	p := filepath.Join(dir, "main.go")
	st, _ := os.Stat(p)
	os.WriteFile(p, []byte("package evil\n"[:len("package main\n")]), 0o644)
	os.Chtimes(p, st.ModTime(), st.ModTime())
	os.Remove(filepath.Join(dir, "go.sum"))
	// A planted file hidden by .gitignore must still be seen.
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("x"), 0o644)
	os.MkdirAll(filepath.Join(dir, "dist"), 0o755)
	os.WriteFile(filepath.Join(dir, "dist/extra"), []byte("x"), 0o644)

	d, err := Verify(dir, snap, []string{"dist/app"})
	if err != nil {
		t.Fatal(err)
	}
	msg := d.Error()
	for _, want := range []string{"modified: main.go", "missing: go.sum", "unexpected new file: secret.txt", "unexpected new file: dist/extra"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
}

func TestTakeRefusesDirtyTree(t *testing.T) {
	dir := repo(t)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package changed\n"), 0o644)
	if _, err := Take(dir); err == nil || !strings.Contains(err.Error(), "modified tracked files") {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckDetectsEditedList(t *testing.T) {
	dir := repo(t)
	snap, _ := Take(dir)
	snap.Files = snap.Files[1:]
	if err := snap.Check(); err == nil {
		t.Fatal("edited file list accepted")
	}
}

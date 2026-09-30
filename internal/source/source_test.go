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

func TestMatch(t *testing.T) {
	cases := []struct {
		pat, p string
		ok     bool
	}{
		{"go.mod", "go.mod", true},
		{"cmd/**/*.go", "cmd/onion/main.go", true},
		{"cmd/**/*.go", "cmd/main.go", true}, // ** matches zero segments
		{"internal/**/*.go", "internal/deps/testdata/generate.sh", false},
		{"internal/**/*.go", "internal/a/b/c.go", true},
		{"src/**", "src/pyonion/cli.py", true},
		{"src/**", "src", true},
		{"src/*", "src/pyonion/cli.py", false},
		{"*.go", "sub/x.go", false},
		{"**", "anything/at/all", true},
	}
	for _, c := range cases {
		if got := Match(c.pat, c.p); got != c.ok {
			t.Errorf("Match(%q, %q) = %v", c.pat, c.p, got)
		}
	}
}

func TestSubset(t *testing.T) {
	snap := &Snapshot{Files: []File{{Path: "build-onion.yml"}, {Path: "go.sum"}, {Path: "main.go"},
		{Path: "tests/files/bad-3-corrupt.xz"}, {Path: "docs/readme.md"}}}
	got, err := snap.Subset([]string{"*.go"}, []string{"build-onion.yml", "go.sum"})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, f := range got {
		paths = append(paths, f.Path)
	}
	if strings.Join(paths, ",") != "build-onion.yml,go.sum,main.go" {
		t.Errorf("subset = %v: test fixtures must not reach the build", paths)
	}
	if _, err := snap.Subset([]string{"*.go", "srcc/**"}, nil); err == nil || !strings.Contains(err.Error(), "srcc/**") {
		t.Errorf("typo'd pattern accepted: %v", err)
	}
	if all, _ := snap.Subset(nil, nil); len(all) != 5 {
		t.Errorf("no patterns should mean every tracked file, got %d", len(all))
	}
}

func TestStageAndVerify(t *testing.T) {
	dir := repo(t)
	snap, err := Take(dir)
	if err != nil {
		t.Fatal(err)
	}
	subset, err := snap.Subset([]string{"*.go", "scripts/**", "link"}, []string{"go.sum"})
	if err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if err := Stage(dir, stage, subset); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stage, ".gitignore")); !os.IsNotExist(err) {
		t.Error("an undeclared file reached the stage")
	}
	if st, _ := os.Stat(filepath.Join(stage, "scripts/run.sh")); st == nil || st.Mode().Perm()&0o100 == 0 {
		t.Error("executable bit lost")
	}
	if d, err := VerifyStage(stage, subset, []string{"dist"}); err != nil || !d.Empty() {
		t.Fatalf("fresh stage: %+v %v", d, err)
	}

	// A build that edits an input or writes outside its outputs is caught.
	os.WriteFile(filepath.Join(stage, "main.go"), []byte("package evil\n"), 0o644)
	os.MkdirAll(filepath.Join(stage, "dist"), 0o755)
	os.WriteFile(filepath.Join(stage, "dist/app"), []byte("ok"), 0o644)
	os.WriteFile(filepath.Join(stage, "planted.sh"), []byte("x"), 0o644)
	d, err := VerifyStage(stage, subset, []string{"dist"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.Modified, ",") != "main.go" || strings.Join(d.Unexpected, ",") != "planted.sh" {
		t.Fatalf("drift = %+v", d)
	}

	// Staging refuses a checkout that changed after the snapshot.
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package swapped\n"), 0o644)
	if err := Stage(dir, t.TempDir(), subset); err == nil || !strings.Contains(err.Error(), "differs from the snapshot") {
		t.Fatalf("swapped input staged: %v", err)
	}
}

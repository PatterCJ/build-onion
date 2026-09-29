// Package source takes a complete, content-addressed snapshot of a checkout —
// sha256 of every tracked file — and re-verifies it. The pipeline snapshots the
// source once, then checks it before and after every step, so a file swapped
// on disk or an output written somewhere undeclared is
// caught while the build is still running.
package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/digest"
)

// Snapshot is the hashed state of every tracked path in a checkout.
type Snapshot struct {
	Commit string `json:"commit"`
	Tree   string `json:"tree"`
	// Digest is sha256 over the canonical "mode digest path\n" lines, sorted
	// by path. Two snapshots are equal exactly when their digests are.
	Digest string `json:"digest"`
	Files  []File `json:"files"`
}

type File struct {
	Path   string `json:"path"`
	Mode   string `json:"mode"`   // git mode: 100644, 100755, 120000 (symlink), 160000 (submodule)
	Digest string `json:"digest"` // sha256 of content; of the link target for symlinks; "git:<sha>" for submodules
}

// Take snapshots dir. The checkout must be clean: a dirty tree means the bytes
// on disk are not the commit, and hashing them would bless the difference.
func Take(dir string) (*Snapshot, error) {
	if dirty, err := git(dir, "status", "--porcelain", "--untracked-files=no"); err != nil {
		return nil, err
	} else if dirty != "" {
		return nil, fmt.Errorf("checkout has modified tracked files:\n%s", dirty)
	}
	commit, err := git(dir, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	tree, err := git(dir, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return nil, err
	}
	files, err := hashTracked(dir)
	if err != nil {
		return nil, err
	}
	return &Snapshot{Commit: commit, Tree: tree, Digest: canonicalDigest(files), Files: files}, nil
}

// Drift is what changed between a snapshot and the checkout now.
type Drift struct {
	Modified   []string `json:"modified,omitempty"`
	Missing    []string `json:"missing,omitempty"`
	Unexpected []string `json:"unexpected,omitempty"` // new files outside the allowed output paths
}

func (d Drift) Empty() bool { return len(d.Modified)+len(d.Missing)+len(d.Unexpected) == 0 }

func (d Drift) Error() string {
	var b strings.Builder
	b.WriteString("source drifted from snapshot:")
	for _, s := range []struct {
		label string
		paths []string
	}{{"modified", d.Modified}, {"missing", d.Missing}, {"unexpected new file", d.Unexpected}} {
		for _, p := range s.paths {
			fmt.Fprintf(&b, "\n  %s: %s", s.label, p)
		}
	}
	return b.String()
}

// Verify re-hashes every file in the snapshot and lists any untracked file in
// dir that is not under one of allowNew (declared outputs). It hashes the
// bytes on disk directly and does not ask git, so a tampered index or stat
// cache cannot hide a change.
func Verify(dir string, snap *Snapshot, allowNew []string) (Drift, error) {
	var d Drift
	for _, f := range snap.Files {
		got, err := hashPath(dir, f)
		switch {
		case errors.Is(err, os.ErrNotExist):
			d.Missing = append(d.Missing, f.Path)
		case err != nil:
			return d, err
		case got != f.Digest:
			d.Modified = append(d.Modified, f.Path)
		}
	}
	// -o lists untracked files; without --exclude-standard, .gitignore'd files
	// are included too, so ignore rules cannot hide a planted file.
	out, err := gitRaw(dir, "ls-files", "-z", "-o")
	if err != nil {
		return d, err
	}
	for _, p := range splitZ(out) {
		if !underAny(p, allowNew) {
			d.Unexpected = append(d.Unexpected, p)
		}
	}
	return d, nil
}

func hashTracked(dir string) ([]File, error) {
	out, err := gitRaw(dir, "ls-files", "-z", "-s")
	if err != nil {
		return nil, err
	}
	var files []File
	for _, rec := range splitZ(out) {
		// "<mode> <blob> <stage>\t<path>"
		meta, p, ok := strings.Cut(rec, "\t")
		fields := strings.Fields(meta)
		if !ok || len(fields) != 3 {
			return nil, fmt.Errorf("unexpected ls-files record %q", rec)
		}
		f := File{Path: p, Mode: fields[0]}
		if f.Mode == "160000" {
			f.Digest = "git:" + fields[1]
		} else if f.Digest, err = hashPath(dir, f); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func hashPath(dir string, f File) (string, error) {
	full := filepath.Join(dir, filepath.FromSlash(f.Path))
	switch f.Mode {
	case "160000":
		return f.Digest, nil // submodule: pinned by commit; its contents are its own snapshot
	case "120000":
		target, err := os.Readlink(full)
		if err != nil {
			return "", err
		}
		return digest.Bytes([]byte(target)), nil
	}
	st, err := os.Lstat(full)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s: tracked as a file but is %s on disk", f.Path, st.Mode().Type())
	}
	return digest.File(full)
}

func canonicalDigest(files []File) string {
	h := sha256.New()
	for _, f := range files {
		fmt.Fprintf(h, "%s %s %s\n", f.Mode, f.Digest, f.Path)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Check recomputes the digest from the file list, so a snapshot read from
// disk cannot carry a list and a digest that disagree.
func (s *Snapshot) Check() error {
	if got := canonicalDigest(s.Files); got != s.Digest {
		return fmt.Errorf("snapshot digest %s does not match its file list (%s)", s.Digest, got)
	}
	return nil
}

func underAny(p string, prefixes []string) bool {
	for _, pre := range prefixes {
		pre = strings.TrimSuffix(path.Clean(pre), "/")
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

func git(dir string, args ...string) (string, error) {
	out, err := gitRaw(dir, args...)
	return strings.TrimSpace(string(out)), err
}

func gitRaw(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

func splitZ(b []byte) []string {
	var out []string
	for _, s := range strings.Split(string(b), "\x00") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

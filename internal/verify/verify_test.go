package verify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PatterCJ/build-onion/internal/manifest"
)

func TestCompare(t *testing.T) {
	m := &manifest.Manifest{Outputs: manifest.Outputs{Files: []string{"dist/a", "dist/b"}}}
	staged, rebuilt := t.TempDir(), t.TempDir()
	put := func(dir, name, body string) {
		os.MkdirAll(filepath.Join(dir, "files"), 0o755)
		os.WriteFile(filepath.Join(dir, "files", name), []byte(body), 0o644)
	}
	put(staged, "a", "same")
	put(rebuilt, "a", "same")
	put(staged, "b", "built")
	put(rebuilt, "b", "built")

	r, err := Compare(m, staged, rebuilt, "runner-2")
	if err != nil || !r.Matched || len(r.Outputs) != 2 || r.Runner != "runner-2" {
		t.Fatalf("r = %+v, err = %v", r, err)
	}

	put(staged, "b", "built+injected")
	r, err = Compare(m, staged, rebuilt, "runner-2")
	if err != nil || r.Matched || r.Outputs[0].Match != true || r.Outputs[1].Match != false {
		t.Fatalf("mismatch not detected: %+v, %v", r, err)
	}

	os.Remove(filepath.Join(rebuilt, "files", "a"))
	if _, err := Compare(m, staged, rebuilt, ""); err == nil {
		t.Fatal("missing rebuilt output accepted")
	}
}

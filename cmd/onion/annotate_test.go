package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stderr
	os.Stderr = w
	f()
	w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestAnnotate(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	if out := captureStderr(t, func() { annotate("error", "t", "m") }); out != "" {
		t.Errorf("annotated outside GitHub Actions: %q", out)
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	out := captureStderr(t, func() { annotate("error", "onion gate: blocked, 100%", "line one\nline two") })
	want := "::error title=onion gate%3A blocked%2C 100%25::line one%0Aline two\n"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
	if strings.Count(out, "\n") != 1 {
		t.Error("a multi-line message must stay one workflow command")
	}
}

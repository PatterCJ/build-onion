package chain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/digest"
)

var (
	snap  = digest.Bytes([]byte("snapshot"))
	cache = digest.Bytes([]byte("cache"))
	out   = digest.Bytes([]byte("widget"))
	img   = digest.Bytes([]byte("image"))
)

// goodChain is snapshot → fetch → build → image for one run.
func goodChain(t *testing.T) []Link {
	t.Helper()
	s := Link{Step: StepSnapshot, Run: "run-1", Snapshot: snap, Products: []Resource{{"source-snapshot", snap}}}
	f, err := Next(s, StepFetch, "run-1", snap)
	if err != nil {
		t.Fatal(err)
	}
	f.Materials, f.Products = []Resource{{"source-snapshot", snap}}, []Resource{{"cache", cache}}
	b, _ := Next(f, StepBuild, "run-1", snap)
	b.Materials, b.Products = []Resource{{"source-snapshot", snap}, {"cache", cache}}, []Resource{{"widget", out}}
	i, _ := Next(b, StepImage, "run-1", snap)
	i.Materials, i.Products = []Resource{{"widget", out}}, []Resource{{"image", img}}
	return []Link{s, f, b, i}
}

var full = Expected(true, true)

func TestVerify(t *testing.T) {
	if err := Verify(goodChain(t), full, snap); err != nil {
		t.Fatalf("good chain: %v", err)
	}
	cases := map[string]struct {
		mutate func([]Link) []Link
		want   string
	}{
		"build consumed another cache": {func(c []Link) []Link { c[2].Materials[1].Digest = digest.Bytes([]byte("swapped")); return c }, "consumed cache"},
		"build skipped the cache":      {func(c []Link) []Link { c[2].Materials = c[2].Materials[:1]; return c }, "didn't record consuming fetch's cache"},
		"fetch record rewritten":       {func(c []Link) []Link { c[1].Products[0].Digest = digest.Bytes([]byte("other")); return c }, "doesn't name the fetch record"},
		"step missing":                 {func(c []Link) []Link { return append(c[:1], c[2:]...) }, "the manifest implies 4"},
		"steps reordered":              {func(c []Link) []Link { c[1], c[2] = c[2], c[1]; return c }, "expected \"fetch\""},
		"record from another run":      {func(c []Link) []Link { c[3].Run = "run-2"; return c }, "from run"},
		"other source":                 {func(c []Link) []Link { c[0].Snapshot = digest.Bytes([]byte("x")); return c }, "this build's is"},
	}
	for name, c := range cases {
		err := Verify(c.mutate(goodChain(t)), full, snap)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if err := Verify(goodChain(t)[:3], Expected(true, false), snap); err != nil {
		t.Errorf("no image: %v", err)
	}
}

func TestNext(t *testing.T) {
	s := goodChain(t)[0]
	if _, err := Next(s, StepFetch, "run-2", snap); err == nil {
		t.Error("record from another run accepted")
	}
	if _, err := Next(s, StepFetch, "run-1", digest.Bytes([]byte("other"))); err == nil {
		t.Error("record for another source accepted")
	}
}

func TestReadIsStrict(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "l.json")
	if err := Write(p, goodChain(t)[1]); err != nil {
		t.Fatal(err)
	}
	if l, err := Read(p); err != nil || l.Step != StepFetch {
		t.Fatalf("round trip: %+v %v", l, err)
	}
	for name, body := range map[string]string{
		"unknown field": `{"step":"fetch","run":"r","snapshot":"` + snap + `","previous":"` + snap + `","products":[{"name":"c","digest":"` + cache + `"}],"command":"rm -rf /"}`,
		"bad digest":    `{"step":"fetch","run":"r","snapshot":"` + snap + `","previous":"` + snap + `","products":[{"name":"c","digest":"md5:x"}]}`,
		"unknown step":  `{"step":"deploy","run":"r","snapshot":"` + snap + `","previous":"` + snap + `","products":[{"name":"c","digest":"` + cache + `"}]}`,
		"no previous":   `{"step":"fetch","run":"r","snapshot":"` + snap + `","products":[{"name":"c","digest":"` + cache + `"}]}`,
	} {
		os.WriteFile(p, []byte(body), 0o644)
		if _, err := Read(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	os.WriteFile(p, make([]byte, maxLink+1), 0o644)
	if _, err := Read(p); err == nil {
		t.Error("oversized record accepted")
	}
}

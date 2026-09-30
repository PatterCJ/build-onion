package tagsig

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func keys(t *testing.T, names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, strings.TrimSpace(string(read(t, n))))
	}
	return out
}

func TestVerify(t *testing.T) {
	allowed, err := Keys(keys(t, "other.pub", "maintainer.pub"))
	if err != nil {
		t.Fatal(err)
	}
	tag, err := Verify(read(t, "signed.tag"), allowed)
	if err != nil {
		t.Fatal(err)
	}
	commit := strings.TrimSpace(string(read(t, "commit")))
	if tag.Name != "v1.0.0" || tag.Object != commit || tag.Type != "commit" || !strings.HasPrefix(tag.Key, "ssh-ed25519 ") {
		t.Errorf("tag = %+v", tag)
	}
}

func TestVerifyRejects(t *testing.T) {
	signed := read(t, "signed.tag")
	cases := map[string]struct {
		raw     []byte
		allowed []string
		want    string
	}{
		"signed by a key not allowed": {signed, keys(t, "other.pub"), "not an allowed signer"},
		"unsigned":                    {read(t, "unsigned.tag"), keys(t, "maintainer.pub"), "not signed"},
		"tag renamed":                 {bytes.Replace(signed, []byte("tag v1.0.0"), []byte("tag v9.9.9"), 1), keys(t, "maintainer.pub"), "does not verify"},
		"object moved": {bytes.Replace(signed, []byte("object "), []byte("object 0000000000000000000000000000000000000000\nx"), 1),
			keys(t, "maintainer.pub"), "does not verify"},
		"no allowed keys": {signed, nil, "no allowed signer keys"},
	}
	for name, c := range cases {
		allowed, err := Keys(c.allowed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(c.raw, allowed); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	if _, err := Keys([]string{"not a key"}); err == nil {
		t.Error("garbage key accepted")
	}
}

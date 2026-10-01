package repo

import "testing"

func TestURL(t *testing.T) {
	for in, want := range map[string]string{
		"PatterCJ/build-onion":                     "https://github.com/PatterCJ/build-onion",
		"github.com/PatterCJ/build-onion":          "https://github.com/PatterCJ/build-onion",
		"https://github.com/PatterCJ/build-onion/": "https://github.com/PatterCJ/build-onion",
		"gitlab.com/PatterCJ/onion":                "https://gitlab.com/PatterCJ/onion",
		"https://gitlab.com/PatterCJ/onion.git":    "https://gitlab.com/PatterCJ/onion",
		"gitlab.example.com/a/b/c":                 "https://gitlab.example.com/a/b/c",
		"https://GitHub.com/a/b":                   "https://github.com/a/b",
		"gitlab.corp.example:8443/team/app":        "https://gitlab.corp.example:8443/team/app",
	} {
		if got, err := URL(in); err != nil || got != want {
			t.Errorf("URL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "onion", "PatterCJ/build-onion/extra", "github.com/a/b/c", "gitlab.com/onion",
		"http://gitlab.com/a/b", "gitlab.com/a/../b", "gitlab.com/a/b?x=1", "gitlab.com//a/b",
		"https://gitlab.com/a/b#frag", "gitlab.com/a/.b", "user@gitlab.com/a/b",
		"https://GitHub.com/a/b/c", "gitlab.com:x/a/b", "-gitlab.com/a/b", "gitlab..com/a/b",
	} {
		if got, err := URL(bad); err == nil {
			t.Errorf("URL(%q) = %q, want an error", bad, got)
		}
	}
}

func TestSame(t *testing.T) {
	if !Same("PatterCJ/Build-Onion", "https://github.com/pattercj/build-onion") {
		t.Error("case or form difference treated as another repository")
	}
	if Same("gitlab.com/PatterCJ/onion", "PatterCJ/onion") {
		t.Error("same path on different hosts treated as one repository")
	}
	if Same("not a repo", "not a repo") {
		t.Error("invalid names compared equal")
	}
}

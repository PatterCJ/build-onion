// Package repo names source repositories on any host by one canonical URL.
package repo

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	segmentRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	hostRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[0-9]{1,5})?$`)
)

// URL returns the canonical https URL for a repository given as OWNER/REPO
// (on GitHub), HOST[:PORT]/PATH (for example gitlab.com/group/project), or
// https://HOST/PATH. A trailing ".git" or "/" is dropped. GitHub owners
// can't contain dots, so a first segment with one is always a host.
func URL(s string) (string, error) {
	in := s
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	s, hasScheme := strings.CutPrefix(s, "https://")
	parts := strings.Split(s, "/")
	if !hasScheme && !strings.Contains(parts[0], ".") {
		parts = append([]string{"github.com"}, parts...)
	}
	parts[0] = strings.ToLower(parts[0])
	host, path := parts[0], parts[1:]
	ok := hostRe.MatchString(host) && len(path) >= 2
	for _, p := range path {
		ok = ok && segmentRe.MatchString(p) && !strings.Contains(p, "..")
	}
	if host == "github.com" && len(path) != 2 {
		ok = false
	}
	if !ok {
		return "", fmt.Errorf("repository %q: want OWNER/REPO (GitHub), HOST/PATH or https://HOST/PATH", in)
	}
	return "https://" + strings.Join(parts, "/"), nil
}

// Same reports whether two repository names are the same repository. Hosts
// treat paths case-insensitively.
func Same(a, b string) bool {
	ua, errA := URL(a)
	ub, errB := URL(b)
	return errA == nil && errB == nil && strings.EqualFold(ua, ub)
}

// IsGitHub reports whether a canonical URL is on github.com.
func IsGitHub(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "https://github.com/")
}

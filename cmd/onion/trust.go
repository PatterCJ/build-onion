package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/peel"
	"github.com/PatterCJ/build-onion/internal/tagsig"
	"github.com/PatterCJ/build-onion/internal/trust"
)

func cmdTrust(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("usage: onion trust add --trust FILE --repo OWNER/REPO --tag TAG")
	}
	return cmdTrustAdd(args[1:])
}

// onion trust add: vet a new builder release with the onion already trusted,
// then add it to the trust file. The new release's code never judges itself:
// this binary checks its tag signature and peels its sealed release.
func cmdTrustAdd(args []string) error {
	fs := flag.NewFlagSet("trust add", flag.ExitOnError)
	file := fs.String("trust", "", "trust file to add the release to (required)")
	repo := fs.String("repo", "PatterCJ/build-onion", "builder repository, OWNER/REPO")
	tag := fs.String("tag", "", "release tag to add, e.g. v0.2.0 (required)")
	asset := fs.String("asset", "onion", "release asset to peel")
	signerPath := fs.String("signer-path", ".github/workflows/onion-verify.yml", "the builder's signing workflow, relative to its repository")
	trustedRoot := fs.String("trusted-root", "", "Sigstore trusted_root.json (default: public-good via TUF)")
	allowDegraded := fs.Bool("allow-degraded", false, "accept a release whose peel verdict is DEGRADED or UNSUPPORTED")
	fs.Parse(args)
	if *file == "" || *tag == "" {
		return errors.New("--trust and --tag are required")
	}
	f, err := trust.Load(*file)
	if err != nil {
		return err
	}
	b := f.Builder(*repo)
	if b == nil || len(b.TagSigners) == 0 {
		return fmt.Errorf("%s: no tagSigners for %s; list the keys allowed to sign its release tags first", *file, *repo)
	}

	// 1. The tag is signed by an allowed key, and names the commit.
	raw, err := fetchTag(*repo, *tag)
	if err != nil {
		return err
	}
	keys, err := tagsig.Keys(b.TagSigners)
	if err != nil {
		return err
	}
	t, err := tagsig.Verify(raw, keys)
	if err != nil {
		return fmt.Errorf("tag %s: %w", *tag, err)
	}
	if t.Name != *tag || t.Type != "commit" {
		return fmt.Errorf("tag object is %s %q, fetched as %q", t.Type, t.Name, *tag)
	}
	fmt.Fprintf(os.Stderr, "trust: %s %s signed by %s → commit %s\n", *repo, *tag, t.Key, t.Object)
	if rel, ok := f.Trusted(*repo, t.Object); ok {
		return fmt.Errorf("%s is already trusted as %s", t.Object, rel.Tag)
	}

	// 2. Its sealed release peels, judged by this (already trusted) binary.
	// The release was sealed by its own signing workflow, so that one commit
	// is accepted as the builder for this check only.
	dir, err := os.MkdirTemp("", "onion-trust-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, *asset)
	if err := downloadAsset(*repo, *tag, *asset, path); err != nil {
		return err
	}
	d, err := digest.File(path)
	if err != nil {
		return err
	}
	cands, err := attest.FromGitHub(context.Background(), *repo, d, os.Getenv("GITHUB_TOKEN"))
	if err != nil {
		return err
	}
	id := attest.Identity{SignerWorkflow: *repo + "/" + *signerPath}
	v, err := attest.NewVerifier(*trustedRoot, id)
	if err != nil {
		return err
	}
	candidate := trust.File{Builders: []trust.Builder{{Repository: *repo, Releases: []trust.Release{{Tag: *tag, Commit: t.Object}}}}}
	rep := peel.Run(peel.Input{
		Artifact:   fmt.Sprintf("%s (%s %s)", *asset, *repo, *tag),
		Digest:     d,
		Claim:      peel.Claim{Repository: *repo, Commit: t.Object},
		Signer:     id,
		Verifier:   v,
		Candidates: cands,
		Refs:       []string{"refs/tags/" + *tag},
		Trust:      &candidate,
	})
	printReport(os.Stderr, rep)
	if rep.ExitCode(*allowDegraded) != 0 {
		return fmt.Errorf("%s %s did not verify (%s); not added", *repo, *tag, rep.Verdict)
	}

	// 3. Record it.
	rel := trust.Release{Tag: *tag, Commit: t.Object, Added: time.Now().UTC().Format("2006-01-02")}
	if err := trust.Append(*file, *repo, rel); err != nil {
		return err
	}
	fmt.Printf("trusted %s %s (%s)\n", *repo, *tag, t.Object)
	return nil
}

// gitHost serves builder repositories; tests point it at a local directory.
var gitHost = "https://github.com/"

// fetchTag returns the raw annotated tag object, fetched with git so its
// bytes are exactly what was signed.
func fetchTag(repo, tag string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "onion-tag-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	ref := "refs/tags/" + tag
	for _, a := range [][]string{
		{"init", "-q"},
		{"fetch", "-q", "--no-tags", "--depth=1", gitHost + repo + ".git", "+" + ref + ":" + ref},
	} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, a...)...).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("git %s: %v: %s", a[0], err, strings.TrimSpace(string(out)))
		}
	}
	out, err := exec.Command("git", "-C", dir, "cat-file", "tag", ref).Output()
	if err != nil {
		return nil, fmt.Errorf("%s is not an annotated tag; release tags must be signed (git tag -s)", tag)
	}
	return out, nil
}

// downloadAsset fetches a GitHub release asset by name.
func downloadAsset(repo, tag, name, dest string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	get := func(url, accept string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", accept)
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("%s: %s", url, resp.Status)
		}
		return resp, err
	}
	resp, err := get("https://api.github.com/repos/"+repo+"/releases/tags/"+tag, "application/vnd.github+json")
	if err != nil {
		return err
	}
	var rel struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"assets"`
	}
	err = json.NewDecoder(resp.Body).Decode(&rel)
	resp.Body.Close()
	if err != nil {
		return err
	}
	for _, a := range rel.Assets {
		if a.Name != name {
			continue
		}
		resp, err := get(a.URL, "application/octet-stream")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		out, err := os.Create(dest)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(resp.Body, 1<<30)); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	return fmt.Errorf("release %s of %s has no asset %q", tag, repo, name)
}

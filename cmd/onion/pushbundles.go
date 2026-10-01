package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"

	"github.com/PatterCJ/build-onion/internal/attest"
	"github.com/PatterCJ/build-onion/internal/ocibundle"
)

// onion push-bundles: store the bundles about an image in its registry, next
// to it, so any verifier can find them without the CI platform's API.
func cmdPushBundles(args []string) error {
	fs := flag.NewFlagSet("push-bundles", flag.ExitOnError)
	image := fs.String("image", "", "image as NAME@sha256:HEX (required)")
	dir := fs.String("bundles", "", "directory of bundles (*.json, *.jsonl); those about the image are pushed (required)")
	fs.Parse(args)
	if *image == "" || *dir == "" {
		return errors.New("--image and --bundles are required")
	}
	subject, err := name.NewDigest(*image, name.StrictValidation)
	if err != nil {
		return fmt.Errorf("--image: %w", err)
	}
	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	existing, err := ocibundle.Fetch(subject, opts...)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, e := range existing {
		have[string(e)] = true
	}
	docs, err := readBundleDocs(*dir)
	if err != nil {
		return err
	}
	pushed, skipped := 0, 0
	for _, doc := range docs {
		var b bundle.Bundle
		if err := b.UnmarshalJSON(doc.raw); err != nil {
			return fmt.Errorf("%s: %w", doc.source, err)
		}
		if about, _ := (attest.Candidate{Bundle: &b}).About(subject.DigestStr()); !about {
			continue
		}
		if have[string(doc.raw)] {
			skipped++
			continue
		}
		ref, err := ocibundle.Push(subject, doc.raw, predicateType(doc.raw), opts...)
		if err != nil {
			return fmt.Errorf("%s: %w", doc.source, err)
		}
		fmt.Fprintf(os.Stderr, "push-bundles: %s → %s\n", doc.source, ref)
		pushed++
	}
	if pushed+skipped == 0 {
		return fmt.Errorf("no bundle in %s is about %s", *dir, subject.DigestStr())
	}
	fmt.Fprintf(os.Stderr, "push-bundles: %d pushed, %d already there, for %s\n", pushed, skipped, subject)
	return nil
}

type bundleDoc struct {
	source string
	raw    []byte
}

func readBundleDocs(dir string) ([]bundleDoc, error) {
	var out []bundleDoc
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		ext := filepath.Ext(p)
		if ext != ".json" && ext != ".jsonl" {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if ext == ".json" {
			out = append(out, bundleDoc{p, []byte(strings.TrimSpace(string(data)))})
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				out = append(out, bundleDoc{fmt.Sprintf("%s[%d]", p, i), []byte(line)})
			}
		}
		return nil
	})
	return out, err
}

// predicateType reads a bundle's in-toto predicate type, or "".
func predicateType(raw []byte) string {
	var b struct {
		Envelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if json.Unmarshal(raw, &b) != nil {
		return ""
	}
	payload, err := base64.StdEncoding.DecodeString(b.Envelope.Payload)
	if err != nil {
		return ""
	}
	var st struct {
		PredicateType string `json:"predicateType"`
	}
	json.Unmarshal(payload, &st)
	return st.PredicateType
}

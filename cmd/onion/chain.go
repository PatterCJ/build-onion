package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/chain"
	"github.com/PatterCJ/build-onion/internal/digest"
)

// linkFlags are the phase-record flags shared by the phase commands.
type linkFlags struct{ in, out, run string }

func (l *linkFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&l.in, "link-in", "", "the previous phase's record; its products must be this phase's inputs")
	fs.StringVar(&l.out, "link-out", "", "write this phase's record here (single-pipeline builds)")
	fs.StringVar(&l.run, "run", "", "the CI run, shared by every phase record (with --link-out)")
}

// start returns the new record for step, checked against the previous one.
// It returns nil when no record was asked for.
func (l linkFlags) start(step, snapshotDigest string) (*chain.Link, *chain.Link, error) {
	if l.out == "" {
		if l.in != "" {
			return nil, nil, errors.New("--link-in needs --link-out")
		}
		return nil, nil, nil
	}
	if l.run == "" || snapshotDigest == "" {
		return nil, nil, errors.New("--link-out needs --run and --snapshot")
	}
	if l.in == "" {
		return nil, nil, fmt.Errorf("the %s record needs the previous one (--link-in)", step)
	}
	prev, err := chain.Read(l.in)
	if err != nil {
		return nil, nil, err
	}
	next, err := chain.Next(prev, step, l.run, snapshotDigest)
	if err != nil {
		return nil, nil, err
	}
	return &next, &prev, nil
}

// treeProduct digests a directory handed to the next phase.
func treeProduct(name, dir string) (chain.Resource, error) {
	d, _, err := digest.Tree(dir)
	if err != nil {
		return chain.Resource{}, fmt.Errorf("%s: %w", name, err)
	}
	return chain.Resource{Name: name, Digest: d}, nil
}

// requireProduct checks that what this phase is about to use is what the
// previous phase produced.
func requireProduct(prev *chain.Link, got chain.Resource) error {
	want, ok := prev.Product(got.Name)
	if !ok {
		return fmt.Errorf("the %s record has no %s", prev.Step, got.Name)
	}
	if want != got.Digest {
		return fmt.Errorf("%s is %s, but the %s step produced %s: it changed between phases", got.Name, got.Digest, prev.Step, want)
	}
	return nil
}

// onion link image: the record for the image build, which runs outside
// onion (docker buildx, buildah …). It checks the build context and output
// files are what the build step produced, and records the image.
func cmdLinkImage(args []string) error {
	if len(args) == 0 || args[0] != "image" {
		return errors.New("usage: onion link image --oci image.tar --context DIR [--files DIR] --snapshot FILE --link-in FILE --link-out FILE --run RUN")
	}
	fs := flag.NewFlagSet("link image", flag.ExitOnError)
	var l linkFlags
	l.register(fs)
	oci := fs.String("oci", "", "the built image, as an OCI layout tarball (required)")
	context := fs.String("context", "", "the build context the image was built from (required)")
	files := fs.String("files", "", "the build's output files, if it declared any")
	snapPath := fs.String("snapshot", "", "source snapshot (required)")
	fs.Parse(args[1:])
	if *oci == "" || *context == "" || *snapPath == "" || l.out == "" {
		return errors.New("--oci, --context, --snapshot and --link-out are required")
	}
	snap, err := loadSnapshot(*snapPath, "")
	if err != nil {
		return err
	}
	link, prev, err := l.start(chain.StepImage, snap.Digest)
	if err != nil {
		return err
	}
	ctx, err := treeProduct("image-context", *context)
	if err != nil {
		return err
	}
	if err := requireProduct(prev, ctx); err != nil {
		return err
	}
	link.Materials = append(link.Materials, ctx)
	if *files != "" {
		outs, err := fileProducts(*files)
		if err != nil {
			return err
		}
		for _, o := range outs {
			if err := requireProduct(prev, o); err != nil {
				return err
			}
		}
		link.Materials = append(link.Materials, outs...)
	}
	img, err := digest.OCIArchive(*oci)
	if err != nil {
		return err
	}
	link.Products = []chain.Resource{{Name: "image", Digest: img}}
	return chain.Write(l.out, *link)
}

// fileProducts digests the regular files directly in dir, by name.
func fileProducts(dir string) ([]chain.Resource, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []chain.Resource
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		d, err := digest.File(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, chain.Resource{Name: "file " + e.Name(), Digest: d})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// readLinks loads the records in dir, in pipeline order.
func readLinks(dir string) ([]chain.Link, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	order := map[string]int{chain.StepSnapshot: 0, chain.StepFetch: 1, chain.StepBuild: 2, chain.StepImage: 3}
	var links []chain.Link
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		l, err := chain.Read(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if seen[l.Step] {
			return nil, fmt.Errorf("%s: more than one %s record", dir, l.Step)
		}
		seen[l.Step] = true
		links = append(links, l)
	}
	sort.Slice(links, func(i, j int) bool { return order[links[i].Step] < order[links[j].Step] })
	return links, nil
}

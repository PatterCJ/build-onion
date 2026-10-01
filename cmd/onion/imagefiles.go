package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/PatterCJ/build-onion/internal/imagefiles"
)

// onion image-files: list every file in an image's final filesystem and
// the layer it came from, base or built. A fact for cross-referencing; it
// grades nothing.
func cmdImageFiles(args []string) error {
	fs := flag.NewFlagSet("image-files", flag.ExitOnError)
	oci := fs.String("oci", "", "OCI image-layout tarball (as the build writes image.tar)")
	image := fs.String("image", "", "image reference, pinned by digest (linux/amd64)")
	base := fs.String("base", "", "the image's base, pinned by digest: its layers are marked base")
	out := fs.String("out", "", "write the JSON here (default: stdout)")
	fs.Parse(args)
	if (*oci == "") == (*image == "") {
		return errors.New("give exactly one of --oci or --image")
	}
	var img v1.Image
	var err error
	if *oci != "" {
		var cleanup func()
		if img, cleanup, err = imagefiles.FromOCIArchive(*oci); err != nil {
			return err
		}
		defer cleanup()
	} else {
		ref, err := name.NewDigest(*image, name.StrictValidation)
		if err != nil {
			return fmt.Errorf("--image must be pinned by digest: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if img, err = remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain),
			remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"})); err != nil {
			return err
		}
	}
	var baseLayers []string
	if *base != "" {
		if baseLayers, err = resolveBaseLayers(*base); err != nil {
			return fmt.Errorf("--base: %w", err)
		}
	}
	listing, err := imagefiles.List(img, baseLayers)
	if err != nil {
		return err
	}
	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(listing); err != nil {
		return err
	}
	byBase := 0
	for _, f := range listing.Files {
		if f.Base {
			byBase++
		}
	}
	fmt.Fprintf(os.Stderr, "image-files: %d path(s): %d from base layers, %d added by the build\n", len(listing.Files), byBase, len(listing.Files)-byBase)
	return nil
}

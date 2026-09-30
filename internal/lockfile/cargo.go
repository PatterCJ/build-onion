package lockfile

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
)

func init() {
	register("cargo", func(base string) bool { return base == "Cargo.lock" }, parseCargoLock)
}

// parseCargoLock reads Cargo.lock. Packages without a source are workspace
// members, built from this source.
func parseCargoLock(data []byte, _ Sibling) (Result, error) {
	var lock struct {
		Package []struct {
			Name     string `toml:"name"`
			Version  string `toml:"version"`
			Source   string `toml:"source"`
			Checksum string `toml:"checksum"`
		} `toml:"package"`
	}
	if _, err := toml.NewDecoder(bytes.NewReader(data)).Decode(&lock); err != nil {
		return Result{}, err
	}
	var res Result
	for _, p := range lock.Package {
		if p.Source == "" {
			res.Local = append(res.Local, Local{Name: p.Name})
			continue
		}
		if p.Version == "" {
			return Result{}, fmt.Errorf("package %s has no version", p.Name)
		}
		pkg := Package{Name: p.Name, Version: p.Version}
		if p.Checksum != "" {
			d, err := archiveDigest(p.Checksum, "sha256")
			if err != nil {
				return Result{}, fmt.Errorf("package %s: %w", p.Name, err)
			}
			pkg.Archives = []string{d}
		}
		res.Packages = append(res.Packages, pkg)
	}
	return res, nil
}

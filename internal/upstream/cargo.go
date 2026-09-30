package upstream

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PatterCJ/build-onion/internal/lockfile"
)

// checkCargo compares Cargo.lock's checksum with the crates.io index.
// crates.io publishes no provenance, so the strongest outcome is Published.
func (c *Checker) checkCargo(ctx context.Context, p lockfile.Package, r *Result) {
	if len(p.Archives) == 0 {
		r.Outcome, r.Detail = Unhashed, "lockfile has no checksum for it (git or path source)"
		return
	}
	body, err := c.get(ctx, c.Registries.Crates+"/"+crateIndexPath(p.Name), "")
	if err != nil {
		fail(r, err, p.Name)
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		var v struct {
			Vers   string `json:"vers"`
			Cksum  string `json:"cksum"`
			Yanked bool   `json:"yanked"`
		}
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			r.Outcome, r.Detail = Error, fmt.Sprintf("index entry: %v", err)
			return
		}
		if v.Vers != p.Version {
			continue
		}
		published := "sha256:" + strings.ToLower(v.Cksum)
		if published != p.Archives[0] {
			r.Outcome, r.Detail = Mismatch, fmt.Sprintf("lockfile pins %s, crates.io publishes %s", short(p.Archives[0]), short(published))
			return
		}
		r.Outcome, r.Detail = Published, "crates.io publishes no provenance"
		if v.Yanked {
			r.Detail = "yanked on crates.io; crates.io publishes no provenance"
		}
		return
	}
	if err := sc.Err(); err != nil {
		r.Outcome, r.Detail = Error, err.Error()
		return
	}
	r.Outcome, r.Detail = NotFound, fmt.Sprintf("%s %s not on crates.io", p.Name, p.Version)
}

// crateIndexPath is a crate's file in the sparse index: 1/a, 2/ab, 3/a/abc,
// ab/cd/abcd….
func crateIndexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 1:
		return "1/" + n
	case 2:
		return "2/" + n
	case 3:
		return "3/" + n[:1] + "/" + n
	}
	return n[:2] + "/" + n[2:4] + "/" + n
}

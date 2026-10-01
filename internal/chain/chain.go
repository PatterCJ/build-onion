// Package chain records what each phase of a single-pipeline build consumed
// and produced, so the seal can show every hand-off between phases matched.
//
// Records are modelled on in-toto links (materials and products) and are
// unsigned: phases that run a repository's build code never hold signing
// rights. The seal signs the whole chain once, inside the inventory, and a
// record never replaces a check the seal can make itself: the seal
// recomputes the source snapshot and the outputs and compares them with the
// chain.
package chain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/PatterCJ/build-onion/internal/digest"
)

// Steps, in pipeline order.
const (
	StepSnapshot = "snapshot"
	StepFetch    = "fetch"
	StepBuild    = "build"
	StepImage    = "image"
)

// Resource is one input or output, by digest.
type Resource struct {
	Name   string `json:"name"`
	Digest string `json:"digest"` // sha256:<hex>
}

// Link is one phase's record.
type Link struct {
	Step      string     `json:"step"`
	Run       string     `json:"run"`      // the CI run, shared by every link
	Snapshot  string     `json:"snapshot"` // the source snapshot, shared by every link
	Previous  string     `json:"previous,omitempty"`
	Materials []Resource `json:"materials,omitempty"`
	Products  []Resource `json:"products"`
}

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// maxLink bounds a record file: records hold digests, not content.
const maxLink = 1 << 20

// Digest identifies a link for the next one's Previous.
func (l Link) Digest() string {
	b, _ := json.Marshal(l)
	return digest.Bytes(b)
}

// Product returns the digest of a named product.
func (l Link) Product(name string) (string, bool) {
	for _, r := range l.Products {
		if r.Name == name {
			return r.Digest, true
		}
	}
	return "", false
}

// Read loads a link, strictly: unknown fields and malformed digests are
// errors.
func Read(p string) (Link, error) {
	f, err := os.Open(p)
	if err != nil {
		return Link{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return Link{}, err
	}
	if st.Size() > maxLink {
		return Link{}, fmt.Errorf("%s: %d bytes is too large for a phase record", p, st.Size())
	}
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var l Link
	if err := dec.Decode(&l); err != nil {
		return Link{}, fmt.Errorf("%s: %w", p, err)
	}
	return l, l.check()
}

// Write saves a link.
func Write(p string, l Link) error {
	if err := l.check(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o644)
}

func (l Link) check() error {
	switch l.Step {
	case StepSnapshot, StepFetch, StepBuild, StepImage:
	default:
		return fmt.Errorf("unknown step %q", l.Step)
	}
	if l.Run == "" || !digestRe.MatchString(l.Snapshot) {
		return fmt.Errorf("%s record needs a run and a source snapshot digest", l.Step)
	}
	if (l.Step == StepSnapshot) != (l.Previous == "") {
		return fmt.Errorf("%s record: only the snapshot record has no previous record", l.Step)
	}
	if l.Previous != "" && !digestRe.MatchString(l.Previous) {
		return fmt.Errorf("%s record: malformed previous digest", l.Step)
	}
	for _, r := range append(append([]Resource{}, l.Materials...), l.Products...) {
		if r.Name == "" || !digestRe.MatchString(r.Digest) {
			return fmt.Errorf("%s record: resource %q needs a name and a sha256 digest", l.Step, r.Name)
		}
	}
	if len(l.Products) == 0 {
		return fmt.Errorf("%s record has no products", l.Step)
	}
	return nil
}

// Next starts the record that follows prev, after checking prev is for
// this run and source.
func Next(prev Link, step, run, snapshot string) (Link, error) {
	if prev.Run != run {
		return Link{}, fmt.Errorf("previous %s record is from run %q, not %q", prev.Step, prev.Run, run)
	}
	if prev.Snapshot != snapshot {
		return Link{}, fmt.Errorf("previous %s record is for source %s, not %s", prev.Step, prev.Snapshot, snapshot)
	}
	return Link{Step: step, Run: run, Snapshot: snapshot, Previous: prev.Digest()}, nil
}

// Expected is the sequence of steps a manifest implies.
func Expected(hasFetch, hasImage bool) []string {
	steps := []string{StepSnapshot}
	if hasFetch {
		steps = append(steps, StepFetch)
	}
	steps = append(steps, StepBuild)
	if hasImage {
		steps = append(steps, StepImage)
	}
	return steps
}

// Verify checks a chain: exactly the expected steps in order, one run and
// one source snapshot throughout, each record naming its predecessor, and
// each record's materials matching what the previous step produced.
func Verify(links []Link, expected []string, snapshot string) error {
	if len(links) != len(expected) {
		return fmt.Errorf("chain has %d record(s), the manifest implies %d (%v)", len(links), len(expected), expected)
	}
	var errs []error
	for i, l := range links {
		if err := l.check(); err != nil {
			errs = append(errs, err)
			continue
		}
		if l.Step != expected[i] {
			errs = append(errs, fmt.Errorf("record %d is %q, expected %q", i, l.Step, expected[i]))
		}
		if l.Snapshot != snapshot {
			errs = append(errs, fmt.Errorf("%s record is for source %s, this build's is %s", l.Step, l.Snapshot, snapshot))
		}
		if i == 0 {
			if d, ok := l.Product("source-snapshot"); !ok || d != snapshot {
				errs = append(errs, errors.New("snapshot record doesn't name this build's source snapshot"))
			}
			continue
		}
		prev := links[i-1]
		if l.Run != prev.Run {
			errs = append(errs, fmt.Errorf("%s record is from run %q, %s from %q", l.Step, l.Run, prev.Step, prev.Run))
		}
		if l.Previous != prev.Digest() {
			errs = append(errs, fmt.Errorf("%s record doesn't name the %s record before it", l.Step, prev.Step))
		}
		// Each step consumed everything its predecessor produced, exactly
		// as produced.
		for _, p := range prev.Products {
			got := ""
			for _, m := range l.Materials {
				if m.Name == p.Name {
					got = m.Digest
				}
			}
			switch {
			case got == "":
				errs = append(errs, fmt.Errorf("%s didn't record consuming %s's %s", l.Step, prev.Step, p.Name))
			case got != p.Digest:
				errs = append(errs, fmt.Errorf("%s consumed %s %s, but %s produced %s", l.Step, p.Name, got, prev.Step, p.Digest))
			}
		}
	}
	return errors.Join(errs...)
}

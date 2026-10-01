// Package trust reads the verifier's list of trusted build-onion releases.
// The file belongs to whoever runs `onion peel` as a gate, not to the
// repositories being verified: an artifact is accepted only if it was
// sealed by a release on this list.
package trust

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PatterCJ/build-onion/internal/signer"
	"github.com/PatterCJ/build-onion/internal/tagsig"
)

const APIVersion = "build-onion/trust/v1"

type File struct {
	APIVersion string    `yaml:"apiVersion"`
	Builders   []Builder `yaml:"builders"`
	// Apps pin who may sign release tags for the repositories being
	// verified. A repository listed here must be released from a tag signed
	// by one of its keys, whatever its own policy says.
	Apps []App `yaml:"apps,omitempty"`
}

// App is one repository whose artifacts the verifier accepts.
type App struct {
	Repository string   `yaml:"repository"` // OWNER/REPO
	TagSigners []string `yaml:"tagSigners"`
}

// Builder is one identity that may seal artifacts: build-onion's reusable
// workflows in a repository (keyless, identified by the signing
// certificate), or an enterprise signing key (Name and Key).
type Builder struct {
	Repository string `yaml:"repository,omitempty"` // OWNER/REPO
	// Name and Key identify a key builder: artifacts sealed with this key
	// (PEM public key, ECDSA P-256 or P-384) are accepted.
	Name string `yaml:"name,omitempty"`
	Key  string `yaml:"key,omitempty"`
	// TagSigners are the keys (authorized_keys form) whose signed tags may
	// be added as releases.
	TagSigners []string  `yaml:"tagSigners,omitempty"`
	Releases   []Release `yaml:"releases,omitempty"`
}

// Release is one trusted commit of the builder.
type Release struct {
	Tag    string `yaml:"tag"`
	Commit string `yaml:"commit"`
	Added  string `yaml:"added,omitempty"` // date it was added, YYYY-MM-DD
}

var (
	repoRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	commitRe = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Load reads and validates a trust file. Unknown keys are an error.
func Load(p string) (*File, error) {
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decode trust file: %w", err)
	}
	return &f, f.Validate()
}

func (f *File) Validate() error {
	var errs []error
	if f.APIVersion != APIVersion {
		errs = append(errs, fmt.Errorf("apiVersion must be %q", APIVersion))
	}
	seen := map[string]bool{}
	for _, b := range f.Builders {
		if b.Key != "" || b.Name != "" {
			if b.Name == "" || b.Key == "" {
				errs = append(errs, errors.New("a key builder needs both name and key"))
			} else if _, err := signer.ParsePublicKey([]byte(b.Key)); err != nil {
				errs = append(errs, fmt.Errorf("builder %s: %w", b.Name, err))
			}
			if b.Repository != "" || len(b.Releases) > 0 || len(b.TagSigners) > 0 {
				errs = append(errs, fmt.Errorf("builder %s: a key builder has no repository, releases or tagSigners", b.Name))
			}
			if seen["key:"+b.Name] {
				errs = append(errs, fmt.Errorf("builder %s listed twice", b.Name))
			}
			seen["key:"+b.Name] = true
			continue
		}
		if !repoRe.MatchString(b.Repository) {
			errs = append(errs, fmt.Errorf("builder repository %q must be OWNER/REPO", b.Repository))
		}
		if seen[strings.ToLower(b.Repository)] {
			errs = append(errs, fmt.Errorf("builder %s listed twice", b.Repository))
		}
		seen[strings.ToLower(b.Repository)] = true
		if _, err := tagsig.Keys(b.TagSigners); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", b.Repository, err))
		}
		for _, r := range b.Releases {
			if !commitRe.MatchString(r.Commit) || r.Tag == "" {
				errs = append(errs, fmt.Errorf("%s: release %q needs a tag and a 40-hex commit", b.Repository, r.Tag))
			}
		}
	}
	seenApp := map[string]bool{}
	for _, a := range f.Apps {
		if !repoRe.MatchString(a.Repository) {
			errs = append(errs, fmt.Errorf("app repository %q must be OWNER/REPO", a.Repository))
		}
		if seenApp[strings.ToLower(a.Repository)] {
			errs = append(errs, fmt.Errorf("app %s listed twice", a.Repository))
		}
		seenApp[strings.ToLower(a.Repository)] = true
		if len(a.TagSigners) == 0 {
			errs = append(errs, fmt.Errorf("app %s: tagSigners is empty", a.Repository))
		}
		if _, err := tagsig.Keys(a.TagSigners); err != nil {
			errs = append(errs, fmt.Errorf("app %s: %w", a.Repository, err))
		}
	}
	return errors.Join(errs...)
}

// App returns the entry for a repository, matched case-insensitively.
func (f *File) App(repo string) *App {
	for i := range f.Apps {
		if strings.EqualFold(f.Apps[i].Repository, repo) {
			return &f.Apps[i]
		}
	}
	return nil
}

// Keys returns the key builders' public keys, by name.
func (f *File) Keys() map[string]*ecdsa.PublicKey {
	out := map[string]*ecdsa.PublicKey{}
	for _, b := range f.Builders {
		if b.Key == "" {
			continue
		}
		if pub, err := signer.ParsePublicKey([]byte(b.Key)); err == nil {
			out[b.Name] = pub
		}
	}
	return out
}

// Builder returns the entry for a repository, matched case-insensitively.
func (f *File) Builder(repo string) *Builder {
	for i := range f.Builders {
		if strings.EqualFold(f.Builders[i].Repository, repo) {
			return &f.Builders[i]
		}
	}
	return nil
}

// Trusted returns the release a builder commit belongs to.
func (f *File) Trusted(repo, commit string) (Release, bool) {
	if b := f.Builder(repo); b != nil {
		for _, r := range b.Releases {
			if r.Commit == commit {
				return r, true
			}
		}
	}
	return Release{}, false
}

// Append adds a release to a builder in the file at p, keeping the file's
// comments and layout.
func Append(p, repo string, rel Release) error {
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return err
	}
	builders := mapValue(doc.Content[0], "builders")
	if builders == nil {
		return errors.New("trust file has no builders")
	}
	for _, b := range builders.Content {
		if r := mapValue(b, "repository"); r == nil || !strings.EqualFold(r.Value, repo) {
			continue
		}
		releases := mapValue(b, "releases")
		if releases != nil {
			for _, r := range releases.Content {
				if c := mapValue(r, "commit"); c != nil && c.Value == rel.Commit {
					return fmt.Errorf("%s %s is already trusted", repo, rel.Commit)
				}
			}
		}
		if releases == nil || releases.Kind != yaml.SequenceNode {
			releases = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			b.Content = append(b.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "releases"}, releases)
		}
		var item yaml.Node
		if err := item.Encode(rel); err != nil {
			return err
		}
		releases.Style = 0
		releases.Content = append(releases.Content, &item)
		var out bytes.Buffer
		enc := yaml.NewEncoder(&out)
		enc.SetIndent(2)
		if err := enc.Encode(&doc); err != nil {
			return err
		}
		return os.WriteFile(p, out.Bytes(), 0o644)
	}
	return fmt.Errorf("trust file has no builder %s", repo)
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

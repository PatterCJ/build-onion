// Package gitlabci lists what a GitLab CI pipeline definition pulls in from
// outside the repository: container images and included configuration. A
// pipeline is pinned when every one of them is immutable: images by digest,
// projects and components by commit, remote files by integrity hash. Local
// includes are files at the same commit.
package gitlabci

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PatterCJ/build-onion/internal/manifest"
)

// References are recorded in these forms:
//
//	docker://IMAGE                   an image or service
//	./PATH                           a local include
//	project:PROJECT/FILE@REF         a file from another project
//	component:COMPONENT@VERSION      a CI/CD component
//	remote:URL[@sha256-BASE64]       a remote file, with its integrity hash
//	template:NAME                    a GitLab-managed template
//
// A value GitLab expands at run time (a $VARIABLE) is recorded as written.

var (
	commitRe    = regexp.MustCompile(`@[a-f0-9]{40}$`)
	integrityRe = regexp.MustCompile(`@sha256-[A-Za-z0-9+/]{43}=$`)
)

// Pinned reports whether a reference can't change.
func Pinned(ref string) bool {
	switch {
	case strings.HasPrefix(ref, "docker://"):
		return manifest.IsPinnedImage(strings.TrimPrefix(ref, "docker://"))
	case strings.HasPrefix(ref, "./"):
		return !strings.Contains(ref, "$")
	case strings.HasPrefix(ref, "project:"), strings.HasPrefix(ref, "component:"):
		return commitRe.MatchString(ref) && !strings.Contains(ref, "$")
	case strings.HasPrefix(ref, "remote:"):
		return integrityRe.MatchString(ref) && !strings.Contains(ref, "$")
	}
	return false
}

// References lists every image and include in a pipeline definition, in
// file order. Keys GitLab reserves are read for what they pull in; every
// other top-level mapping is a job (hidden ".name" jobs included, since
// jobs extend them).
func References(raw []byte) ([]string, error) {
	var out []string
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
			continue // an empty document, or the spec header's
		}
		top := doc.Content[0]
		for i := 0; i+1 < len(top.Content); i += 2 {
			key, val := top.Content[i].Value, top.Content[i+1]
			switch key {
			case "spec", "variables", "stages", "workflow", "before_script", "after_script", "cache":
			case "include":
				refs, err := includes(val)
				if err != nil {
					return nil, err
				}
				out = append(out, refs...)
			case "image":
				out = append(out, images(val)...)
			case "services":
				out = append(out, services(val)...)
			case "default":
				out = append(out, job(val)...)
			default:
				out = append(out, job(val)...)
			}
		}
	}
	return out, nil
}

func job(n *yaml.Node) []string {
	var out []string
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		val := n.Content[i+1]
		switch n.Content[i].Value {
		case "image":
			out = append(out, images(val)...)
		case "services":
			out = append(out, services(val)...)
		case "trigger":
			// A child pipeline's definition is included like configuration.
			if val.Kind == yaml.MappingNode {
				if inc := mapValue(val, "include"); inc != nil {
					refs, _ := includes(inc)
					out = append(out, refs...)
				}
			}
		}
	}
	return out
}

// images reads image: NAME or image: {name: NAME}. An !reference to another
// job's image is that job's, recorded there.
func images(n *yaml.Node) []string {
	switch {
	case n.Tag == "!reference":
		return nil
	case n.Kind == yaml.ScalarNode:
		return []string{"docker://" + n.Value}
	case n.Kind == yaml.MappingNode:
		if name := mapValue(n, "name"); name != nil && name.Kind == yaml.ScalarNode {
			return []string{"docker://" + name.Value}
		}
	}
	return nil
}

func services(n *yaml.Node) []string {
	if n.Kind != yaml.SequenceNode || n.Tag == "!reference" {
		return nil
	}
	var out []string
	for _, s := range n.Content {
		out = append(out, images(s)...)
	}
	return out
}

// includes reads include: in each of its forms: a string, a mapping, or a
// list of either.
func includes(n *yaml.Node) ([]string, error) {
	switch n.Kind {
	case yaml.ScalarNode:
		// A bare string is a local path, or a remote URL.
		if strings.HasPrefix(n.Value, "https://") || strings.HasPrefix(n.Value, "http://") {
			return []string{"remote:" + n.Value}, nil
		}
		return []string{"./" + strings.TrimPrefix(n.Value, "/")}, nil
	case yaml.SequenceNode:
		var out []string
		for _, c := range n.Content {
			refs, err := includes(c)
			if err != nil {
				return nil, err
			}
			out = append(out, refs...)
		}
		return out, nil
	case yaml.MappingNode:
		get := func(k string) string {
			if v := mapValue(n, k); v != nil && v.Kind == yaml.ScalarNode {
				return v.Value
			}
			return ""
		}
		switch {
		case get("local") != "":
			return []string{"./" + strings.TrimPrefix(get("local"), "/")}, nil
		case get("project") != "":
			ref := get("ref")
			files := []string{get("file")}
			if f := mapValue(n, "file"); f != nil && f.Kind == yaml.SequenceNode {
				files = nil
				for _, c := range f.Content {
					files = append(files, c.Value)
				}
			}
			var out []string
			for _, f := range files {
				r := "project:" + get("project") + "/" + strings.TrimPrefix(f, "/")
				if ref != "" {
					r += "@" + ref
				}
				out = append(out, r)
			}
			return out, nil
		case get("component") != "":
			return []string{"component:" + get("component")}, nil
		case get("remote") != "":
			r := "remote:" + get("remote")
			if in := get("integrity"); in != "" {
				r += "@" + in
			}
			return []string{r}, nil
		case get("template") != "":
			return []string{"template:" + get("template")}, nil
		}
		return nil, fmt.Errorf("include at line %d: not local, project, component, remote or template", n.Line)
	}
	return nil, fmt.Errorf("include at line %d: unexpected form", n.Line)
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

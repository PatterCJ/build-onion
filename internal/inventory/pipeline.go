package inventory

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Pipeline records what ran the build, not just what was built: the build-onion
// commit, every workflow and the actions it pins, and per job the runner image
// and tool versions. After an incident, "which builds ran X?" is a query over
// these records.
type Pipeline struct {
	Platform   string        `json:"platform"`
	BuildOnion BuildOnionRef `json:"buildOnion"`
	Workflows  []Workflow    `json:"workflows"`
	Jobs       []Job         `json:"jobs"`
}

type BuildOnionRef struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	CLIDigest  string `json:"cliDigest"`
}

type Workflow struct {
	Role    string   `json:"role"` // caller | build-onion
	Ref     string   `json:"ref"`  // owner/repo/path@ref
	Digest  string   `json:"digest"`
	Actions []string `json:"actions"` // every `uses:` exactly as pinned
}

type Job struct {
	Name   string `json:"name"`
	Runner string `json:"runner"` // e.g. "ubuntu24 20260921.1"
	Tools  []Tool `json:"tools,omitempty"`
}

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Record files are written by `onion record` in each job and merged by
// `onion inventory --records DIR`.
type record struct {
	Kind     string         `json:"kind"` // job | workflow | build-onion
	Job      *Job           `json:"job,omitempty"`
	Workflow *Workflow      `json:"workflow,omitempty"`
	Onion    *BuildOnionRef `json:"buildOnion,omitempty"`
}

func WriteJobRecord(p string, j Job) error {
	sort.Slice(j.Tools, func(a, b int) bool { return j.Tools[a].Name < j.Tools[b].Name })
	return writeRecord(p, record{Kind: "job", Job: &j})
}

func WriteWorkflowRecord(p string, w Workflow) error {
	return writeRecord(p, record{Kind: "workflow", Workflow: &w})
}

func WriteBuildOnionRecord(p string, b BuildOnionRef) error {
	return writeRecord(p, record{Kind: "build-onion", Onion: &b})
}

func writeRecord(p string, r record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

// ReadPipeline merges every *.json record under dir.
func ReadPipeline(dir, platform string) (Pipeline, error) {
	pl := Pipeline{Platform: platform}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return pl, err
	}
	sort.Strings(paths)
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return pl, err
		}
		var r record
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			return pl, fmt.Errorf("%s: %w", p, err)
		}
		switch {
		case r.Kind == "job" && r.Job != nil:
			pl.Jobs = append(pl.Jobs, *r.Job)
		case r.Kind == "workflow" && r.Workflow != nil:
			pl.Workflows = append(pl.Workflows, *r.Workflow)
		case r.Kind == "build-onion" && r.Onion != nil:
			if pl.BuildOnion.Commit != "" {
				return pl, fmt.Errorf("%s: second build-onion record", p)
			}
			pl.BuildOnion = *r.Onion
		default:
			return pl, fmt.Errorf("%s: unknown record kind %q", p, r.Kind)
		}
	}
	if pl.BuildOnion.Commit == "" {
		return pl, errors.New("no build-onion record: the inventory must name the builder commit")
	}
	return pl, nil
}

var usesRe = regexp.MustCompile(`^\s*-?\s*uses:\s*["']?([^"'\s#]+)`)

// WorkflowActions lists every `uses:` reference in a workflow file, in order.
func WorkflowActions(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := usesRe.FindStringSubmatch(sc.Text()); m != nil {
			out = append(out, m[1])
		}
	}
	return out, sc.Err()
}

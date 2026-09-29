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
	"time"

	"github.com/PatterCJ/build-onion/internal/digest"
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
	Scans      []Scan        `json:"scans,omitempty"`
}

// Scan records that a tool ran against this build. build-onion does not read
// or judge the tool's findings; it records what ran, at which stage, when,
// against exactly which bytes, and the digest of the report it produced, so
// the report can later be proven to belong to this build.
type Scan struct {
	Name       string `json:"name"` // the pipeline's name for this check, e.g. "sca"
	Tool       string `json:"tool"`
	Version    string `json:"version,omitempty"`
	Stage      string `json:"stage"` // pre-build | post-build
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt"`
	// Status is whether the analysis itself completed, not what it found.
	Status string `json:"status"` // completed | incomplete | failed
	// Coverage says what was not analyzed, when Status is not completed.
	Coverage string      `json:"coverage,omitempty"`
	Subject  ScanSubject `json:"subject"`
	Report   *Report     `json:"report,omitempty"`
}

// ScanSubject is what the tool examined.
type ScanSubject struct {
	Kind   string `json:"kind"`   // source (the snapshot) | artifact (an output)
	Digest string `json:"digest"` // snapshot digest or output digest
}

type Report struct {
	Digest string `json:"digest"`        // sha256 of the report as the tool wrote it
	URL    string `json:"url,omitempty"` // where the report is kept
}

const (
	StagePreBuild  = "pre-build"
	StagePostBuild = "post-build"

	ScanCompleted  = "completed"
	ScanIncomplete = "incomplete"
	ScanFailed     = "failed"
)

var scanNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Validate checks a scan record's shape. Whether it is about this build is
// checked when the inventory is generated.
func (s Scan) Validate() error {
	var errs []error
	add := func(f string, a ...any) {
		errs = append(errs, fmt.Errorf("scan %q: "+f, append([]any{s.Name}, a...)...))
	}
	if !scanNameRe.MatchString(s.Name) {
		add("name must be lowercase alphanumeric with . _ -")
	}
	if s.Tool == "" {
		add("tool is required")
	}
	if s.Stage != StagePreBuild && s.Stage != StagePostBuild {
		add("stage must be %s or %s", StagePreBuild, StagePostBuild)
	}
	switch s.Status {
	case ScanCompleted:
	case ScanIncomplete, ScanFailed:
		if s.Coverage == "" {
			add("coverage must say what was not analyzed when status is %s", s.Status)
		}
	default:
		add("status must be %s, %s or %s", ScanCompleted, ScanIncomplete, ScanFailed)
	}
	start, err1 := time.Parse(time.RFC3339, s.StartedAt)
	end, err2 := time.Parse(time.RFC3339, s.FinishedAt)
	if err1 != nil || err2 != nil {
		add("startedAt and finishedAt must be RFC 3339 times")
	} else if end.Before(start) {
		add("finishedAt is before startedAt")
	}
	switch s.Subject.Kind {
	case "source":
	case "artifact":
		if s.Stage == StagePreBuild {
			add("a pre-build scan cannot examine an artifact")
		}
	default:
		add("subject.kind must be source or artifact")
	}
	if !digest.Valid(s.Subject.Digest) {
		add("subject.digest must be sha256:<hex>")
	}
	if s.Report != nil && !digest.Valid(s.Report.Digest) {
		add("report.digest must be sha256:<hex>")
	}
	return errors.Join(errs...)
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
	Kind     string         `json:"kind"` // job | workflow | build-onion | scan
	Job      *Job           `json:"job,omitempty"`
	Workflow *Workflow      `json:"workflow,omitempty"`
	Onion    *BuildOnionRef `json:"buildOnion,omitempty"`
	Scan     *Scan          `json:"scan,omitempty"`
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

func WriteScanRecord(p string, s Scan) error {
	if err := s.Validate(); err != nil {
		return err
	}
	return writeRecord(p, record{Kind: "scan", Scan: &s})
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
		case r.Kind == "scan" && r.Scan != nil:
			if err := r.Scan.Validate(); err != nil {
				return pl, fmt.Errorf("%s: %w", p, err)
			}
			pl.Scans = append(pl.Scans, *r.Scan)
		case r.Kind == "build-onion" && r.Onion != nil:
			// Each line resolves build-onion independently; they must agree
			// on the commit, so one build is never driven by two versions.
			if pl.BuildOnion.Commit != "" && pl.BuildOnion.Commit != r.Onion.Commit {
				return pl, fmt.Errorf("%s: build-onion %s, but another line ran %s", p, r.Onion.Commit, pl.BuildOnion.Commit)
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

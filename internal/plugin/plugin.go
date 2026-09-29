// Package plugin is build-onion's extension API. A plugin is a program —
// normally a container image pinned by digest — that receives one JSON
// Request on stdin and writes one JSON Response to stdout. That is the whole
// contract, so a plugin can wrap any tool in any language (a commercial SCA
// scanner, a model-based risk scorer, a cloud policy check) without
// build-onion knowing about it. Every invocation is recorded, with the
// plugin's digest, in the build's inventory.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/manifest"
)

const APIVersion = "build-onion/plugin/v1"

// Hooks are the points in the pipeline a plugin can attach to.
const (
	HookGate = "gate" // before the build: is this commit trustworthy enough to build and release?
)

var knownHooks = map[string]bool{HookGate: true}

// Modes decide what a plugin's verdict can do.
const (
	Advisory = "advisory" // recorded in the inventory; never blocks
	Enforce  = "enforce"  // a fail (or an error) blocks the pipeline
)

// Verdicts a plugin may return. "error" is assigned by build-onion when the
// plugin crashes, times out, or answers with something unparseable.
const (
	Pass  = "pass"
	Warn  = "warn"
	Fail  = "fail"
	Error = "error"
)

// Spec is a plugin as declared in the policy file.
type Spec struct {
	Name string `yaml:"name" json:"name"`
	Hook string `yaml:"hook" json:"hook"`
	Mode string `yaml:"mode" json:"mode"`
	// Image is the plugin container, pinned by digest.
	Image string `yaml:"image" json:"image,omitempty"`
	// Command runs a local executable instead of an image. It is unpinned, so
	// it is refused unless the caller explicitly allows it (local development).
	Command []string `yaml:"command" json:"command,omitempty"`
	// Network grants the plugin network access (e.g. to call a hosted model).
	Network bool `yaml:"network" json:"network,omitempty"`
	// Secrets are environment variable names passed through to the plugin.
	Secrets []string `yaml:"secrets" json:"secrets,omitempty"`
	Timeout string   `yaml:"timeout" json:"timeout,omitempty"`
	// Config is passed to the plugin verbatim in Request.Config.
	Config map[string]any `yaml:"config" json:"config,omitempty"`
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (s *Spec) Validate() error {
	var errs []error
	add := func(f string, a ...any) {
		errs = append(errs, fmt.Errorf("plugin %q: "+f, append([]any{s.Name}, a...)...))
	}
	if !nameRe.MatchString(s.Name) {
		add("name must be lowercase alphanumeric with . _ -")
	}
	if !knownHooks[s.Hook] {
		add("unknown hook %q", s.Hook)
	}
	if s.Mode != Advisory && s.Mode != Enforce {
		add("mode must be %q or %q", Advisory, Enforce)
	}
	switch {
	case (s.Image == "") == (len(s.Command) == 0):
		add("set exactly one of image or command")
	case s.Image != "" && !manifest.IsPinnedImage(s.Image):
		add("image %q must be pinned by digest", s.Image)
	}
	for _, e := range s.Secrets {
		if !envNameRe.MatchString(e) {
			add("secret %q is not an environment variable name", e)
		}
	}
	if s.Timeout != "" {
		if _, err := time.ParseDuration(s.Timeout); err != nil {
			add("timeout: %v", err)
		}
	}
	return errors.Join(errs...)
}

// Request is what a plugin reads from stdin.
type Request struct {
	APIVersion string         `json:"apiVersion"`
	Hook       string         `json:"hook"`
	Source     Source         `json:"source"`
	Change     *Change        `json:"change,omitempty"`
	Context    Context        `json:"context"`
	Config     map[string]any `json:"config,omitempty"`
}

type Source struct {
	Repository     string `json:"repository"`
	Commit         string `json:"commit"`
	Tree           string `json:"tree"`
	SnapshotDigest string `json:"snapshotDigest"`
	// Dir is where the checkout is mounted, read-only, inside the plugin.
	Dir string `json:"dir"`
}

// Change describes what this commit changed relative to the previous build
// point, when that is known.
type Change struct {
	Base      string   `json:"base,omitempty"`
	Files     []string `json:"files"`
	Sensitive []string `json:"sensitive,omitempty"`
}

type Context struct {
	Platform string `json:"platform"` // github-actions, aws-codebuild, local, …
	Event    string `json:"event"`
	Ref      string `json:"ref"`
	Actor    string `json:"actor,omitempty"`
	RunURL   string `json:"runUrl,omitempty"`
}

// Response is what a plugin writes to stdout.
type Response struct {
	APIVersion string    `json:"apiVersion"`
	Verdict    string    `json:"verdict"`
	Score      *float64  `json:"score,omitempty"` // 0 (no risk) … 1 (maximum risk), if the plugin scores
	Summary    string    `json:"summary"`
	Findings   []Finding `json:"findings,omitempty"`
}

type Finding struct {
	ID       string `json:"id,omitempty"`
	Severity string `json:"severity"` // info | low | medium | high | critical
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// Record is what the inventory keeps about one invocation.
type Record struct {
	Name     string   `json:"name"`
	Hook     string   `json:"hook"`
	Mode     string   `json:"mode"`
	Image    string   `json:"image,omitempty"`
	Command  []string `json:"command,omitempty"`
	Verdict  string   `json:"verdict"`
	Score    *float64 `json:"score,omitempty"`
	Summary  string   `json:"summary"`
	Findings int      `json:"findings"`
	// ResultDigest is sha256 of the raw response, which is kept as a build record.
	ResultDigest string `json:"resultDigest,omitempty"`
	Blocking     bool   `json:"blocking"`
}

// Runner invokes plugins.
type Runner struct {
	Docker       string
	AllowCommand bool
	// Env supplies secret values by name; nil means the process environment.
	Env func(string) (string, bool)
	// ResultsDir, if set, receives each raw response as <name>.json.
	ResultsDir string
}

const maxResponse = 8 << 20

// Run invokes one plugin with the checkout at srcDir mounted read-only.
func (r Runner) Run(ctx context.Context, spec Spec, srcDir string, req Request) Record {
	rec := Record{Name: spec.Name, Hook: spec.Hook, Mode: spec.Mode, Image: spec.Image, Command: spec.Command}
	resp, raw, err := r.invoke(ctx, spec, srcDir, req)
	if raw != nil {
		rec.ResultDigest = digest.Bytes(raw)
		if r.ResultsDir != "" {
			os.MkdirAll(r.ResultsDir, 0o755)
			os.WriteFile(filepath.Join(r.ResultsDir, spec.Name+".json"), raw, 0o644)
		}
	}
	if err != nil {
		rec.Verdict, rec.Summary = Error, err.Error()
	} else {
		rec.Verdict, rec.Score, rec.Summary, rec.Findings = resp.Verdict, resp.Score, resp.Summary, len(resp.Findings)
	}
	rec.Blocking = spec.Mode == Enforce && (rec.Verdict == Fail || rec.Verdict == Error)
	return rec
}

func (r Runner) invoke(ctx context.Context, spec Spec, srcDir string, req Request) (*Response, []byte, error) {
	if err := spec.Validate(); err != nil {
		return nil, nil, err
	}
	if len(spec.Command) > 0 && !r.AllowCommand {
		return nil, nil, errors.New("command plugins are unpinned and not allowed here; use a pinned image")
	}
	timeout := 5 * time.Minute
	if spec.Timeout != "" {
		timeout, _ = time.ParseDuration(spec.Timeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	src, err := filepath.Abs(srcDir)
	if err != nil {
		return nil, nil, err
	}
	req.APIVersion, req.Hook, req.Config = APIVersion, spec.Hook, spec.Config
	env := r.secretEnv(spec.Secrets)

	var cmd *exec.Cmd
	if spec.Image != "" {
		req.Source.Dir = "/src"
		args := []string{"run", "--rm", "-i", "--read-only", "--tmpfs", "/tmp",
			"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
			"-v", src + ":/src:ro", "-w", "/src"}
		if !spec.Network {
			args = append(args, "--network", "none")
		}
		for _, kv := range env {
			k, _, _ := strings.Cut(kv, "=")
			args = append(args, "-e", k) // value comes from cmd.Env, never argv
		}
		docker := r.Docker
		if docker == "" {
			docker = "docker"
		}
		cmd = exec.CommandContext(ctx, docker, append(args, spec.Image)...)
		// The docker CLI needs its usual environment, but not the secret bundle.
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "ONION_SECRETS=") {
				cmd.Env = append(cmd.Env, kv)
			}
		}
		cmd.Env = append(cmd.Env, env...)
	} else {
		req.Source.Dir = src
		cmd = exec.CommandContext(ctx, spec.Command[0], spec.Command[1:]...)
		cmd.Dir = src
		cmd.Env = append(minimalEnv(), env...)
	}
	in, err := json.Marshal(req)
	if err != nil {
		return nil, nil, err
	}
	var stdout, stderr bytes.Buffer
	// A plugin's children can hold stdout open after it is killed; stop
	// waiting for them shortly after the deadline so a timeout is a timeout.
	cmd.WaitDelay = time.Second
	cmd.Stdin = bytes.NewReader(in)
	cmd.Stdout = &limitWriter{w: &stdout, n: maxResponse}
	cmd.Stderr = &limitWriter{w: &stderr, n: 64 << 10}
	runErr := cmd.Run()
	raw := stdout.Bytes()
	if ctx.Err() != nil {
		return nil, raw, fmt.Errorf("timed out after %s", timeout)
	}
	if runErr != nil {
		return nil, raw, fmt.Errorf("exited with %v: %s", runErr, lastLine(stderr.String()))
	}
	var resp Response
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		return nil, raw, fmt.Errorf("invalid response: %w", err)
	}
	if resp.APIVersion != APIVersion {
		return nil, raw, fmt.Errorf("response apiVersion %q, want %q", resp.APIVersion, APIVersion)
	}
	switch resp.Verdict {
	case Pass, Warn, Fail:
	default:
		return nil, raw, fmt.Errorf("invalid verdict %q", resp.Verdict)
	}
	if resp.Score != nil && (*resp.Score < 0 || *resp.Score > 1) {
		return nil, raw, fmt.Errorf("score %v outside [0,1]", *resp.Score)
	}
	return &resp, raw, nil
}

func (r Runner) secretEnv(names []string) []string {
	get := r.Env
	if get == nil {
		get = os.LookupEnv
	}
	sorted := append([]string{}, names...)
	sort.Strings(sorted)
	var out []string
	for _, n := range sorted {
		if v, ok := get(n); ok {
			out = append(out, n+"="+v)
		}
	}
	return out
}

// minimalEnv keeps command plugins from inheriting the pipeline's secrets.
func minimalEnv() []string {
	var out []string
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "LANG"} {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

type limitWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room < len(p) {
		if room > 0 {
			l.w.Write(p[:room])
		}
		return 0, errors.New("plugin output too large")
	}
	return l.w.Write(p)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	return s[strings.LastIndexByte(s, '\n')+1:]
}

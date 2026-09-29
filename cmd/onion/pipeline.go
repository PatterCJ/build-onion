package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PatterCJ/build-onion/internal/digest"
	"github.com/PatterCJ/build-onion/internal/gate"
	"github.com/PatterCJ/build-onion/internal/inventory"
	"github.com/PatterCJ/build-onion/internal/plugin"
	"github.com/PatterCJ/build-onion/internal/policy"
	"github.com/PatterCJ/build-onion/internal/source"
)

// onion source snapshot|verify
func cmdSource(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: onion source snapshot|verify [flags]")
	}
	switch args[0] {
	case "snapshot":
		fs := flag.NewFlagSet("source snapshot", flag.ExitOnError)
		dir := fs.String("source", ".", "clean checkout to snapshot")
		out := fs.String("out", "", "write the snapshot JSON here (required)")
		fs.Parse(args[1:])
		if *out == "" {
			return errors.New("--out is required")
		}
		snap, err := source.Take(*dir)
		if err != nil {
			return err
		}
		if err := writeJSON(*out, snap); err != nil {
			return err
		}
		fmt.Println(snap.Digest)
		return nil
	case "verify":
		fs := flag.NewFlagSet("source verify", flag.ExitOnError)
		var s sourceFlags
		s.register(fs)
		snapPath := fs.String("snapshot", "", "snapshot JSON from `onion source snapshot` (required)")
		expect := fs.String("expect", "", "require the snapshot to have this digest")
		fs.Parse(args[1:])
		m, err := s.load()
		if err != nil {
			return err
		}
		return verifySource(s.source, *snapPath, *expect, m.Writable())
	}
	return fmt.Errorf("unknown source command %q", args[0])
}

func loadSnapshot(p, expect string) (*source.Snapshot, error) {
	var snap source.Snapshot
	if err := readJSON(p, &snap); err != nil {
		return nil, err
	}
	if err := snap.Check(); err != nil {
		return nil, err
	}
	if expect != "" && snap.Digest != expect {
		return nil, fmt.Errorf("snapshot %s, expected %s", snap.Digest, expect)
	}
	return &snap, nil
}

func verifySource(dir, snapPath, expect string, allowNew []string) error {
	if snapPath == "" {
		return errors.New("--snapshot is required")
	}
	snap, err := loadSnapshot(snapPath, expect)
	if err != nil {
		return err
	}
	d, err := source.Verify(dir, snap, allowNew)
	if err != nil {
		return err
	}
	if !d.Empty() {
		return d
	}
	fmt.Fprintf(os.Stderr, "source matches snapshot %s (%d files)\n", snap.Digest, len(snap.Files))
	return nil
}

// onion gate
func cmdGate(args []string) error {
	fs := flag.NewFlagSet("gate", flag.ExitOnError)
	var s sourceFlags
	s.register(fs)
	var p gate.Params
	policyPath := fs.String("policy", "", "policy file (default: built-in policy)")
	snapPath := fs.String("snapshot", "", "source snapshot JSON (required)")
	fs.StringVar(&p.Repository, "repository", "", "source repository URL")
	fs.StringVar(&p.Base, "base", "", "previous build point to diff against")
	fs.BoolVar(&p.Fork, "fork", false, "the commit comes from a fork")
	fs.StringVar(&p.Context.Platform, "platform", "local", "CI platform name, passed to plugins")
	fs.StringVar(&p.Context.Event, "event", "", "triggering event (required)")
	fs.StringVar(&p.Context.Ref, "ref", "", "triggering ref (required)")
	fs.StringVar(&p.Context.Actor, "actor", "", "who triggered the run")
	fs.StringVar(&p.Context.RunURL, "run-url", "", "URL of this run")
	out := fs.String("out", "", "write the verdict JSON here")
	results := fs.String("results-dir", "", "keep each plugin's raw response here")
	ghOut := fs.String("github-output", "", "append releasable=true|false here")
	allowCmd := fs.Bool("allow-command-plugins", false, "allow unpinned command plugins (local development only)")
	fs.Parse(args)
	if p.Context.Event == "" || p.Context.Ref == "" || *snapPath == "" {
		return errors.New("--event, --ref and --snapshot are required")
	}
	m, err := s.load()
	if err != nil {
		return err
	}
	pol, _, err := policy.Load(*policyPath)
	if err != nil {
		return err
	}
	snap, err := loadSnapshot(*snapPath, "")
	if err != nil {
		return err
	}
	p.SourceDir, p.ManifestPath, p.PolicyPath = s.source, s.manifest, *policyPath
	runner := plugin.Runner{AllowCommand: *allowCmd, ResultsDir: *results, Env: secretLookup()}
	v, err := gate.Evaluate(context.Background(), p, pol, m, snap, runner)
	if err != nil {
		return err
	}
	if *policyPath != "" {
		raw, err := os.ReadFile(*policyPath)
		if err != nil {
			return err
		}
		v.PolicyDigest = digest.Bytes(raw)
	}
	if *out != "" {
		if err := writeJSON(*out, v); err != nil {
			return err
		}
	}
	printGate(v)
	if *ghOut != "" {
		if err := appendLines(*ghOut, fmt.Sprintf("releasable=%t", v.Releasable)); err != nil {
			return err
		}
	}
	if v.Blocked {
		return fmt.Errorf("gate blocked the build:\n  %s", strings.Join(v.BlockedBy, "\n  "))
	}
	return nil
}

// secretLookup resolves plugin secrets from ONION_SECRETS (a JSON object, as
// produced by GitHub's toJSON(secrets)) and then the process environment.
// Only names a plugin declares are ever read.
func secretLookup() func(string) (string, bool) {
	var fromJSON map[string]string
	if raw := os.Getenv("ONION_SECRETS"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &fromJSON)
	}
	return func(k string) (string, bool) {
		if v, ok := fromJSON[k]; ok {
			return v, true
		}
		if k == "ONION_SECRETS" {
			return "", false
		}
		return os.LookupEnv(k)
	}
}

func printGate(v *gate.Verdict) {
	w := os.Stderr
	fmt.Fprintf(w, "gate: releasable=%t (%s)\n", v.Releasable, v.Reason)
	if v.ChangeKnown {
		fmt.Fprintf(w, "gate: %d file(s) changed since %s\n", v.ChangedFiles, v.Base)
	} else {
		fmt.Fprintln(w, "gate: change set unknown (no base to diff against)")
	}
	for _, f := range v.SensitiveChange {
		fmt.Fprintf(w, "gate: build-sensitive change: %s\n", f)
	}
	for _, r := range v.Plugins {
		fmt.Fprintf(w, "gate: plugin %s (%s): %s — %s\n", r.Name, r.Mode, r.Verdict, r.Summary)
	}
}

// onion record job|workflow|build-onion
func cmdRecord(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: onion record job|workflow|build-onion [flags]")
	}
	fs := flag.NewFlagSet("record "+args[0], flag.ExitOnError)
	out := fs.String("out", "", "record file to write (required)")
	switch args[0] {
	case "job":
		var j inventory.Job
		fs.StringVar(&j.Name, "name", "", "job name")
		fs.StringVar(&j.Runner, "runner", "", "runner image and version")
		fs.Func("tool", "tool=version (repeatable)", func(s string) error {
			n, v, ok := strings.Cut(s, "=")
			if !ok || n == "" {
				return fmt.Errorf("want name=version, got %q", s)
			}
			j.Tools = append(j.Tools, inventory.Tool{Name: n, Version: strings.TrimSpace(v)})
			return nil
		})
		fs.Parse(args[1:])
		if *out == "" || j.Name == "" {
			return errors.New("--out and --name are required")
		}
		return inventory.WriteJobRecord(*out, j)
	case "workflow":
		var w inventory.Workflow
		file := fs.String("file", "", "workflow file to record")
		fs.StringVar(&w.Role, "role", "", "caller | build-onion")
		fs.StringVar(&w.Ref, "ref", "", "owner/repo/path@ref")
		fs.Parse(args[1:])
		if *out == "" || *file == "" {
			return errors.New("--out and --file are required")
		}
		var err error
		if w.Actions, err = inventory.WorkflowActions(*file); err != nil {
			return err
		}
		if w.Digest, err = digest.File(*file); err != nil {
			return err
		}
		return inventory.WriteWorkflowRecord(*out, w)
	case "build-onion":
		var b inventory.BuildOnionRef
		fs.StringVar(&b.Repository, "repository", "", "build-onion repository")
		fs.StringVar(&b.Commit, "commit", "", "build-onion commit")
		fs.StringVar(&b.CLIDigest, "cli-digest", "", "digest of the onion CLI binary")
		fs.Parse(args[1:])
		if *out == "" || b.Commit == "" {
			return errors.New("--out and --commit are required")
		}
		return inventory.WriteBuildOnionRecord(*out, b)
	}
	return fmt.Errorf("unknown record kind %q", args[0])
}

func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if dir := filepath.Dir(p); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(p, append(b, '\n'), 0o644)
}

func readJSON(p string, v any) error {
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func appendLines(p string, lines ...string) error {
	for _, l := range lines {
		if strings.ContainsAny(l, "\r\n") {
			return fmt.Errorf("output value contains a newline: %q", l)
		}
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, strings.Join(lines, "\n"))
	return err
}

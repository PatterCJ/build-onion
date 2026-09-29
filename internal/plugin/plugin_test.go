package plugin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// script writes an executable shell plugin and returns a command spec for it.
func script(t *testing.T, mode, body string) Spec {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plugin.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return Spec{Name: "test", Hook: HookGate, Mode: mode, Command: []string{p}, Timeout: "5s"}
}

func run(t *testing.T, spec Spec, env map[string]string) Record {
	t.Helper()
	r := Runner{AllowCommand: true, ResultsDir: t.TempDir(), Env: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}
	return r.Run(context.Background(), spec, t.TempDir(), Request{Source: Source{Commit: "abc"}})
}

func TestRoundTrip(t *testing.T) {
	// The plugin echoes back the commit and hook it was given, proving the
	// request reached it, and the secret it was granted.
	spec := script(t, Advisory, `req=$(cat)
commit=$(echo "$req" | sed -n 's/.*"commit":"\([^"]*\)".*/\1/p')
hook=$(echo "$req" | sed -n 's/.*"hook":"\([^"]*\)".*/\1/p')
printf '{"apiVersion":"build-onion/plugin/v1","verdict":"warn","score":0.7,"summary":"%s %s %s","findings":[{"severity":"medium","message":"m"}]}' "$commit" "$hook" "$RISK_KEY"
`)
	spec.Secrets = []string{"RISK_KEY"}
	rec := run(t, spec, map[string]string{"RISK_KEY": "k1", "OTHER": "leak"})
	if rec.Verdict != Warn || rec.Summary != "abc gate k1" || rec.Findings != 1 || *rec.Score != 0.7 {
		t.Fatalf("record = %+v", rec)
	}
	if rec.Blocking || rec.ResultDigest == "" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestOnlyDeclaredSecretsReachPlugin(t *testing.T) {
	t.Setenv("PIPELINE_TOKEN", "should-not-leak")
	spec := script(t, Advisory, `cat >/dev/null
printf '{"apiVersion":"build-onion/plugin/v1","verdict":"pass","summary":"[%s]"}' "$PIPELINE_TOKEN"`)
	if rec := run(t, spec, nil); rec.Summary != "[]" {
		t.Fatalf("pipeline env leaked into plugin: %q", rec.Summary)
	}
}

func TestModes(t *testing.T) {
	fail := `cat >/dev/null; echo '{"apiVersion":"build-onion/plugin/v1","verdict":"fail","summary":"risky"}'`
	crash := `cat >/dev/null; echo boom >&2; exit 3`
	cases := []struct {
		name, mode, body, verdict string
		blocking                  bool
	}{
		{"advisory fail is recorded, not blocking", Advisory, fail, Fail, false},
		{"enforce fail blocks", Enforce, fail, Fail, true},
		{"advisory crash is an error, not blocking", Advisory, crash, Error, false},
		{"enforce crash blocks (fail closed)", Enforce, crash, Error, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := run(t, script(t, tc.mode, tc.body), nil)
			if rec.Verdict != tc.verdict || rec.Blocking != tc.blocking {
				t.Fatalf("record = %+v", rec)
			}
		})
	}
}

func TestBadResponses(t *testing.T) {
	cases := map[string]string{
		"not json":      `echo nope`,
		"wrong version": `echo '{"apiVersion":"v0","verdict":"pass","summary":""}'`,
		"bad verdict":   `echo '{"apiVersion":"build-onion/plugin/v1","verdict":"maybe","summary":""}'`,
		"score range":   `echo '{"apiVersion":"build-onion/plugin/v1","verdict":"pass","score":7,"summary":""}'`,
		"unknown field": `echo '{"apiVersion":"build-onion/plugin/v1","verdict":"pass","summary":"","approved":true}'`,
		"timeout":       `sleep 10`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			spec := script(t, Enforce, "cat >/dev/null\n"+body)
			spec.Timeout = "300ms"
			if rec := run(t, spec, nil); rec.Verdict != Error || !rec.Blocking {
				t.Fatalf("record = %+v", rec)
			}
		})
	}
}

func TestCommandPluginsNeedOptIn(t *testing.T) {
	spec := script(t, Advisory, `echo '{}'`)
	rec := Runner{}.Run(context.Background(), spec, t.TempDir(), Request{})
	if rec.Verdict != Error || !strings.Contains(rec.Summary, "unpinned") {
		t.Fatalf("record = %+v", rec)
	}
}

func TestSpecValidate(t *testing.T) {
	pinned := "ghcr.io/acme/scan@sha256:" + strings.Repeat("a", 64)
	bad := []Spec{
		{Name: "x", Hook: "gate", Mode: "advisory", Image: "ghcr.io/acme/scan:latest"},
		{Name: "x", Hook: "deploy", Mode: "advisory", Image: pinned},
		{Name: "x", Hook: "gate", Mode: "maybe", Image: pinned},
		{Name: "x", Hook: "gate", Mode: "advisory"},
		{Name: "x", Hook: "gate", Mode: "advisory", Image: pinned, Secrets: []string{"A=B"}},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("case %d accepted: %+v", i, s)
		}
	}
	good := Spec{Name: "jev", Hook: "gate", Mode: "advisory", Image: pinned, Secrets: []string{"TYPESAFE_API_KEY"}, Network: true}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRequestShape(t *testing.T) {
	// Pin the wire format plugin authors code against.
	b, _ := json.Marshal(Request{APIVersion: APIVersion, Hook: HookGate, Change: &Change{Files: []string{"a"}}})
	for _, key := range []string{`"apiVersion"`, `"hook"`, `"source"`, `"change"`, `"context"`, `"snapshotDigest"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("request JSON lacks %s: %s", key, b)
		}
	}
}

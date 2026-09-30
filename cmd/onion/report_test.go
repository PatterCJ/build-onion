package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/peel"
)

func TestReportHasHeader(t *testing.T) {
	var buf bytes.Buffer
	printReport(&buf, &peel.Report{
		Artifact: "dist/onion", Digest: "sha256:abc", Verdict: peel.Passed,
		Results: []peel.Result{
			{Layer: "seal", Check: "bundles found", Status: peel.Passed, Detail: "3 bundle(s)"},
			{Layer: "seal", Check: "no invalid bundles", Status: peel.Passed},
			{Layer: "gate", Check: "release allowed", Status: peel.Passed},
		},
	})
	lines := strings.Split(buf.String(), "\n")
	if !strings.HasPrefix(lines[3], "SECTION") || !strings.Contains(lines[3], "RESULT") || !strings.HasPrefix(lines[4], "-------") {
		t.Fatalf("no header:\n%s", buf.String())
	}
	// The section name appears once, on the first row of each section.
	if strings.Count(buf.String(), "seal ") != 1 {
		t.Fatalf("section repeated:\n%s", buf.String())
	}
	t.Log("\n" + buf.String())
}

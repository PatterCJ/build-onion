package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/PatterCJ/build-onion/internal/peel"
)

// annotate raises a GitHub Actions annotation, so a block or finding shows on
// the run's summary page with what failed and why, not only in the log.
// Outside GitHub Actions it does nothing. level is error, warning or notice.
func annotate(level, title, msg string) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return
	}
	fmt.Fprintf(os.Stderr, "::%s title=%s::%s\n", level, escapeProperty(title), escapeData(msg))
}

func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

// annotateReport raises one annotation per failing peel check: findings and
// missing evidence as errors, incomplete coverage as warnings.
func annotateReport(r *peel.Report) {
	for _, res := range r.Results {
		level := ""
		switch res.Status {
		case peel.Finding, peel.Failed:
			level = "error"
		case peel.Degraded, peel.Unsupported:
			level = "warning"
		}
		if level != "" {
			annotate(level, fmt.Sprintf("onion peel %s: %s %s/%s", r.Artifact, res.Status, res.Layer, res.Check), res.Detail)
		}
	}
}

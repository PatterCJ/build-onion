package lint

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// build-onion's own workflows pipe onion's output (onion peel | tee). Without
// shell: bash, GitHub runs steps without pipefail and a failing onion
// command in a pipe leaves the step green.
func TestOwnWorkflowsFailOnPipeErrors(t *testing.T) {
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var wf struct {
			Defaults struct {
				Run struct {
					Shell string `yaml:"shell"`
				} `yaml:"run"`
			} `yaml:"defaults"`
		}
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if wf.Defaults.Run.Shell != "bash" {
			t.Errorf("%s: set defaults.run.shell: bash so a failing command in a pipe fails its step", filepath.Base(f))
		}
	}
}

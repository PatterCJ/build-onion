package builder

import (
	"os"
	"strings"
	"testing"

	"github.com/PatterCJ/build-onion/internal/manifest"
)

// The policy's setting wins over the manifest's, whatever its spelling.
func TestFetchEnvNoInstallScripts(t *testing.T) {
	m := &manifest.Manifest{Dependencies: manifest.Dependencies{Env: map[string]string{"NPM_CONFIG_IGNORE_SCRIPTS": "false", "GOFLAGS": "-mod=mod"}}}
	env := Runner{NoInstallScripts: true}.fetchEnv(m)
	if env["npm_config_ignore_scripts"] != "true" || len(env) != 2 || env["GOFLAGS"] != "-mod=mod" {
		t.Errorf("env = %v", env)
	}
	if env := (Runner{}).fetchEnv(m); env["NPM_CONFIG_IGNORE_SCRIPTS"] != "false" || len(env) != 2 {
		t.Errorf("without the policy, the manifest's env is kept: %v", env)
	}
}

func TestRequireStatic(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	// /bin/sh is dynamically linked on every distribution this runs on.
	if err := requireStatic("/bin/sh"); err == nil || !strings.Contains(err.Error(), "CGO_ENABLED=0") {
		t.Errorf("dynamic binary accepted: %v", err)
	}
	if err := requireStatic("fetchenv_test.go"); err != nil {
		t.Errorf("non-ELF file: %v", err)
	}
}

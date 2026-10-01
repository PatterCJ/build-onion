package builder

import (
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

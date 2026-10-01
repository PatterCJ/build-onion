package signer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// GitLabBuildType is the SLSA build type of provenance for a GitLab CI
// pipeline, as GitLabProvenance writes it.
const GitLabBuildType = "https://github.com/PatterCJ/build-onion/buildtypes/gitlab-ci/v1"

// GitLabProvenance describes the running GitLab CI pipeline as SLSA v1
// provenance, from GitLab's predefined variables. The run is the pipeline:
// every phase of a single-pipeline build is a job in it, and its URL is
// what the phase records and the inventory name.
func GitLabProvenance(env func(string) string) ([]byte, error) {
	need := []string{"CI_SERVER_URL", "CI_PROJECT_URL", "CI_PROJECT_PATH", "CI_PROJECT_ID", "CI_COMMIT_SHA",
		"CI_PIPELINE_URL", "CI_PIPELINE_SOURCE", "CI_CONFIG_PATH", "CI_JOB_URL", "CI_RUNNER_ID"}
	var missing []string
	for _, k := range need {
		if env(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("not in a GitLab CI job: %s unset", strings.Join(missing, ", "))
	}
	var ref string
	switch {
	case env("CI_COMMIT_TAG") != "":
		ref = "refs/tags/" + env("CI_COMMIT_TAG")
	case env("CI_COMMIT_BRANCH") != "":
		ref = "refs/heads/" + env("CI_COMMIT_BRANCH")
	case env("CI_MERGE_REQUEST_REF_PATH") != "":
		ref = env("CI_MERGE_REQUEST_REF_PATH")
	default:
		return nil, errors.New("GitLab CI job with no tag, branch or merge request ref")
	}
	repoURL := env("CI_PROJECT_URL")
	type m = map[string]any
	return json.Marshal(m{
		"buildDefinition": m{
			"buildType": GitLabBuildType,
			"externalParameters": m{
				// CI_CONFIG_PATH is "file@group/project" when the pipeline
				// definition lives in another project.
				"workflow": m{"ref": ref, "repository": repoURL, "path": env("CI_CONFIG_PATH")},
			},
			"internalParameters": m{
				"gitlab": m{
					"pipeline_source":    env("CI_PIPELINE_SOURCE"),
					"project_id":         env("CI_PROJECT_ID"),
					"ref_protected":      env("CI_COMMIT_REF_PROTECTED"),
					"job_url":            env("CI_JOB_URL"),
					"runner_id":          env("CI_RUNNER_ID"),
					"runner_description": env("CI_RUNNER_DESCRIPTION"),
					"runner_tags":        env("CI_RUNNER_TAGS"),
				},
			},
			"resolvedDependencies": []m{{
				"uri":    "git+" + repoURL + "@" + ref,
				"digest": m{"gitCommit": env("CI_COMMIT_SHA")},
			}},
		},
		"runDetails": m{
			"builder":  m{"id": env("CI_SERVER_URL") + "/" + env("CI_PROJECT_PATH") + "/-/runners/" + env("CI_RUNNER_ID")},
			"metadata": m{"invocationId": env("CI_PIPELINE_URL")},
		},
	})
}

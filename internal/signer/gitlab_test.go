package signer

import (
	"encoding/json"
	"strings"
	"testing"
)

func gitlabEnv(extra map[string]string) func(string) string {
	vars := map[string]string{
		"CI_SERVER_URL":           "https://gitlab.com",
		"CI_PROJECT_URL":          "https://gitlab.com/PatterCJ/onion",
		"CI_PROJECT_PATH":         "PatterCJ/onion",
		"CI_PROJECT_ID":           "77",
		"CI_COMMIT_SHA":           strings.Repeat("a", 40),
		"CI_COMMIT_TAG":           "v1.0.0",
		"CI_COMMIT_REF_PROTECTED": "true",
		"CI_PIPELINE_URL":         "https://gitlab.com/PatterCJ/onion/-/pipelines/9",
		"CI_PIPELINE_SOURCE":      "push",
		"CI_CONFIG_PATH":          ".gitlab-ci.yml",
		"CI_JOB_URL":              "https://gitlab.com/PatterCJ/onion/-/jobs/42",
		"CI_RUNNER_ID":            "12270807",
		"CI_RUNNER_DESCRIPTION":   "green-1.saas-linux-small-amd64.runners-manager.gitlab.com/default",
	}
	for k, v := range extra {
		vars[k] = v
	}
	return func(k string) string { return vars[k] }
}

func TestGitLabProvenance(t *testing.T) {
	raw, err := GitLabProvenance(gitlabEnv(nil))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		BuildDefinition struct {
			BuildType          string
			ExternalParameters struct {
				Workflow struct{ Ref, Repository, Path string }
			}
			InternalParameters struct {
				GitLab map[string]string `json:"gitlab"`
			}
			ResolvedDependencies []struct {
				URI    string
				Digest map[string]string
			}
		}
		RunDetails struct {
			Builder  struct{ ID string }
			Metadata struct{ InvocationID string }
		}
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	bd := p.BuildDefinition
	for _, c := range [][2]string{
		{bd.BuildType, GitLabBuildType},
		{bd.ExternalParameters.Workflow.Ref, "refs/tags/v1.0.0"},
		{bd.ExternalParameters.Workflow.Repository, "https://gitlab.com/PatterCJ/onion"},
		{bd.ExternalParameters.Workflow.Path, ".gitlab-ci.yml"},
		{bd.InternalParameters.GitLab["ref_protected"], "true"},
		{bd.ResolvedDependencies[0].URI, "git+https://gitlab.com/PatterCJ/onion@refs/tags/v1.0.0"},
		{bd.ResolvedDependencies[0].Digest["gitCommit"], strings.Repeat("a", 40)},
		{p.RunDetails.Builder.ID, "https://gitlab.com/PatterCJ/onion/-/runners/12270807"},
		{p.RunDetails.Metadata.InvocationID, "https://gitlab.com/PatterCJ/onion/-/pipelines/9"},
	} {
		if c[0] != c[1] {
			t.Errorf("got %q, want %q", c[0], c[1])
		}
	}

	// A branch pipeline names the branch.
	raw, _ = GitLabProvenance(gitlabEnv(map[string]string{"CI_COMMIT_TAG": "", "CI_COMMIT_BRANCH": "main"}))
	if !strings.Contains(string(raw), `"ref":"refs/heads/main"`) {
		t.Errorf("branch pipeline: %s", raw)
	}
	// Outside GitLab, or with no ref, there's nothing to describe.
	if _, err := GitLabProvenance(gitlabEnv(map[string]string{"CI_PIPELINE_URL": ""})); err == nil || !strings.Contains(err.Error(), "CI_PIPELINE_URL") {
		t.Errorf("missing variable: %v", err)
	}
	if _, err := GitLabProvenance(gitlabEnv(map[string]string{"CI_COMMIT_TAG": ""})); err == nil {
		t.Error("no ref accepted")
	}
}

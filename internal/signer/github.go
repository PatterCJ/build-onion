package signer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// GitHubToken fetches the job's OIDC token with audience "sigstore". The job
// needs `id-token: write`.
func GitHubToken(ctx context.Context) (string, error) {
	reqURL, reqToken := getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL == "" || reqToken == "" {
		return "", errors.New("no GitHub Actions OIDC token available (the job needs `permissions: id-token: write`)")
	}
	u, err := url.Parse(reqURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("audience", "sigstore")
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+reqToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC token request: %s", resp.Status)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Value == "" {
		return "", errors.New("OIDC token response has no token")
	}
	return out.Value, nil
}

// EnvToken returns a token another CI put in an environment variable (for
// example GitLab's id_tokens or Buildkite's OIDC plugin).
func EnvToken(name string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) {
		if t := getenv(name); t != "" {
			return t, nil
		}
		return "", fmt.Errorf("$%s is empty", name)
	}
}

// Claims reads a JWT's claims without verifying it. Fulcio verifies the
// token; the claims are only used to describe the run, and peel checks that
// description against the certificate Fulcio issued.
func Claims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("JWT claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("JWT claims: %w", err)
	}
	return claims, nil
}

// GitHubProvenance is the SLSA v1 predicate for the current GitHub Actions
// job, with the same build type and fields as GitHub's own provenance:
// the calling workflow, the commit and ref, and the reusable workflow that
// built it (from the job's OIDC claims).
func GitHubProvenance(env func(string) string, claims map[string]any) ([]byte, error) {
	need := []string{"GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_REF", "GITHUB_SHA", "GITHUB_WORKFLOW_REF",
		"GITHUB_EVENT_NAME", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_REPOSITORY_ID", "GITHUB_REPOSITORY_OWNER_ID", "RUNNER_ENVIRONMENT"}
	var missing []string
	for _, k := range need {
		if env(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("not in a GitHub Actions job: %s unset", strings.Join(missing, ", "))
	}
	jobWorkflowRef, _ := claims["job_workflow_ref"].(string)
	if jobWorkflowRef == "" {
		return nil, errors.New("OIDC token has no job_workflow_ref claim")
	}
	server, repo := env("GITHUB_SERVER_URL"), env("GITHUB_REPOSITORY")
	repoURL := server + "/" + repo
	// GITHUB_WORKFLOW_REF is owner/repo/.github/workflows/file.yml@ref.
	workflowPath := strings.TrimPrefix(strings.SplitN(env("GITHUB_WORKFLOW_REF"), "@", 2)[0], repo+"/")
	type m = map[string]any
	return json.Marshal(m{
		"buildDefinition": m{
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"externalParameters": m{
				"workflow": m{"ref": env("GITHUB_REF"), "repository": repoURL, "path": workflowPath},
			},
			"internalParameters": m{
				"github": m{
					"event_name":          env("GITHUB_EVENT_NAME"),
					"repository_id":       env("GITHUB_REPOSITORY_ID"),
					"repository_owner_id": env("GITHUB_REPOSITORY_OWNER_ID"),
					"runner_environment":  env("RUNNER_ENVIRONMENT"),
				},
			},
			"resolvedDependencies": []m{{
				"uri":    "git+" + repoURL + "@" + env("GITHUB_REF"),
				"digest": m{"gitCommit": env("GITHUB_SHA")},
			}},
		},
		"runDetails": m{
			"builder":  m{"id": server + "/" + jobWorkflowRef},
			"metadata": m{"invocationId": fmt.Sprintf("%s/actions/runs/%s/attempts/%s", repoURL, env("GITHUB_RUN_ID"), env("GITHUB_RUN_ATTEMPT"))},
		},
	})
}

var getenv = os.Getenv

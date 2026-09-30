package gate

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"github.com/PatterCJ/build-onion/internal/codeowners"
	"github.com/PatterCJ/build-onion/internal/manifest"
	"github.com/PatterCJ/build-onion/internal/policy"
)

// RepoCheck records the repository protections the gate verified. It is
// present only when the policy requires some.
type RepoCheck struct {
	// Branch is the branch whose rules were read: the pushed branch, or the
	// default branch for a tag or pull request.
	Branch          string   `json:"branch"`
	Rules           []string `json:"rules,omitempty"` // active rule types
	Approvals       int      `json:"approvals"`
	CodeOwnerReview bool     `json:"codeOwnerReview"`
	CodeOwnersFile  string   `json:"codeOwnersFile,omitempty"`
	OwnedSensitive  int      `json:"ownedSensitive"`
	Unowned         []string `json:"unowned,omitempty"`
	TagOnDefault    *bool    `json:"tagOnDefault,omitempty"`
	Problems        []string `json:"problems,omitempty"`
}

// branchRule is one entry of GitHub's "rules for a branch" response.
type branchRule struct {
	Type       string `json:"type"`
	Parameters struct {
		RequiredApprovals int  `json:"required_approving_review_count"`
		CodeOwnerReview   bool `json:"require_code_owner_review"`
	} `json:"parameters"`
}

// checkRepository verifies the policy's repository requirements from facts
// readable without admin rights: the branch's active rules (supplied by the
// caller), CODEOWNERS in the checkout, and git history.
func checkRepository(p Params, pol *policy.Policy, m *manifest.Manifest) *RepoCheck {
	req := pol.Repository
	if !req.Any() {
		return nil
	}
	rc := &RepoCheck{Branch: strings.TrimPrefix(p.Context.Ref, "refs/heads/")}
	problem := func(f string, a ...any) { rc.Problems = append(rc.Problems, fmt.Sprintf(f, a...)) }
	isTag := strings.HasPrefix(p.Context.Ref, "refs/tags/")
	if !strings.HasPrefix(p.Context.Ref, "refs/heads/") {
		// Tags and pull request refs are held to the default branch's rules.
		rc.Branch = p.DefaultBranch
	}

	if req.NeedsRules() {
		if p.BranchRules == nil {
			problem("branch rules for %q were not provided", rc.Branch)
		} else {
			var rules []branchRule
			if err := json.Unmarshal(p.BranchRules, &rules); err != nil {
				problem("branch rules unreadable: %v", err)
			}
			seen := map[string]bool{}
			for _, r := range rules {
				if !seen[r.Type] {
					seen[r.Type] = true
					rc.Rules = append(rc.Rules, r.Type)
				}
				if r.Type == "pull_request" {
					rc.Approvals = max(rc.Approvals, r.Parameters.RequiredApprovals)
					rc.CodeOwnerReview = rc.CodeOwnerReview || r.Parameters.CodeOwnerReview
				}
			}
			sort.Strings(rc.Rules)
			if req.RequirePullRequest && !seen["pull_request"] {
				problem("%s doesn't require pull requests", rc.Branch)
			}
			if rc.Approvals < req.MinApprovals {
				problem("%s requires %d approval(s); policy requires %d", rc.Branch, rc.Approvals, req.MinApprovals)
			}
			if req.RequireCodeOwnerReview && !rc.CodeOwnerReview {
				problem("%s doesn't require code-owner review", rc.Branch)
			}
			if req.BlockForcePush && !seen["non_fast_forward"] {
				problem("%s allows force pushes", rc.Branch)
			}
		}
	}

	if req.RequireCodeOwners {
		co, err := codeowners.Load(p.SourceDir)
		switch {
		case err != nil:
			problem("CODEOWNERS: %v", err)
		case co == nil:
			problem("no CODEOWNERS file (looked in %s)", strings.Join(codeowners.Locations, ", "))
		default:
			rc.CodeOwnersFile = co.Path
			files, err := trackedFiles(p.SourceDir)
			if err != nil {
				problem("list tracked files: %v", err)
				break
			}
			patterns := SensitivePatterns(pol, m, p.ManifestPath, p.PolicyPath)
			var sensitive []string
			for _, f := range files {
				if matchAny(patterns, f) {
					sensitive = append(sensitive, f)
				}
			}
			rc.Unowned = co.Unowned(sensitive)
			rc.OwnedSensitive = len(sensitive) - len(rc.Unowned)
			if len(rc.Unowned) > 0 {
				problem("%d build-configuration file(s) have no code owner: %s", len(rc.Unowned), strings.Join(rc.Unowned, ", "))
			}
		}
	}

	if req.TagsFromDefaultBranch && isTag {
		on := false
		if p.DefaultBranch == "" {
			problem("default branch not provided")
		} else {
			on = exec.Command("git", "-C", p.SourceDir, "merge-base", "--is-ancestor", "HEAD", "refs/remotes/origin/"+p.DefaultBranch).Run() == nil
			if !on {
				problem("tagged commit is not on %s", p.DefaultBranch)
			}
		}
		rc.TagOnDefault = &on
	}
	return rc
}

func trackedFiles(dir string) ([]string, error) {
	out, err := exec.Command("git", "-C", dir, "ls-files", "-z").Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}

# Policy

The **manifest** (`build-onion.yml`) belongs to the repository and describes *what* to build. The **policy** belongs to whoever owns the build platform and describes *what is allowed*: which builds may become releases, which changes are recorded as build-configuration changes, and what blocks a build.

```yaml
apiVersion: build-onion/policy/v1

release:
  # Only builds of these refs, triggered by these events, are ever sealed.
  # Everything else (pull requests, feature branches, forks) still builds and
  # is checked, but is never signed or published.
  refs: [refs/heads/main, refs/tags/v*]          # default
  events: [push, workflow_dispatch, release]     # default

# Build-configuration files, recorded when they change. Always included:
# .github/**, CODEOWNERS, the manifest, this policy, the lockfiles, the
# Dockerfile, and the manifest's build.sensitive.
sensitivePaths:
  - scripts/release/**
# Named sets of common build-system files: autotools, bazel, cmake, docker,
# go, gradle, make, maven, meson, node, python, rust.
sensitivePresets: [make, python]

# Refuse to build a manifest that doesn't declare build.inputs.
requireBuildInputs: true
# Refuse to build a change that adds or modifies a binary file (by content)
# the build can read.
blockOpaqueInputs: true
```

With no policy file, the defaults above apply.

## Refused outright

`pull_request_target` and `workflow_run` run with the target repository's privileges and are the usual way fork code reaches release credentials. build-onion refuses to run under them at all, and a policy can't list them as release events.

## Making policy mandatory across an organization

A per-repo policy file can be changed in a pull request. That change shows up as a build-sensitive change, and PR builds are never sealed anyway, but a platform team usually wants one policy it controls. Wrap the reusable workflow in your own:

```yaml
# acme/platform/.github/workflows/secure-build.yml
on:
  workflow_call:
jobs:
  build:
    permissions: { contents: read, id-token: write }
    uses: PatterCJ/build-onion/.github/workflows/onion-build.yml@<sha>
    with:
      policy: .build-onion/policy.yml     # checked in by your org's repo template
  verify:
    needs: build
    permissions: { contents: read, id-token: write, attestations: write }
    uses: PatterCJ/build-onion/.github/workflows/onion-verify.yml@<sha>
    with:
      snapshot: ${{ needs.build.outputs.snapshot }}
      releasable: ${{ needs.build.outputs.releasable }}
      policy: .build-onion/policy.yml     # the security line re-runs the gate itself
      runs-on: acme-isolated-verifiers   # separate infrastructure for the rebuild
```

Then have repositories call `acme/platform/.github/workflows/secure-build.yml@<sha>`, and require that workflow with a repository ruleset. When verifying, pin the signer to your wrapper's build-onion ref with `onion peel --signer-ref`.

## Repository requirements

The gate can refuse to build unless the repository is protected. It reads the release branch's active rules and your `CODEOWNERS` file with the workflow's read-only token; no admin access is needed.

```yaml
repository:
  requirePullRequest: true      # the branch's rules require pull requests
  minApprovals: 1               # at least this many approvals
  requireCodeOwnerReview: true  # code owners must approve
  blockForcePush: true          # force pushes are blocked
  requireCodeOwners: true       # CODEOWNERS names an owner for every build-configuration file
  tagsFromDefaultBranch: true   # a tag release must point at a commit on the default branch
```

Branch requirements are read from [rulesets](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets); classic branch protection settings need admin access to read, so they aren't used. For tag releases, the default branch's rules are checked. The verified protections are recorded in the signed inventory, and `peel` lists them in its gate section.

On a repository with a single maintainer, GitHub won't let you approve your own pull request, so leave `minApprovals` at 0 and `requireCodeOwnerReview` off. `requirePullRequest`, `blockForcePush`, `requireCodeOwners` and `tagsFromDefaultBranch` still apply.

## Repository settings

build-onion reads what it needs with the workflow's read-only token. Monitor your repository's configuration (branch rules, token defaults, required reviews) separately, on a schedule and outside the build, with [OpenSSF Scorecard](https://github.com/ossf/scorecard-action) or [OpenSSF Allstar](https://github.com/ossf/allstar). Both are free.

## Where it's recorded

The gate's verdict goes into the signed inventory: releasable or not and why, the diff base, the build-configuration files changed, binary files changed (and which of them the build can read), and the sha256 of the policy file. `onion peel` fails if the gate didn't allow a release, and shows the changes as notes.

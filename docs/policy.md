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
# .github/**, .gitlab-ci.yml, .gitlab/**, CODEOWNERS, the manifest, this policy, the lockfiles, the
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
# Turn off npm dependency install scripts during fetch, and refuse a fetch
# command that turns them back on.
blockInstallScripts: true
```

Save it as `.build-onion/policy.yml` and both the build and security lines apply it, whether or not the workflows name it (the `policy` input points elsewhere). With no policy file, the defaults above apply.

## Dependency install scripts

npm packages can run code when they are installed (`preinstall`, `install`, `postinstall`). That code runs during fetch, on both the build line and the security line alike, so the independent rebuild can't catch it. The inventory records which locked packages have install scripts (from `package-lock.json`), and `peel` lists them.

With `blockInstallScripts: true`, onion runs the fetch step with `npm_config_ignore_scripts=true`, so no npm invocation in it runs dependency scripts, including `npm rebuild`, and the gate refuses a fetch command that explicitly turns them back on: npm lets a command-line flag override that setting. A fetch step that calls one of the repository's own scripts, which then re-enables them, is the repository's code: list such scripts in `build.sensitive` so changes to them are flagged for review.

## Report mode: adopt first, enforce later

```yaml
mode: report      # default: enforce
```

In report mode nothing the policy adds blocks a build; it is recorded instead, so a team can turn build-onion on and see its gaps before enforcing it:

- The gate records what it would have blocked (`wouldBlock` in the verdict) and raises a warning annotation for each.
- The fetch step always runs behind the egress proxy, which **records** connections outside `dependencies.egress` instead of denying them, including hosts on private addresses and IP-address targets, so turning report mode on never breaks a fetch that worked before. It prints an allow-list covering everything fetch reached (with `private: true` where a host was reached at a private address), ready to paste into the manifest. Loopback, link-local and cloud metadata addresses are refused in every mode.
- Builds are sealed as usual, with the mode in the inventory, and `peel` grades everything that would have been blocked or denied as a FINDING, so a deploy gate still refuses it.

`pull_request_target` and `workflow_run` are refused in every mode.

A repository can put its own policy in report mode. That moves enforcement to `onion peel`, which still grades every would-be block as a finding: rely on the deploy gate, and keep the policy in a platform-owned wrapper (below) where a repository mustn't relax it.

## Signed release tags

```yaml
release:
  refs: [refs/tags/v*]
  tagSigners:
    - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… release key
```

With `tagSigners`, a tag release builds only if its tag is signed by one of these keys (`git tag -s` with `gpg.format=ssh`) and points at the commit being built. An unsigned tag, or one signed by any other key, is blocked, so a stolen token can push a tag but can't release it. Keep the signing key off CI, ideally on a hardware key (`ssh-keygen -t ed25519-sk`). The signer is recorded in the inventory and shown by `peel`.

A policy file in the repository can be changed by a merged pull request, so for the strongest guarantee keep `tagSigners` in a policy your platform team controls (see below), or check tag signatures in the deploy gate's trust file ([Adopting](adopting.md#6-trust-build-onion-releases-not-commits)).

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

Branch requirements are read from [rulesets](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets); classic branch protection settings need admin access to read, so they aren't used. For tag releases and pull request builds, the default branch's rules are checked. The verified protections are recorded in the signed inventory, and `peel` lists them in its gate section.

On a repository with a single maintainer, GitHub won't let you approve your own pull request, so leave `minApprovals` at 0 and `requireCodeOwnerReview` off. `requirePullRequest`, `blockForcePush`, `requireCodeOwners` and `tagsFromDefaultBranch` still apply.

## Repository settings

build-onion reads what it needs with the workflow's read-only token. Monitor your repository's configuration (branch rules, token defaults, required reviews) separately, on a schedule and outside the build, with [OpenSSF Scorecard](https://github.com/ossf/scorecard-action) or [OpenSSF Allstar](https://github.com/ossf/allstar). Both are free.

## Where it's recorded

The gate's verdict goes into the signed inventory: releasable or not and why, the diff base, the build-configuration files changed, binary files changed (and which of them the build can read), and the sha256 of the policy file. `onion peel` fails if the gate didn't allow a release, and shows the changes as notes.

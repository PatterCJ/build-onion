# Policy

The **manifest** (`build-onion.yml`) belongs to the repository and describes *what* to build. The **policy** belongs to whoever owns the build platform and describes *what is allowed*: which builds may become releases, which changes deserve scrutiny, and which [plugins](plugins.md) run.

```yaml
apiVersion: build-onion/policy/v1

release:
  # Only builds of these refs, triggered by these events, are ever sealed.
  # Everything else (pull requests, feature branches, forks) still builds and
  # is checked, but is never signed or published.
  refs: [refs/heads/main, refs/tags/v*]          # default
  events: [push, workflow_dispatch, release]     # default

# Added to the built-in list: .github/**, the manifest, the lockfiles, the
# Dockerfile, and this policy file.
sensitivePaths:
  - scripts/release/**
  - Makefile

plugins:
  - name: commit-risk
    hook: gate
    mode: advisory
    image: ghcr.io/acme/commit-risk@sha256:…
    network: true
    secrets: [RISK_API_KEY]
```

With no policy file, the defaults above apply with no plugins.

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
    permissions: { contents: read, id-token: write, attestations: write, packages: write }
    uses: PatterCJ/build-onion/.github/workflows/onion-build.yml@<sha>
    with:
      policy: .build-onion/policy.yml     # checked in by your org's repo template
    secrets: inherit
```

Then have repositories call `acme/platform/.github/workflows/secure-build.yml@<sha>`, and require that workflow with a repository ruleset. When verifying, pin the signer to your wrapper's build-onion ref with `onion peel --signer-ref`.

## Where it's recorded

The gate's verdict goes into the signed inventory: releasable or not and why, the diff base, the build-sensitive files changed, every plugin result, and the sha256 of the policy file. `onion peel` fails if the gate didn't allow a release. Sensitive changes and non-passing advisory plugins show up as warnings.

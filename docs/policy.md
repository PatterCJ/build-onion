# Policy

The **manifest** (`build-onion.yml`) belongs to the repository and describes *what* to build. The **policy** belongs to whoever owns the build platform and describes *what is allowed*: which builds may become releases, and which changes count as build-sensitive.

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

# Refuse to build a manifest that doesn't declare build.inputs.
requireBuildInputs: true
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

## Where it's recorded

The gate's verdict goes into the signed inventory: releasable or not and why, the diff base, the build-sensitive files changed, and the sha256 of the policy file. `onion peel` fails if the gate didn't allow a release, and shows sensitive changes as notes.

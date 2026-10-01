# Reference

Every option build-onion reads, in one place:

- [`build-onion.yml`](#build-onionyml): the manifest
- [Policy file](#policy-file)
- [Trust file](#trust-file): the build-onion releases a verifier accepts
- [Reusable workflows](#reusable-workflows): inputs, outputs, permissions
- [`onion` CLI](#onion-cli): every command and flag

[Adopting](adopting.md) walks through setting these up; this page lists them.

## `build-onion.yml`

The manifest sits at the repository root (or wherever the workflows' `manifest` input points). Unknown keys are an error.

### Complete example

```yaml
apiVersion: build-onion/v1              # required, exactly this
name: widget                            # required

builder:
  # Every fetch and build step runs in this image. Pinned by digest.
  image: docker.io/library/golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195

dependencies:
  lockfiles: [go.sum]                   # required, at least one
  fetch: go mod download && go mod verify
  cache: /go/pkg/mod                    # required with fetch
  env:                                  # fetch step only
    GOFLAGS: -mod=readonly
  egress:                               # the only hosts fetch may reach
    - host: proxy.golang.org
    - host: storage.googleapis.com
    - host: artifacts.internal.acme.com
      port: 8443
      private: true

build:
  run: go build -trimpath -o dist/widget ./cmd/widget   # required; runs with no network
  env:                                  # build step only
    CGO_ENABLED: "0"
  inputs:                               # the only tracked files fetch and build can read
    - go.mod
    - cmd/**/*.go
    - internal/**/*.go
  scratch: [build]                      # extra paths the build may create
  sensitive: [Makefile, scripts/**]     # your own build scripts, flagged when changed

outputs:                                # at least one file or an image
  files: [dist/widget]
  image:
    name: ghcr.io/acme/widget
    dockerfile: Dockerfile
    context: .
```

### Fields

| Field | Required | Meaning and rules |
|---|---|---|
| `apiVersion` | yes | `build-onion/v1`. |
| `name` | yes | Lowercase letters, digits, `.`, `_`, `-`; starts with a letter or digit. |
| `builder.image` | yes | Container image for fetch and build, pinned by digest: `registry/name[:tag]@sha256:<64 hex>`. |
| `dependencies.lockfiles` | yes | Paths to lockfiles, relative to the repository root. Each is hashed into the inventory. `go.sum`, `package-lock.json`, `npm-shrinkwrap.json`, `requirements*.txt`, `uv.lock`, `poetry.lock` and `Cargo.lock` are also parsed: their packages are checked against the artifact and against the public registries. Other lockfiles are hashed only. |
| `dependencies.fetch` | no | Shell command run in the builder, with network, to download dependencies into `cache`. Omit it if the build needs nothing fetched. |
| `dependencies.cache` | with `fetch` | Absolute path inside the builder that `fetch` fills and `build` reads (read-only). |
| `dependencies.env` | no | Environment for `fetch` only. `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and `ALL_PROXY` are set by build-onion and can't be overridden. |
| `dependencies.egress` | no | Hosts `fetch` may reach. When set, the only route out is a filtering proxy, and any other connection fails the fetch. When empty, `fetch` has unrestricted network and `peel` grades it DEGRADED. Requires `fetch`. |
| `dependencies.egress[].host` | yes | Lowercase DNS name, or `*.example.com` for any subdomain. No IP addresses, schemes or ports. |
| `dependencies.egress[].port` | no | Port, default 443. |
| `dependencies.egress[].private` | no | Allow the host to resolve to a private address (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7), such as an internal artifact store. Loopback, link-local and cloud metadata addresses are always blocked. |
| `build.run` | yes | Shell command run in the builder with no network, reading the staged inputs and the fetched cache. |
| `build.env` | no | Environment for `build` only. |
| `build.inputs` | no | Globs (`*`, `?`, `**` across directories) naming the tracked files fetch and build can read. The manifest, lockfiles and Dockerfile are always included. A pattern that matches nothing fails the build. Empty means every tracked file, which `peel` notes. |
| `build.scratch` | no | Paths besides the outputs that fetch or build may create (`node_modules`, `build`; no trailing slash). Any other new file fails the build. |
| `build.sensitive` | no | Globs naming your own build scripts (`Makefile`, `scripts/**`, `*.m4`, `build.rs`). The gate records changes to them. Each must match at least one tracked file. |
| `outputs.files` | one of | Files `build.run` produces, relative to the repository root. Basenames must be unique: they name the signed subjects. |
| `outputs.image` | one of | An OCI image built from the outputs after the build. |
| `outputs.image.name` | with `image` | Registry repository, no tag or digest: `ghcr.io/acme/widget`. |
| `outputs.image.dockerfile` | with `image` | Dockerfile path. Every `FROM` must be pinned by digest. `RUN` steps have no network. |
| `outputs.image.context` | no | Build context, default `.`. |

All paths are relative to the repository root and may contain only letters, digits and `.`, `_`, `+`, `/`, `-`.

## Policy file

Optional. Put it at `.build-onion/policy.yml` and both lines use it automatically; the workflows' `policy` input names another path. Without a policy file, the defaults below apply. Unknown keys are an error. [Policy](policy.md) explains when to use each option.

```yaml
apiVersion: build-onion/policy/v1

release:
  refs: [refs/heads/main, refs/tags/v*]          # default
  events: [push, workflow_dispatch, release]     # default

sensitivePaths: [scripts/release/**]
sensitivePresets: [make, python]
requireBuildInputs: true
blockOpaqueInputs: true

repository:
  requirePullRequest: true
  minApprovals: 1
  requireCodeOwnerReview: true
  blockForcePush: true
  requireCodeOwners: true
  tagsFromDefaultBranch: true
```

| Field | Default | Meaning |
|---|---|---|
| `apiVersion` | | `build-onion/policy/v1`. |
| `release.refs` | `refs/heads/main`, `refs/tags/v*` | Refs (globs) whose builds may be sealed. Everything else builds and is checked, but isn't signed or published. |
| `release.events` | `push`, `workflow_dispatch`, `release` | Events whose builds may be sealed. `pull_request_target` and `workflow_run` are always refused. |
| `release.tagSigners` | | SSH public keys (authorized_keys form). When set, a tag release builds only if its tag is signed by one of them and points at the commit being built. |
| `sensitivePaths` | | Globs added to the build-configuration files the gate records changes to. Always included: `.github/**`, `CODEOWNERS`, the manifest, the policy, the lockfiles, the Dockerfile, and `build.sensitive`. |
| `sensitivePresets` | | Named sets of build-system files: `autotools`, `bazel`, `cmake`, `docker`, `go`, `gradle`, `make`, `maven`, `meson`, `node`, `python`, `rust`. |
| `requireBuildInputs` | `false` | Refuse to build a manifest without `build.inputs`. |
| `blockOpaqueInputs` | `false` | Refuse to build a change that adds or modifies a binary file (by content) the build can read. |
| `repository.requirePullRequest` | `false` | The release branch's rules must require pull requests. |
| `repository.minApprovals` | `0` | The release branch's rules must require at least this many approvals. |
| `repository.requireCodeOwnerReview` | `false` | The release branch's rules must require code-owner review. |
| `repository.blockForcePush` | `false` | The release branch's rules must block force pushes. |
| `repository.requireCodeOwners` | `false` | `CODEOWNERS` must name an owner for every build-configuration file. |
| `repository.tagsFromDefaultBranch` | `false` | A tag release must point at a commit on the default branch. |

Branch requirements are read from rulesets with the workflow's read-only token; for a tag release or a pull request build, the default branch's rules are checked.

## Trust file

Held by whoever runs `onion peel` as a gate, not by the repositories it verifies. Passed with `peel --trust`, and updated with `onion trust add`.

```yaml
apiVersion: build-onion/trust/v1
builders:
  - repository: PatterCJ/build-onion
    tagSigners:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… build-onion release key
    releases:
      - tag: v0.1.0
        commit: 0123456789abcdef0123456789abcdef01234567
        added: "2026-10-01"
apps:
  - repository: acme/widget
    tagSigners:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… widget release key
```

| Field | Meaning |
|---|---|
| `apiVersion` | `build-onion/trust/v1`. |
| `builders[].repository` | `OWNER/REPO` of the repository whose signing workflow seals artifacts. |
| `builders[].tagSigners` | SSH public keys allowed to sign its release tags. `onion trust add` requires one. |
| `builders[].releases` | Trusted releases: `tag`, the 40-hex `commit`, and the date it was `added`. An artifact is accepted only if the commit in its signing certificate is listed here. |
| `apps[].repository` | Optional. `OWNER/REPO` of a repository whose artifacts this verifier checks. |
| `apps[].tagSigners` | SSH public keys allowed to sign that repository's release tags. An artifact from a listed repository must have been released from a tag signed by one of them, whatever the repository's own policy allows. A repository not listed is noted, not checked. |

## Reusable workflows

Pin each one to a full commit SHA. A calling job must grant at least the permissions listed; the workflows grant each of their own jobs only what that job needs.

### Complete caller

Releases from signed tags; pull requests run the build line alone (see `ci.yml` in this repository). `.build-onion/policy.yml` applies without being named.

```yaml
name: release
on:
  push:
    tags: ["v*"]

permissions: {}

jobs:
  build:
    permissions: { contents: read, id-token: write }
    uses: PatterCJ/build-onion/.github/workflows/onion-build.yml@<sha>

  # Optional: your own scans, recorded (see scans.md).
  scan:
    needs: build
    # ... uploads an artifact named onion-record-scan-<name>

  verify:
    needs: [build, scan]
    permissions: { contents: read, id-token: write, attestations: write }
    uses: PatterCJ/build-onion/.github/workflows/onion-verify.yml@<sha>
    with:
      snapshot: ${{ needs.build.outputs.snapshot }}
      releasable: ${{ needs.build.outputs.releasable }}

  publish:
    needs: [build, verify]
    if: needs.build.outputs.releasable == 'true'
    permissions: { contents: write, packages: write, id-token: write }
    uses: PatterCJ/build-onion/.github/workflows/onion-publish.yml@<sha>
    with:
      image-digest: ${{ needs.verify.outputs.image-digest }}
      baseline: ghcr.io/acme/widget:v1.4.0   # the previous release
```

### `onion-build.yml`: build line

Caller permissions: `contents: read`, `id-token: write` (read only for the workflow's own identity; the build line never signs).

| Input | Default | Meaning |
|---|---|---|
| `manifest` | `build-onion.yml` | Manifest path, relative to the repository root. |
| `policy` | `.build-onion/policy.yml` if present, else built-in | Policy file path. |

| Output | Meaning |
|---|---|
| `releasable` | `true` when the gate allows this build to be sealed. |
| `snapshot` | Digest of the source snapshot the build used. Pass it to the verify line. |
| `cli-digest` | sha256 of the `onion` CLI this run built (artifact `onion-cli`), for scan jobs that record results. |

Artifacts other jobs can use: `onion-cli` (the CLI), `onion-snapshot` (`source.json`), `onion-outputs` (the staged outputs).

### `onion-verify.yml`: security line

Caller permissions: `contents: read`, `id-token: write`, `attestations: write`. Only its `seal` job can sign.

| Input | Default | Meaning |
|---|---|---|
| `snapshot` | *(required)* | The build line's `snapshot` output. |
| `releasable` | *(required)* | The build line's `releasable` output. The seal job re-runs the gate itself and refuses to sign if it disagrees. |
| `manifest` | `build-onion.yml` | Manifest path. |
| `policy` | `.build-onion/policy.yml` if present, else built-in | Policy file path; must be the file the build line was given. |
| `runs-on` | `ubuntu-24.04` | Runner for the independent rebuild. Point it at separate infrastructure where you have it. |

| Output | Meaning |
|---|---|
| `files-checksums` | `sha256sum`-format checksums of the sealed files. |
| `image-digest` | Digest of the sealed image, empty if none. |

It collects scan records from any artifact named `onion-record-scan-*`. It uploads the sealed bytes as `onion-verified` and the Sigstore bundles as `onion-bundles`. The `upstream` job needs outbound HTTPS to registry.npmjs.org, pypi.org, index.crates.io and sum.golang.org.

### `onion-publish.yml`: publish line

Caller permissions: `contents: write` (release assets on tags), `packages: write` (push the image), `id-token: write` (read only for the workflow's own identity; the publish line never signs).

| Input | Default | Meaning |
|---|---|---|
| `image-digest` | *(empty)* | The verify line's `image-digest` output. |
| `manifest` | `build-onion.yml` | Manifest path. |
| `environment` | `release` | GitHub environment the publish job runs in. Configure required reviewers there. |
| `baseline` | *(empty)* | A previously published image, usually the last release, to compare with. Dependencies that lost provenance or changed signer since then block publishing. If the image doesn't exist, publishing continues with a warning. |
| `accept-signer-changes` | `false` | Report provenance and signer changes against the baseline as notes instead of blocking. |

| Output | Meaning |
|---|---|
| `image` | Published image, pinned by digest (empty if none). |

The image is pushed as `<name>:sha-<commit>`, and also as `<name>:<tag>` for tag pushes. On tags, the files and bundles are attached to the GitHub release.

## `onion` CLI

Build it from the build-onion commit you use:

```sh
CGO_ENABLED=0 go build -trimpath -o onion ./cmd/onion
```

Or run it from the published image: `docker run --rm ghcr.io/pattercj/build-onion:<tag> peel …`. On GitHub Actions, every block, finding and coverage gap is also raised as an annotation on the run's summary page. `GITHUB_TOKEN`, when set, authenticates GitHub API requests; the unauthenticated limit is 60 an hour.

Commands you run yourself: [`peel`](#onion-peel), [`trust add`](#onion-trust-add), [`attest`](#onion-attest), [`validate`](#onion-validate), [`upstream`](#onion-upstream), [`record scan`](#onion-record), [`digest`](#onion-digest). The rest are the steps the reusable workflows run, and can drive the same pipeline from another CI system.

### Flags most commands share

| Flag | Default | Meaning |
|---|---|---|
| `--source DIR` | `.` | Repository checkout. |
| `--manifest FILE` | `build-onion.yml` | Manifest path, relative to `--source`. |

### `onion peel`

Verify an artifact against its signed record. See [Verifying an artifact](../README.md#verifying-an-artifact) for the report.

```sh
onion peel ARTIFACT --repo OWNER/REPO [flags]
```

`ARTIFACT` is a file, an image reference (a tag is resolved to its digest once), or an OCI tarball with `--oci`. It can come before or after the flags.

| Flag | Default | Meaning |
|---|---|---|
| `--repo OWNER/REPO` | *(required)* | Repository the artifact claims to come from. |
| `--commit SHA` | | Require this source commit. |
| `--ref REFS` | | Comma-separated ref globs the artifact must be built from, e.g. `refs/heads/main,refs/tags/v*`. |
| `--trust FILE` | | Accept only artifacts sealed by a build-onion release listed in this [trust file](#trust-file). |
| `--baseline ARTIFACT` | | Also verify a previous release and report what changed since it. |
| `--accept-signer-changes` | `false` | With `--baseline`: report lost provenance and signer changes as notes. |
| `--source DIR` | | Also check this checkout against the signed source snapshot. |
| `--rebuild` | `false` | Also rebuild from `--source` and compare digests (needs Docker). |
| `--oci` | `false` | `ARTIFACT` is an OCI image-layout tarball. |
| `--packages` | `false` | List every package in the artifact with its lockfile and upstream outcomes. |
| `--json` | `false` | Print the full report as JSON. |
| `--allow-degraded` | `false` | Exit 0 when the verdict is DEGRADED or UNSUPPORTED. |
| `--bundles DIR` | | Read Sigstore bundles from this directory instead of the GitHub attestations API. |
| `--baseline-bundles DIR` | | The same, for `--baseline`. |
| `--signer OWNER/REPO/PATH` | `PatterCJ/build-onion/.github/workflows/onion-verify.yml` | The workflow allowed to sign. Change it if you call the workflows from a fork or wrapper. |
| `--signer-ref REF` | *(any)* | Require an exact signer ref, e.g. `refs/tags/v0.1.0`. |
| `--trusted-root FILE` | *(Sigstore public-good via TUF)* | Sigstore `trusted_root.json`, for offline or private-instance verification. |

Exit codes: 0 passed, 3 degraded or unsupported, 4 finding, 5 failed.

### `onion trust add`

Vet a new build-onion release with the `onion` you already trust, then add it to a trust file.

```sh
onion trust add --trust FILE --tag TAG [--repo OWNER/REPO]
```

It fetches the tag with `git` and requires a signature from one of the builder's `tagSigners`. It then downloads the release's sealed binary and peels it (`--ref refs/tags/TAG`, commit from the tag), using this binary's code. Only if that passes does it append the release.

| Flag | Default | Meaning |
|---|---|---|
| `--trust FILE` | *(required)* | Trust file to update. |
| `--tag TAG` | *(required)* | Release tag, e.g. `v0.2.0`. |
| `--repo OWNER/REPO` | `PatterCJ/build-onion` | Builder repository. |
| `--asset NAME` | `onion` | Release asset to peel. |
| `--signer-path PATH` | `.github/workflows/onion-verify.yml` | The builder's signing workflow. |
| `--allow-degraded` | `false` | Accept a DEGRADED or UNSUPPORTED peel verdict. |
| `--trusted-root FILE` | *(Sigstore public-good)* | Sigstore `trusted_root.json`. |

### `onion validate`

Check a manifest, its pins and the repository's workflows.

```sh
onion validate [--source DIR] [--manifest FILE] [--github-output FILE]
```

| Flag | Meaning |
|---|---|
| `--github-output FILE` | Append the build plan (`has_image`, `image_name`, `dockerfile`, `context`) as `key=value` lines. |

### `onion upstream`

Check every locked package against its public registry. It prints what needs attention and exits 0 once the check has run; `peel` does the grading.

```sh
onion upstream [--source DIR] [--manifest FILE] [--out FILE] [-v]
```

| Flag | Default | Meaning |
|---|---|---|
| `--out FILE` | | Write the record as JSON. |
| `--snapshot FILE` | | Verify the checkout against this snapshot first. |
| `-v` | `false` | List every package, not only the ones that need attention. |
| `--npm-registry URL` | `https://registry.npmjs.org` | npm registry. |
| `--pypi URL` | `https://pypi.org` | PyPI (simple API and provenance). |
| `--crates-index URL` | `https://index.crates.io` | crates.io sparse index. |
| `--gosumdb URL` | `https://sum.golang.org` | Go checksum database, or a proxy of it. |
| `--gosumdb-key KEY` | *(sum.golang.org's key)* | Verifier key for `--gosumdb`. |
| `--trusted-root FILE` | *(Sigstore public-good)* | Sigstore `trusted_root.json` for provenance bundles. |

### `onion record`

Write a record for the security line to seal. Scan jobs use `record scan` (see [Scan records](scans.md)); the workflows use the others.

```sh
onion record scan --name NAME --status STATUS --subject-kind KIND --subject DIGEST --out FILE [flags]
```

| Flag | Meaning |
|---|---|
| `--name` | Your name for this check, e.g. `sca`. The record artifact must be named `onion-record-scan-<name>`. |
| `--tool`, `--version` | The tool that ran and its version. |
| `--stage` | `pre-build` or `post-build`. |
| `--started`, `--finished` | RFC 3339 times. |
| `--status` | Whether the analysis completed, not what it found: `completed`, `incomplete` or `failed`. |
| `--coverage` | What wasn't analyzed. Required unless `--status completed`. |
| `--subject-kind` | `source` (the snapshot) or `artifact` (an output). |
| `--subject` | The snapshot digest or artifact digest the tool examined. |
| `--report FILE` | The tool's report. It is hashed, never read. |
| `--report-url URL` | Where the report is kept. |
| `--out FILE` | Record to write (required). |

`record job` (`--name`, `--runner`, repeatable `--tool name=version`), `record workflow` (`--role`, `--ref`, `--file`) and `record build-onion` (`--repository`, `--commit`, `--cli-digest`) record the pipeline itself; each takes `--out`.

### `onion attest`

Sign an in-toto statement about one or more artifacts and write it as a Sigstore bundle, keyless: a short-lived key, certified by Fulcio for the CI job's OIDC identity and recorded in Rekor. `onion peel --bundles` verifies the result like any other bundle.

```sh
onion attest --subject NAME@sha256:HEX --predicate FILE --predicate-type URI --out bundle.json
onion attest --subject-checksums files.sha256 --provenance github --out provenance.json
```

| Flag | Default | Meaning |
|---|---|---|
| `--out FILE` | *(required)* | Bundle to write. |
| `--subject NAME@sha256:HEX` | | A subject; repeatable. |
| `--subject-checksums FILE` | | Subjects from `sha256sum` output. |
| `--predicate FILE`, `--predicate-type URI` | | The predicate to sign. |
| `--provenance github` | | Generate SLSA v1 provenance for the current GitHub Actions job instead, in the same form as GitHub's own. |
| `--token SOURCE` | `github` | Where the OIDC token comes from: `github` (the job needs `id-token: write`), or `env:NAME` for a token another CI provides. |
| `--fulcio URL`, `--rekor URL` | public-good Sigstore | Sigstore instances to use. |

### `onion digest`

```sh
onion digest [--oci] PATH...
```

Print the sha256 digest of each file, or with `--oci`, the image manifest digest of an OCI layout tarball.

### Pipeline steps

These are the commands the reusable workflows run, in order.

| Command | What it does | Flags |
|---|---|---|
| `onion source snapshot` | Hash every tracked file of a clean checkout. | `--source`, `--out` (required) |
| `onion source verify` | Fail if the checkout differs from a snapshot. | `--snapshot` (required), `--expect DIGEST`, `--source`, `--manifest` |
| `onion gate` | Decide whether this build may be sealed; exit non-zero if the policy blocks it. | `--snapshot`, `--event`, `--ref` (all required); `--policy`, `--base SHA`, `--fork`, `--repository`, `--platform`, `--actor`, `--run-url`, `--branch-rules FILE`, `--default-branch`, `--out`, `--github-output` |
| `onion fetch` | Run `dependencies.fetch` in the builder, behind the egress proxy when an allow-list is declared. | `--cache DIR` (required), `--snapshot`, `--egress-out FILE` |
| `onion build` | Run `build.run` in the builder with no network, on the staged inputs, and collect the outputs. | `--cache DIR`, `--out DIR`, `--snapshot`, `--stage-dir DIR` |
| `onion compare` | Compare the security line's rebuild with the build line's outputs; exit non-zero if they differ. | `--staged DIR`, `--rebuilt DIR`, `--runner`, `--out` |
| `onion inventory` | Hash everything and write the inventory predicate to stdout. | `--snapshot`, `--records DIR`, `--repository`, `--commit`, `--tree`, `--files DIR` (all required); `--expect-snapshot`, `--image-archive`, `--scan-records DIR`, `--gate`, `--rebuild`, `--egress`, `--upstream`, `--platform`, `--invocation` |
| `onion proxy` | The egress proxy, run inside its own container by `fetch`. | `--rules JSON`, `--log FILE` (required), `--listen` (default `127.0.0.1:3128`) |
| `onion version` | Print the version. | |

# Adopting build-onion

Every option mentioned here is listed in the [reference](reference.md).

## 1. Write the manifest

The manifest is the whole contract. Anything not declared is not available to the build.

| Field | Rule |
|---|---|
| `builder.image` | Pinned by digest. Every fetch and build step runs in it. |
| `dependencies.lockfiles` | Hashed into the inventory, and parsed so `peel` can prove every package in the artifact against them. Supported: `go.sum`, `package-lock.json` / `npm-shrinkwrap.json`, `requirements*.txt` (pinned with `==`), `uv.lock`, `poetry.lock`, `Cargo.lock`. Other lockfiles are still hashed, and packages from them grade UNSUPPORTED. |
| `dependencies.fetch` / `cache` | `fetch` must populate `cache` (a path inside the builder). The cache is then the only third-party input the build sees. |
| `dependencies.egress` | The only hosts `fetch` may reach, each with an optional `port` (default 443) and `private: true` if it lives on a private network. See [Restricting fetch](#restricting-fetch). Without it, fetch has unrestricted network and `peel` reports that as DEGRADED. |
| `dependencies.env` | Environment for `fetch` only, typically pointing a package manager at your artifact store. |
| `build.run` / `env` | Runs with `--network none`, as your UID, with `HOME=/tmp`. `env` applies to this step only, not to `fetch`. |
| `build.inputs` | Globs (`**` spans directories) naming the files fetch and build may read, for example `[src/**, cmd/**/*.go, go.mod]`. The manifest, lockfiles and Dockerfile are always included. Nothing else is staged: tests, fixtures, docs and untracked files don't exist for the build. A pattern that matches nothing fails the build. Without it, the build sees every tracked file and `peel` notes it. |
| `build.sensitive` | Globs naming your build scripts and build configuration (`Makefile`, `scripts/**`, `*.m4`, `build.rs`). Changes to them are recorded by the gate and shown by `peel`. Each pattern must match a tracked file. |
| `build.scratch` | Other paths `fetch` or `build` may create in the tree (`node_modules`, `build`). Any other new file fails the build. |
| `outputs.files` | Must not exist in the source; they must be produced by the build. |
| `outputs.image` | Built from the Dockerfile with `RUN` steps networkless, as a single-platform reproducible OCI image. Every `FROM` must be pinned. |

### Examples for other ecosystems

These use the same pattern: fetch with network into a cache, build offline from it.

```yaml
# Node
builder: { image: docker.io/library/node:22-bookworm@sha256:… }
dependencies:
  lockfiles: [package-lock.json]
  fetch: npm ci --ignore-scripts --cache /cache/npm && cp -r node_modules /cache/
  cache: /cache
build:
  run: cp -r /cache/node_modules . && npm run build --offline
  scratch: [node_modules, build]
```

```yaml
# Python (see build-onion-example-python for a complete repo)
builder: { image: docker.io/library/python:3.12-slim-bookworm@sha256:… }
dependencies:
  lockfiles: [requirements.txt]   # hash-pinned, e.g. `uv export --format requirements-txt`
  fetch: "pip download --require-hashes --only-binary=:all: --no-deps -r requirements.txt -d /cache/wheels"
  cache: /cache
  egress: [{host: pypi.org}, {host: files.pythonhosted.org}]
build:
  inputs: [src/**]
  run: pip install --no-index --find-links /cache/wheels --require-hashes --no-deps --no-compile -r requirements.txt --target dist/site
  scratch: [dist/site]
```

### Restricting fetch

With `dependencies.egress` set, the fetch container runs on a Docker network with **no route out**. Its only reachable peer is build-onion's egress proxy, which runs in a pinned distroless image with a read-only filesystem and no capabilities.

- **What gets through:** HTTPS goes through `CONNECT` and plain HTTP is forwarded, but only to listed hosts and ports.
- **How the check works:** the proxy resolves each host itself and connects to the address it checked. IP addresses are refused outright.
- **Addresses that are always blocked:** loopback, link-local (including the cloud metadata address `169.254.169.254`) and multicast.
- **Private addresses** (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7) are reachable only when the rule says `private: true`.
- **What the fetch container can't do:** it can't resolve external names itself, so tools that ignore the proxy variables get no network.
- **What happens on a violation:** any attempt to reach anything else **fails the fetch**, and the log names the host.

Every connection (host, port, allowed or denied, bytes each way) is recorded. The security line's record is sealed into the inventory.

```yaml
dependencies:
  lockfiles: [go.sum]
  fetch: go mod download && go mod verify
  cache: /go/pkg/mod
  egress:
    - host: proxy.golang.org
    - host: storage.googleapis.com   # proxy.golang.org redirects module zips here
```

With an internal artifact store, point the package manager at it and allow only the store:

```yaml
  env:
    GOPROXY: https://artifactory.acme.internal/api/go/go-remote
    GONOSUMDB: "*"
  egress:
    - host: artifactory.acme.internal
      private: true
```

The allow-list works on host names. It doesn't intercept TLS, so it can't tell apart paths or tenants on a shared host like `storage.googleapis.com`. An artifact store you control gives the tightest boundary.

To find out what a tool needs, run the fetch with a minimal list. The failure message names each denied host.

### How packages are proven

`peel` compares two independent readings of the build:

- **Declared:** build-onion's own parser reads each lockfile at the exact commit.
- **Present:** syft reports what is actually installed or linked inside the artifact.

Every package in the artifact gets one outcome:

| Outcome | Meaning | Grade |
|---|---|---|
| hash-verified | Declared, same version, same content hash. Go binaries carry each module's `h1:` hash; Rust binaries built with `cargo auditable` carry the crate list. | PASSED |
| version-verified | Declared, same version, no comparable hash. npm and Python lockfiles hash downloaded archives, not installed files; those archives were verified against the lockfile during the restricted fetch. | PASSED |
| base-image | Found in a layer of the pinned base image. The inventory proves the image starts with exactly those layers. | PASSED |
| vendored | A copy bundled inside a declared package (such as `setuptools/_vendor/…`). | PASSED |
| undeclared / version-drift / hash-mismatch | In the artifact but not declared, at a different version, or with different content. | FINDING |
| OS package outside the base, or an ecosystem without a parser | Can't be checked against a lockfile. | UNSUPPORTED |

Packages declared but not shipped (tests, tooling, other platforms) are counted as a note.

### How locked packages are checked upstream

The lockfile proves the artifact matches what you locked. The security line's `upstream` job then checks what you locked against the public registries, for every locked package, shipped or not (build-time tools run during fetch and build):

| Ecosystem | Checked against | Strongest outcome |
|---|---|---|
| Go | `go.sum` hashes against the sum.golang.org transparency log, with its signed tree head and inclusion proofs verified | logged |
| npm | `integrity` against the registry's, then the registry's Sigstore provenance, whose subject must be that same sha512 | attested |
| Python | every locked wheel and sdist hash against PyPI's files for that project and version, then each file's PEP 740 attestations | attested |
| Rust | `Cargo.lock` checksums against the crates.io index (crates.io publishes no provenance) | published |

| Outcome | Meaning | Grade |
|---|---|---|
| attested | Signed provenance verified, about exactly the locked bytes. The source repository, commit and workflow that built it are recorded. | PASSED |
| logged | The hash is the one Go's checksum log gives everyone. | PASSED |
| published | The registry publishes exactly the locked bytes, but no provenance for them. | PASSED |
| not-found / unhashed | Not on the public registry (a private package), or the lockfile pins no hash to compare. | NOTE |
| mismatch | The lockfile pins bytes the public registry doesn't publish under that name and version. | FINDING |
| invalid | The registry serves provenance that fails verification, or that is about other bytes. | FINDING |
| error | A registry couldn't be reached. | DEGRADED |

The check always uses the public registries, even when your fetch goes through a mirror: the mirror should agree with them. A private package whose name and version also exist on the public registry grades mismatch, since that name is open to dependency confusion. Rename or scope the private package.

`onion upstream` runs the same check locally; `--npm-registry`, `--pypi`, `--crates-index`, `--gosumdb` and `--gosumdb-key` point it elsewhere.

## 2. Make it reproducible

The security line seals only if its independent rebuild matches the build line byte for byte, so the build must be deterministic. Common fixes:

- Go: `-trimpath`, `-buildvcs=false`, `-ldflags=-buildid=`, `CGO_ENABLED=0`, `GOTOOLCHAIN=local`.
- Anything that embeds time: honor `SOURCE_DATE_EPOCH`.
- Images: build from already-compiled outputs; the pipeline sets `rewrite-timestamp=true`.

## 3. Add a policy (optional)

Without one, only `push`/`workflow_dispatch`/`release` builds of `main` and `v*` tags are sealed. See [policy.md](policy.md) to change that or flag more sensitive paths. To record the scanners your pipeline runs, see [scans.md](scans.md).

## 4. Wire the three lines

Call each reusable workflow by **commit SHA**:

```yaml
jobs:
  build:
    permissions: { contents: read, id-token: write }
    uses: PatterCJ/build-onion/.github/workflows/onion-build.yml@<sha>

  # …your own scan jobs here, uploading onion-record-scan-* artifacts (see scans.md)…

  verify:
    needs: [build]
    permissions: { contents: read, id-token: write, attestations: write }
    uses: PatterCJ/build-onion/.github/workflows/onion-verify.yml@<sha>
    with:
      snapshot: ${{ needs.build.outputs.snapshot }}
      releasable: ${{ needs.build.outputs.releasable }}
      # policy: same file as the build line, if you use one

  publish:
    needs: [build, verify]
    if: needs.build.outputs.releasable == 'true'
    permissions: { contents: write, packages: write, id-token: write }
    uses: PatterCJ/build-onion/.github/workflows/onion-publish.yml@<sha>
    with:
      image-digest: ${{ needs.verify.outputs.image-digest }}
      baseline: ghcr.io/acme/widget:v1.4.0   # optional: the last release
```

The `id-token` permission on the build and publish lines only lets each one read its own OIDC claims to pin the build-onion commit it runs; neither can sign. The publish job runs in the `release` environment (change it with the `environment` input). Add required reviewers there to put a human approval in front of every release.

To require a specific build-onion version when verifying, pass `--signer-ref`:

```sh
onion peel dist/widget --repo acme/widget --signer-ref refs/tags/v0.1.0
```

### On GitLab CI

GitLab has no reusable workflows, so the phases run as jobs of one pipeline, each recording what it consumed and produced (`--run`, `--link-in`, `--link-out`), and the release is sealed with your own key instead of keyless:

| Job | Commands |
|---|---|
| snapshot | `onion validate`, `onion source snapshot`, `onion gate --platform gitlab-ci`, `onion upstream` |
| fetch | `onion fetch` |
| build | `onion build` |
| package | `docker buildx build`, then `onion link image` |
| sbom | your SBOM tool on the image |
| seal | `onion source verify`, `onion gate` again, `onion record`, `onion inventory --links --platform gitlab-ci`, `onion attest --provenance gitlab --signer-command …` |
| publish | push the image by digest, `onion push-bundles`, `onion peel` |

Only the seal job gets the key: make it a protected CI/CD variable scoped to the seal job's environment, protect your release tags, and set the minimum role for pipeline variables to "No one allowed". Verify with `onion peel IMAGE --repo gitlab.com/GROUP/PROJECT --trust trust.yml --attestations registry`, where `trust.yml` lists the key as a builder. A single pipeline is graded DEGRADED, with the reason in the report. The [GitLab example project](https://gitlab.com/PatterCJ/onion) has the complete `.gitlab-ci.yml`.

## 5. Verify in your deploy gate

`peel` exits 0 only when every check passed: 3 for degraded or unsupported coverage, 4 for a finding, 5 when evidence couldn't be produced. `--allow-degraded` accepts incomplete coverage, and `--json` gives a machine-readable report. Typical gate:

```sh
onion peel "$IMAGE" --repo acme/widget --commit "$EXPECTED_SHA" \
  --ref 'refs/heads/main,refs/tags/v*' --json > peel.json
```

`--ref` makes the deploy gate decide which refs it releases from, independent of any policy file in the repository.

### Comparing with the last release

`--baseline` (or the publish line's `baseline` input) verifies a previously sealed artifact the same way, then adds a **differential** section:

| Change since the baseline | Grade |
|---|---|
| A dependency that published provenance before and doesn't now | FINDING |
| A dependency now built by a different source repository, workflow or identity provider | FINDING |
| Dependencies added, removed or at new versions; builder, base images, commands, lockfiles, Dockerfile, allowed hosts, workflow actions, build-onion commit or policy changed | NOTE |
| A dependency that now publishes provenance | NOTE |

Signers are compared per package across versions, so a new release of a dependency must come from the same repository and workflow as the one before. When a change is expected (a project moved or renamed its release workflow), `--accept-signer-changes` (publish input `accept-signer-changes`) reports it as a note. A baseline that doesn't verify makes the section DEGRADED.

```sh
onion peel "$IMAGE" --repo acme/widget --baseline ghcr.io/acme/widget:v1.4.0
``` Set `GITHUB_TOKEN` in the environment to avoid the GitHub API's 60-requests-per-hour unauthenticated limit, or pass `--bundles` to verify offline.

## 6. Trust build-onion releases, not commits

A workflow pin can point at any commit of build-onion, and anyone who can edit your workflow can change it. So the deploy gate, not the repository, decides which build-onion releases may seal what it deploys. Keep a trust file wherever the gate's configuration lives, owned by whoever owns the gate:

```yaml
# trust.yml
apiVersion: build-onion/trust/v1
builders:
  - repository: PatterCJ/build-onion
    # Keys allowed to sign build-onion release tags.
    tagSigners:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… build-onion release key
    releases: []   # filled by `onion trust add`
```

Then verify with it:

```sh
onion peel "$IMAGE" --repo acme/widget --trust trust.yml
```

An artifact sealed by any build-onion commit that isn't a listed release is a FINDING, whatever the workflow pinned. The signing certificate records the exact commit that sealed it, so a moved tag or a different pin can't hide it.

### Pinning who releases each app

The repository's own policy decides which keys may sign its tags, and the repository's writers can change it. To hold an app to keys you control, list it in the trust file:

```yaml
apps:
  - repository: acme/widget
    tagSigners:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… widget release key
```

`peel --trust` then requires the artifact's release tag to have been signed by one of these keys. An artifact built from an unsigned tag, from a branch, or signed by another key is a FINDING. Repositories not listed are noted, not checked.

### Adding a release

Run the `onion` you already trust:

```sh
onion trust add --trust trust.yml --tag v0.2.0
```

It adds the release only if:

1. the tag is signed by one of `tagSigners`, and
2. the release's sealed `onion` binary peels with your current `onion`, built from that tag's commit.

The new release's own code never judges itself. Pin your workflows to the commit it prints.

### The first release

With no trusted `onion` yet, check the first release independently before adding it: build `onion` from the tag after checking its signature (`git verify-tag`), and check the release binary with GitHub's verifier:

```sh
gh attestation verify onion --repo PatterCJ/build-onion \
  --signer-workflow PatterCJ/build-onion/.github/workflows/onion-verify.yml
```

Then run `onion trust add` with the binary you built.


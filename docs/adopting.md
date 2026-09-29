# Adopting build-onion

## 1. Write the manifest

The manifest is the whole contract. Anything not declared is not available to the build.

| Field | Rule |
|---|---|
| `builder.image` | Pinned by digest. Every fetch and build step runs in it. |
| `dependencies.lockfiles` | Hashed into the inventory. `go.sum` is also parsed for the dependency cross-check. |
| `dependencies.fetch` / `cache` | `fetch` runs **with network** and must populate `cache` (a path inside the builder). The cache is then the only third-party input the build sees. |
| `build.run` / `env` | Runs with `--network none`, as your UID, with `HOME=/tmp`. `env` applies to this step only, not to `fetch`. |
| `build.scratch` | Other paths `fetch` or `build` may create in the tree (`node_modules`, `build/`). Any other new file fails the build. |
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
# Python
builder: { image: docker.io/library/python:3.13-slim@sha256:… }
dependencies:
  lockfiles: [requirements.lock]
  fetch: pip download --require-hashes -r requirements.lock -d /wheels
  cache: /wheels
build:
  run: pip wheel --no-index --find-links /wheels --no-deps -w dist .
```

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

  # …your own scan jobs here, uploading onion-record-* artifacts (see scans.md)…

  verify:
    needs: [build]
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
```

The `id-token` permission on the build and publish lines only lets each one read its own OIDC claims to pin the build-onion commit it runs; neither can sign. The publish job runs in the `release` environment (change it with the `environment` input). Add required reviewers there to put a human approval in front of every release.

To require a specific build-onion version when verifying, pass `--signer-ref`:

```sh
onion peel dist/widget --repo acme/widget --signer-ref refs/tags/v0.1.0
```

## 5. Verify in your deploy gate

`peel` exits non-zero if any layer fails, and `--json` gives a machine-readable report. Typical gate:

```sh
onion peel "$IMAGE" --repo acme/widget --commit "$EXPECTED_SHA" --json > peel.json
```

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

`peel --rebuild` passes only if the build is deterministic. Common fixes:

- Go: `-trimpath`, `-buildvcs=false`, `-ldflags=-buildid=`, `CGO_ENABLED=0`, `GOTOOLCHAIN=local`.
- Anything that embeds time: honor `SOURCE_DATE_EPOCH`.
- Images: build from already-compiled outputs; the pipeline sets `rewrite-timestamp=true`.

## 3. Add a policy (optional)

Without one, only `push`/`workflow_dispatch`/`release` builds of `main` and `v*` tags are sealed. See [policy.md](policy.md) to change that, flag more sensitive paths, or add [plugins](plugins.md). If a plugin needs secrets, pass `secrets: inherit`. Each plugin receives only the secret names it declares.

## 4. Pin the workflow

Call the reusable workflow by **commit SHA**, and pass `--signer-ref` to `peel` if you want to require a specific build-onion version:

```sh
onion peel dist/widget --repo acme/widget --signer-ref refs/tags/v0.1.0
```

## 5. Verify in your deploy gate

`peel` exits non-zero if any layer fails, and `--json` gives a machine-readable report. Typical gate:

```sh
onion peel "$IMAGE" --repo acme/widget --commit "$EXPECTED_SHA" --json > peel.json
```

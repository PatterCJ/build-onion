# Adopting build-onion

## 1. Write the manifest

The manifest is the whole contract. Anything not declared is not available to the build.

| Field | Rule |
|---|---|
| `builder.image` | Pinned by digest. Every fetch and build step runs in it. |
| `dependencies.lockfiles` | Hashed into the inventory. `go.sum` is also parsed for the dependency cross-check. |
| `dependencies.fetch` / `cache` | `fetch` must populate `cache` (a path inside the builder). The cache is then the only third-party input the build sees. |
| `dependencies.egress` | The only hosts `fetch` may reach, each with an optional `port` (default 443) and `private: true` if it lives on a private network. See [Restricting fetch](#restricting-fetch). Without it, fetch has unrestricted network and `peel` reports that as DEGRADED. |
| `dependencies.env` | Environment for `fetch` only, typically pointing a package manager at your artifact store. |
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

`peel` exits 0 only when every check passed: 3 for degraded or unsupported coverage, 4 for a finding, 5 when evidence couldn't be produced. `--allow-degraded` accepts incomplete coverage, and `--json` gives a machine-readable report. Typical gate:

```sh
onion peel "$IMAGE" --repo acme/widget --commit "$EXPECTED_SHA" --json > peel.json
```

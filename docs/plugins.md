# Plugin API

build-onion protects the build. It is not a scanner and doesn't try to replace the tools teams already rely on: SCA suites, SAST, secret scanners, commit-risk models, cloud policy engines. The plugin API is how those tools join the pipeline, so their verdicts end up in the signed inventory alongside everything else.

A plugin is **a program that reads one JSON request on stdin and writes one JSON response on stdout**. That's the whole contract, so you can write one in any language, around any tool, without changing build-onion.

## Declaring a plugin

Plugins are declared in the [policy file](policy.md), not the per-repo manifest, so a repository cannot quietly turn off its own checks.

```yaml
plugins:
  - name: commit-risk              # lowercase; appears in the inventory and peel report
    hook: gate                     # where it runs (see Hooks)
    mode: advisory                 # advisory | enforce
    image: ghcr.io/acme/commit-risk@sha256:…   # must be pinned by digest
    network: true                  # default false: --network none
    secrets: [RISK_API_KEY]        # env var names passed through; nothing else is
    timeout: 2m                    # default 5m
    config:                        # passed verbatim as request.config
      threshold: 0.7
```

`command: [path, args…]` can replace `image` for local development. Command plugins aren't pinned, so they're refused unless `onion gate --allow-command-plugins` is passed. The reusable workflow never passes it.

## Hooks

| Hook | Runs | Question it answers |
|---|---|---|
| `gate` | before fetch and build | Is this commit trustworthy enough to build and release? |

More hooks are planned for the security line (`scan`, after the build, against the outputs) and the publish line (`publish`, before release). They will use the same request and response shapes.

## Request (stdin)

```json
{
  "apiVersion": "build-onion/plugin/v1",
  "hook": "gate",
  "source": {
    "repository": "https://github.com/acme/widget",
    "commit": "3f9c…",
    "tree": "a1b2…",
    "snapshotDigest": "sha256:…",
    "dir": "/src"
  },
  "change": {
    "base": "77e1…",
    "files": [".github/workflows/release.yml", "go.sum", "main.go"],
    "sensitive": [".github/workflows/release.yml", "go.sum"]
  },
  "context": {
    "platform": "github-actions",
    "event": "push",
    "ref": "refs/heads/main",
    "actor": "octocat",
    "runUrl": "https://github.com/acme/widget/actions/runs/42"
  },
  "config": { "threshold": 0.7 }
}
```

- `source.dir` is the checkout, mounted **read-only**. `snapshotDigest` identifies the exact bytes; the full per-file snapshot is what the build is verified against.
- `change` is omitted when there's no previous build point to diff against, such as the first push of a branch. Treat that as "unknown", not "nothing changed".
- `sensitive` lists changed paths that alter *how* the build runs: workflows, the manifest, lockfiles, the Dockerfile, the policy file, and any `sensitivePaths` from the policy.

## Response (stdout)

```json
{
  "apiVersion": "build-onion/plugin/v1",
  "verdict": "warn",
  "score": 0.82,
  "summary": "unusual author/time pattern for a change to release.yml",
  "findings": [
    { "id": "CR-7", "severity": "high", "message": "workflow change without review", "path": ".github/workflows/release.yml" }
  ]
}
```

| Field | Rules |
|---|---|
| `verdict` | `pass`, `warn` or `fail`. |
| `score` | Optional, 0 (no risk) to 1 (maximum risk). |
| `summary` | One line; shown in the gate log, the inventory and `onion peel`. |
| `findings` | Optional. `severity` is `info`, `low`, `medium`, `high` or `critical`. |

Unknown fields are rejected, and so are a wrong `apiVersion`, a score outside 0–1, a non-zero exit, a timeout, or more than 8 MiB of output. Any of these makes the verdict `error`.

## Modes

| Verdict | `advisory` | `enforce` |
|---|---|---|
| pass | recorded | recorded |
| warn | recorded, WARN in `peel` | recorded, WARN in `peel` |
| fail | recorded, WARN in `peel` | **blocks the build** |
| error | recorded, WARN in `peel` | **blocks the build** (fails closed) |

Every invocation goes into the signed inventory: plugin name, pinned image, mode, verdict, score, summary, finding count, and the sha256 of the raw response. The raw responses are kept as a build artifact.

## Sandbox

Image plugins run with:

```
docker run --rm -i --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges -v <checkout>:/src:ro \
  [--network none]  -e <declared secrets only>  <image@sha256:…>
```

Secret values reach the container through the environment, never the command line. Command plugins get only `PATH`, `HOME`, `TMPDIR`, `LANG` and their declared secrets.

## A minimal plugin

```python
#!/usr/bin/env python3
# Warns when a commit touches build-sensitive files. Package it in an image
# and pin the digest in the policy.
import json, sys

req = json.load(sys.stdin)
sensitive = (req.get("change") or {}).get("sensitive", [])
json.dump({
    "apiVersion": "build-onion/plugin/v1",
    "verdict": "warn" if sensitive else "pass",
    "summary": f"{len(sensitive)} build-sensitive file(s) changed",
    "findings": [{"severity": "medium", "message": "sensitive change", "path": p} for p in sensitive],
}, sys.stdout)
```

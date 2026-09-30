# Scan records

build-onion doesn't run scanners and doesn't judge what they find. The pipeline runs whatever tools it already uses (SCA, SAST, secret scanning, commit-risk scoring, licence checks), however and wherever it runs them. build-onion records **that** each one ran, and binds that record to the exact bytes of this build:

| Recorded | Why |
|---|---|
| Name, tool and version | Which check ran, and with what. |
| Stage | `pre-build` (against the source) or `post-build` (against an output). |
| Start and finish times | When it ran relative to the build. |
| Status | Whether the analysis itself completed (`completed`, `incomplete`, `failed`), with a coverage note saying what wasn't analyzed. This is about the tool finishing, never about what it found. |
| Subject | The source snapshot digest or the output digest the tool examined. |
| Report digest (and optional URL) | The sha256 of the report as the tool wrote it. build-onion never reads it, but anyone holding the report can prove it's the one recorded. |

## The one rule build-onion enforces

Every scan record must be **about this build**. A `source` subject has to equal this build's source snapshot, and an `artifact` subject has to be one of this build's outputs. Otherwise the security line refuses to seal. A report from an earlier commit, a different branch or another build can't be attached to this one.

What a scan *found*, and whether that should stop a release, is up to the pipeline and the teams that own those tools.

## Recording a scan

With the `onion` CLI (available as the `onion-cli` artifact in any run of the build line):

```sh
onion record scan \
  --name sca --tool blackduck --version 2026.7 \
  --stage post-build \
  --started 2026-09-29T20:05:00Z --finished 2026-09-29T20:31:00Z \
  --status completed \
  --subject-kind artifact --subject sha256:… \
  --report blackduck-report.json --report-url https://… \
  --out records/scan-sca.json
```

Then upload the record as an artifact named `onion-record-scan-<name>` before the security line runs. The security line collects every `onion-record-scan-*` artifact, and accepts **only scan records** from them. Pipeline facts (jobs, workflows, the build-onion commit) come only from build-onion's own jobs, so a job in your workflow can't vouch for anything but its own scans. See `.github/workflows/release.yml` for a complete example that records `govulncheck`.

Without the CLI, write the record directly:

```json
{
  "kind": "scan",
  "scan": {
    "name": "sca",
    "tool": "blackduck",
    "version": "2026.7",
    "stage": "post-build",
    "startedAt": "2026-09-29T20:05:00Z",
    "finishedAt": "2026-09-29T20:31:00Z",
    "status": "completed",
    "subject": { "kind": "artifact", "digest": "sha256:…" },
    "report": { "digest": "sha256:…", "url": "https://…" }
  }
}
```

## Where it shows up

Scan records go into the signed inventory under `pipeline.scans`. `onion peel` lists each one in its **scans** layer, with the tool, stage, times, what it examined and the report digest. A record that isn't about this build is a FINDING. A scan that didn't complete is DEGRADED: the coverage gap is reported, never silently treated as clean.

A scan that finishes after the security line has sealed isn't in the inventory. Record slow scans before `onion-verify.yml` runs, or keep their records alongside the release.

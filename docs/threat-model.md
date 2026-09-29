# Threat model

build-onion is a claim about **where an artifact came from**. This page says precisely which attacks that claim defeats and which it doesn't, so nobody over-trusts a green `peel`.

## Trust boundary

| Component | Trusted? | Why |
|---|---|---|
| GitHub-hosted runners, Actions OIDC, artifact attestations | Yes | The build platform. SLSA L3 assumes a trustworthy platform. |
| Sigstore (Fulcio, Rekor) | Yes | Issues and logs the signing certificates. |
| build-onion reusable workflow at a pinned commit | Yes | It is the signer identity `peel` checks. |
| The caller's source, manifest, fetch and build commands | **No** | Treated as adversarial. They run only in jobs that cannot sign. |
| Third-party dependencies | **No** | Constrained by the lockfile; fetched separately; build has no network. |

## Attacks defeated

| Attack | Stopped by |
|---|---|
| Artifact swapped after the build | Digest mismatch at the **seal** layer — the signature covers the bytes. |
| Artifact built elsewhere (a laptop, a fork, another workflow) and passed off as official | Certificate identity must be build-onion's workflow; provenance source repo and commit must match the claim. |
| Build step tries to sign something itself | The build job has no `id-token` permission; it cannot obtain a Sigstore certificate. |
| Caller input crafted to inject commands into the signing job | Inputs reach scripts only through environment variables; the manifest is parsed, never executed, in `seal`. |
| Build reaches the network to pull an unpinned tool or exfiltrate | Build runs with `--network none`. |
| Mutable references repointed (tags, `latest`) | Builder image, `FROM` lines, and actions must be pinned by digest/SHA or `validate` fails. |
| A dependency linked into the artifact that the lockfile never declared | **dependencies** layer: SBOM of the artifact ⊆ lockfile. |
| Provenance, SBOM, and inventory stitched together from different runs | **seal** layer requires one run invocation behind all three; inventory must name the same run as provenance. |
| Source tampered after release (lockfile edited, commit rewritten) | **source** layer recomputes tree hash and file digests from a checkout. |
| A source file swapped on the build machine and left that way | Every tracked file is sha256-hashed before the build and re-verified before and after fetch and build. Git's index and stat cache aren't consulted, so they can't be used to hide the change. |
| A file planted in the tree during the build (including `.gitignore`d paths) | Any new file outside declared outputs and `build.scratch` fails the build. |
| Mutable action tags repointed to malicious code | Unpinned `uses:` fails `validate`. Every action SHA that ran is in the signed inventory, so after an incident "which builds ran this commit of that action?" is a query. |
| Fork or PR code reaching release credentials | `pull_request_target` and `workflow_run` are refused. PRs, forks and non-release refs build but are never sealed. |
| A malicious commit to a release branch | Not blocked by provenance alone, but surfaced: changes to workflows, the manifest, lockfiles, Dockerfile or policy are flagged in the signed inventory, and any commit-risk scan the pipeline runs is recorded against the source snapshot. `peel` shows sensitive changes as warnings. |
| A file swapped only while the compiler reads it, then restored | The security line rebuilds from the same hashed inputs on its own runners and seals only if its bytes match the build line's. |
| The build approving its own output | The build line has no signing rights. Only the security line seals, and only after its own rebuild matches; the publish line can't sign and releases only what `peel` verifies. |
| A scan report from another build attached to this one | Scan records must name this build's source snapshot or one of its output digests, or the security line refuses to seal. |
| Build is not what the manifest says it is | **rebuild** layer replays the manifest and compares bytes. |

## Not defeated (be honest about these)

- **A compromise of both build environments at once.** The independent rebuild catches an environment that alters output, unless the same compromise affects the security line's runners too. Pointing `onion-verify.yml`'s `runs-on` at separate infrastructure narrows this.
- **Build behavior.** build-onion checks what a build consumed and produced, not what it did along the way (processes, files touched, connections). Observed-behavior recording is on the roadmap.
- **Build line network.** Until the egress proxy (Phase C) lands, the fetch step can reach any host. The build step already has no network; the fetch step has no signing credentials and is constrained by lockfile verification.
- **Malicious code at the commit.** If the commit itself contains a backdoor, build-onion faithfully proves the backdoor was built from that commit. Provenance is not code review — pair it with review and scanning.
- **A compromised dependency that *is* in the lockfile.** Lockfiles pin bytes, not intent. The fetch step runs `go mod verify` against `go.sum`, but a malicious version you locked is still malicious.
- **Compromised GitHub, Sigstore, or build-onion itself.** These are the trust root. Pin build-onion by commit and review updates.
- **Non-Go dependency checks.** The SBOM-within-lockfile check covers Go modules today. Other ecosystems still get lockfile hashing, a signed SBOM, and hermetic builds, but not the cross-check. OS packages in a pinned base image are reported but not lock-checked.
- **Private repositories.** GitHub signs attestations for private repos with its own Sigstore instance; pass that trust root with `peel --trusted-root`.

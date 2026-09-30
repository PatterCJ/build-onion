#!/usr/bin/env bash
# Captures real registry responses so the upstream tests run offline against
# genuine Sigstore bundles. Re-run to refresh; the tests pin these exact files.
set -euo pipefail
cd "$(dirname "$0")"

# npm: semver 7.6.3 publishes SLSA provenance.
curl -fsSL https://registry.npmjs.org/semver/7.6.3 -o npm-semver-7.6.3.json
curl -fsSL https://registry.npmjs.org/-/npm/v1/attestations/semver@7.6.3 -o npm-semver-7.6.3-attestations.json

# PyPI: sigstore 3.6.1 publishes PEP 740 attestations. The simple index is
# trimmed to that version's files.
curl -fsSL -H 'Accept: application/vnd.pypi.simple.v1+json' https://pypi.org/simple/sigstore/ |
  python3 -c 'import sys,json; d=json.load(sys.stdin); d["files"]=[f for f in d["files"] if "-3.6.1" in f["filename"]]; json.dump(d,sys.stdout)' \
  > pypi-sigstore-simple.json
curl -fsSL https://pypi.org/integrity/sigstore/3.6.1/sigstore-3.6.1-py3-none-any.whl/provenance -o pypi-sigstore-3.6.1-whl-provenance.json

# The Sigstore public-good trusted root, current as of capture.
cp ~/.sigstore/root/tuf-repo-cdn.sigstore.dev/targets/trusted_root.json trusted-root.json

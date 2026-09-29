#!/usr/bin/env bash
# Regenerates the dependency fixtures from real open-source packages.
#
# For each ecosystem it locks a small project that depends on real tools,
# installs or builds it exactly as the lockfile says, and scans the result
# with syft, the same version the pipeline uses. The tests then check that
# onion's lockfile parsers and syft's SBOM agree package by package.
#
# Needs: go, python3 (with venv), node/npm, cargo + cargo-auditable, syft.
# Every scan uses syft's image catalogers, as the pipeline does for built
# outputs: they report what is installed or linked, not what a manifest in
# the directory declares. SBOMs are trimmed to the fields peel reads (type,
# name, version, purl, hashes, first location path, and syft's
# h1Digest/mainModule properties) to keep fixtures small.
set -euo pipefail

SYFT_VERSION=1.51.1
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

syft version | grep -q "Version: *$SYFT_VERSION" || { echo "need syft $SYFT_VERSION" >&2; exit 1; }

trim() { # trim SBOM.json OUT.json
  python3 - "$1" "$2" <<'EOF'
import json, sys
keep_props = {"syft:metadata:h1Digest", "syft:metadata:mainModule", "syft:location:0:path"}
bom = json.load(open(sys.argv[1]))
out = []
for c in bom.get("components", []):
    t = {k: c[k] for k in ("type", "name", "version", "purl", "hashes") if k in c}
    props = [p for p in c.get("properties", []) if p["name"] in keep_props]
    if props:
        t["properties"] = props
    if "purl" in t:  # files and OS descriptors carry no package identity
        out.append(t)
out.sort(key=lambda c: (c.get("purl", ""), c.get("name", ""), c.get("version", "")))
json.dump({"bomFormat": "CycloneDX", "components": out}, open(sys.argv[2], "w"), indent=1)
EOF
}

scan() { # scan SOURCE OUT.json
  syft scan "$1" -q --override-default-catalogers image -o "cyclonedx-json=$work/raw.json"
  trim "$work/raw.json" "$2"
}

echo "== go: a real Go CLI (govulncheck), from its own go.sum"
mkdir -p "$here/go"
GOBIN="$work/go" GOFLAGS=-trimpath go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
(cd "$work" && go mod download -json golang.org/x/vuln@v1.1.4 | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])') > "$work/vulndir"
# The module cache is read-only; install gives the fixtures normal permissions.
install -m 0644 "$(cat "$work/vulndir")/go.sum" "$here/go/go.sum"
install -m 0644 "$(cat "$work/vulndir")/go.mod" "$here/go/go.mod"
scan "file:$work/go/govulncheck" "$here/go/sbom.json"

echo "== npm: http-server plus a scoped package, production install"
mkdir -p "$work/npm" "$here/npm"
cat > "$work/npm/package.json" <<'EOF'
{
  "name": "onion-npm-fixture",
  "version": "1.0.0",
  "private": true,
  "dependencies": { "http-server": "14.1.1", "@sindresorhus/slugify": "2.2.1" },
  "devDependencies": { "semver": "7.6.3" }
}
EOF
(cd "$work/npm" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null && npm ci --omit=dev --ignore-scripts --no-audit --no-fund >/dev/null)
cp "$work/npm/package-lock.json" "$here/npm/package-lock.json"
scan "dir:$work/npm/node_modules" "$here/npm/sbom.json"

echo "== pypi: httpie and PyYAML, locked by uv; poetry and requirements from the same set"
mkdir -p "$work/py" "$here/pypi"
python3 -m venv "$work/tools"
"$work/tools/bin/pip" install -q uv==0.9.5 poetry==2.2.1
cat > "$work/py/pyproject.toml" <<'EOF'
[project]
name = "onion-pypi-fixture"
version = "1.0.0"
requires-python = ">=3.12"
dependencies = ["httpie==3.2.4", "PyYAML==6.0.2"]

[tool.poetry]
package-mode = false
EOF
(cd "$work/py" && "$work/tools/bin/uv" lock -q && "$work/tools/bin/uv" export -q --format requirements-txt --no-emit-project -o requirements.txt && "$work/tools/bin/poetry" lock -q)
cp "$work/py/uv.lock" "$work/py/poetry.lock" "$work/py/requirements.txt" "$here/pypi/"
"$work/tools/bin/pip" install -q --no-deps --require-hashes -r "$work/py/requirements.txt" --target "$work/py/site"
scan "dir:$work/py/site" "$here/pypi/sbom.json"

echo "== cargo: a small binary with real crates, built with cargo-auditable"
mkdir -p "$work/rs/src" "$here/cargo"
cat > "$work/rs/Cargo.toml" <<'EOF'
[package]
name = "onion-cargo-fixture"
version = "1.0.0"
edition = "2021"

[dependencies]
serde_json = "=1.0.128"
anyhow = "=1.0.89"
EOF
echo 'fn main() { let v: serde_json::Value = serde_json::json!({"ok": true}); println!("{v}"); let _ = anyhow::anyhow!("x"); }' > "$work/rs/src/main.rs"
(cd "$work/rs" && cargo generate-lockfile -q && cargo auditable build -q --release --locked)
cp "$work/rs/Cargo.lock" "$here/cargo/Cargo.lock"
scan "file:$work/rs/target/release/onion-cargo-fixture" "$here/cargo/sbom.json"

echo "fixtures regenerated in $here"

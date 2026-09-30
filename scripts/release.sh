#!/usr/bin/env bash
# Tag origin/main as a signed release and push the tag, which starts the
# release workflow. Usage: scripts/release.sh v1.2.3
#
# The tag is checked against the keys the policy at that commit accepts
# (.build-onion/policy.yml release.tagSigners) before anything is pushed.
set -euo pipefail

version=${1:-}
if [[ ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "usage: scripts/release.sh vX.Y.Z" >&2
  exit 2
fi

git fetch -q origin --tags
if git rev-parse -q --verify "refs/tags/$version" >/dev/null; then
  echo "$version already exists; release tags can't be reused" >&2
  exit 1
fi
commit=$(git rev-parse origin/main)
echo "Releasing $version at: $(git log --oneline -1 "$commit")"

signers=$(git show "$commit:.build-onion/policy.yml" \
  | sed -n '/^ *tagSigners:/,/^[^ ]/p' | sed -n 's/^ *- *\(ssh-[^ ]* [^ ]*\).*$/\1/p')
if [ -z "$signers" ]; then
  echo "no release.tagSigners in .build-onion/policy.yml at $commit" >&2
  exit 1
fi

git tag -s "$version" -m "$version" "$commit"

allowed=$(mktemp)
trap 'rm -f "$allowed"' EXIT
while read -r key; do echo "release $key"; done <<<"$signers" >"$allowed"
if ! git -c gpg.ssh.allowedSignersFile="$allowed" verify-tag "$version"; then
  git tag -d "$version" >/dev/null
  echo "the tag isn't signed by a key the policy accepts (check: git config user.signingkey); tag removed" >&2
  exit 1
fi

read -r -p "Push $version? [y/N] " answer
if [ "$answer" != y ]; then
  git tag -d "$version" >/dev/null
  echo "not pushed; tag removed"
  exit 1
fi
git push origin "$version"
echo "Pushed $version. Approve the publish job in GitHub Actions when it asks."

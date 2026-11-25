#!/usr/bin/env bash
# Pin the agent builds the action runs to a release: download each asset from
# the given tag, hash it, and write action/agents.json. Review the diff, then
# commit it with the change that needs the new agents.
#
#   scripts/pin-agents.sh v1.2.0
set -euo pipefail
tag="${1:?usage: scripts/pin-agents.sh <tag, e.g. v1.2.0>}"
[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not a release tag: $tag" >&2; exit 2; }
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
declare -A hash
for a in legionr-bpf legionr-fim; do
    curl -fsSL -o "$tmp/$a" "https://github.com/Wraith-security/legion_runner/releases/download/${tag}/${a}"
    hash[$a]="$(sha256sum "$tmp/$a" | cut -c1-64)"
    echo "$a ${hash[$a]}"
done
cat > "$root/action/agents.json" <<EOF
{
  "release": "${tag}",
  "assets": {
    "legionr-bpf": "${hash[legionr-bpf]}",
    "legionr-fim": "${hash[legionr-fim]}"
  }
}
EOF
echo "wrote action/agents.json for ${tag}"

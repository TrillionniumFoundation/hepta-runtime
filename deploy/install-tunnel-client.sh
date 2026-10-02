#!/usr/bin/env bash
set -euo pipefail
version=v0.0.15
asset="tunnel-client-runtime-${version}-linux-amd64.zip"
expected=f26f8b3ee6c335e38fa5cfbe6ce5635f53738f08a26eecf07d6cebacab4a1abf
base="https://github.com/openai/tunnel-client/releases/download/${version}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl --fail --location --retry 3 --output "$tmp/$asset" "$base/$asset"
printf '%s  %s\n' "$expected" "$tmp/$asset" | sha256sum --check --strict
unzip -q "$tmp/$asset" -d "$tmp/unpacked"
binary=$(find "$tmp/unpacked" -type f -name tunnel-client-runtime -print -quit)
if [[ -z "$binary" ]]; then
  echo "release did not contain tunnel-client" >&2
  exit 1
fi
install -o root -g root -m 0755 "$binary" /usr/local/bin/tunnel-client
/usr/local/bin/tunnel-client --version

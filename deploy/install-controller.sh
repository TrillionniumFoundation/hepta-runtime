#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 3 ]]; then
  echo "usage: $0 BINARY RUNTIME_CONFIG VERSION" >&2
  exit 2
fi
binary=$1
config=$2
version=$3
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
if ! id -u hepta-runtime >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/hepta-runtime --create-home --shell /bin/bash hepta-runtime
fi
install -d -o hepta-runtime -g hepta-runtime -m 0700 \
  /var/lib/hepta-runtime /var/lib/hepta-runtime/.ssh \
  /var/lib/hepta-runtime/state /var/lib/hepta-runtime/jobs \
  /var/lib/hepta-runtime/workspaces
install -d -o root -g root -m 0755 "/opt/hepta-runtime/releases/$version"
install -o root -g root -m 0755 "$binary" "/opt/hepta-runtime/releases/$version/hepta-runtime"
ln -sfn "/opt/hepta-runtime/releases/$version" /opt/hepta-runtime/current
install -d -o root -g hepta-runtime -m 0750 /etc/hepta-runtime
install -o root -g hepta-runtime -m 0640 "$config" /etc/hepta-runtime/runtime.json
if [[ ! -s /etc/hepta-runtime/mcp-token ]]; then
  token_tmp=$(mktemp)
  trap 'rm -f "$token_tmp"' EXIT
  openssl rand -hex 32 > "$token_tmp"
  install -o root -g hepta-runtime -m 0640 "$token_tmp" /etc/hepta-runtime/mcp-token
fi
install -o root -g root -m 0644 "$script_dir/hepta-runtime.service" \
  /etc/systemd/system/hepta-runtime.service
install -o root -g root -m 0644 "$script_dir/hepta-runtime-tunnel.service" \
  /etc/systemd/system/hepta-runtime-tunnel.service
loginctl enable-linger hepta-runtime
systemctl daemon-reload
systemctl enable --now hepta-runtime.service
systemctl --no-pager --full status hepta-runtime.service

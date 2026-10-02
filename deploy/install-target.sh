#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then
  echo "usage: $0 CONTROLLER_PUBLIC_KEY_FILE" >&2
  exit 2
fi
pubfile=$1
if ! id -u hepta-runtime >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/hepta-runtime --create-home --shell /bin/bash hepta-runtime
fi
uid=$(id -u hepta-runtime)
install -d -o hepta-runtime -g hepta-runtime -m 0700 \
  /var/lib/hepta-runtime /var/lib/hepta-runtime/.ssh \
  /var/lib/hepta-runtime/state /var/lib/hepta-runtime/jobs \
  /var/lib/hepta-runtime/workspaces
# Preserve existing management keys; provision only the reviewed public key.
key=$(cat "$pubfile")
[[ $key == ssh-ed25519\ * || $key == ecdsa-sha2-* ]] || { echo 'Unsupported public key' >&2; exit 2; }
[[ $key != *$'\n'* ]] || { echo 'Exactly one public key is required' >&2; exit 2; }
authorized=/var/lib/hepta-runtime/.ssh/authorized_keys
touch "$authorized"
if ! grep -Fq -- "$key" "$authorized"; then
  printf 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding %s\n' "$key" >> "$authorized"
fi
chown hepta-runtime:hepta-runtime /var/lib/hepta-runtime/.ssh/authorized_keys
chmod 0600 /var/lib/hepta-runtime/.ssh/authorized_keys
loginctl enable-linger hepta-runtime
systemctl start "user@${uid}.service"
echo "Target account ready. Review sshd AllowUsers/Match rules before remote use."

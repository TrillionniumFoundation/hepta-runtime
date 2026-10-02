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
extra_groups=()
getent group render >/dev/null && extra_groups+=(render)
getent group video >/dev/null && extra_groups+=(video)
if ((${#extra_groups[@]})); then
  IFS=,; usermod -aG "${extra_groups[*]}" hepta-runtime; unset IFS
fi
install -d -o hepta-runtime -g hepta-runtime -m 0700 \
  /var/lib/hepta-runtime /var/lib/hepta-runtime/.ssh \
  /var/lib/hepta-runtime/state /var/lib/hepta-runtime/jobs \
  /var/lib/hepta-runtime/workspaces
{
  printf 'no-agent-forwarding,no-X11-forwarding,no-port-forwarding '
  cat "$pubfile"
} > /var/lib/hepta-runtime/.ssh/authorized_keys
chown hepta-runtime:hepta-runtime /var/lib/hepta-runtime/.ssh/authorized_keys
chmod 0600 /var/lib/hepta-runtime/.ssh/authorized_keys
loginctl enable-linger hepta-runtime
systemctl start "user@${uid}.service"
echo "Target account ready. Review sshd AllowUsers/Match rules before remote use."

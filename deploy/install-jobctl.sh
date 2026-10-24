#!/usr/bin/env bash
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
# Installer source; run only on a reviewed Linux target with administrator access.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root on the reviewed Linux target.' >&2; exit 1; }
binary=${1:?usage: install-jobctl.sh BINARY}
[[ -f $binary ]] || exit 2
id hepta-runtime >/dev/null
getent group hepta-workspace >/dev/null || groupadd --system hepta-workspace
usermod -aG hepta-workspace hepta-runtime
install -d -o hepta-runtime -g hepta-workspace -m 2770 /var/lib/hepta-runtime/workspaces
install -d -o root -g hepta-runtime -m 0750 /etc/hepta-runtime
install -d -o root -g root -m 0755 /usr/local/libexec
stamp=$(date +%Y%m%dT%H%M%S)
backup=/var/backups/hepta-runtime-jobctl/$stamp
install -d -m 0700 "$backup"
for p in /usr/local/libexec/hepta-runtime-jobctl /etc/hepta-runtime/job-policy.json /etc/sudoers.d/hepta-runtime-jobctl /etc/systemd/system/hepta-runtime-jobs.slice; do
  [[ ! -f $p ]] || cp -a "$p" "$backup/$(basename "$p")"
done
install -o root -g root -m 0755 "$binary" /usr/local/libexec/hepta-runtime-jobctl.new
mv /usr/local/libexec/hepta-runtime-jobctl.new /usr/local/libexec/hepta-runtime-jobctl
if [[ ! -f /etc/hepta-runtime/job-policy.json ]]; then
  printf '%s\n' '{"workspace":"/var/lib/hepta-runtime/workspaces","allow_network":false,"max_cpu_percent":100,"max_memory_bytes":1073741824,"max_timeout_seconds":3600}' > /etc/hepta-runtime/job-policy.json
  chmod 0640 /etc/hepta-runtime/job-policy.json
fi
printf '%s\n' 'hepta-runtime ALL=(root) NOPASSWD: /usr/local/libexec/hepta-runtime-jobctl ""' > /etc/sudoers.d/hepta-runtime-jobctl
chmod 0440 /etc/sudoers.d/hepta-runtime-jobctl
visudo -cf /etc/sudoers.d/hepta-runtime-jobctl
# Aggregate caps apply only to our jobs, not to trading or CI services.
cat > /etc/systemd/system/hepta-runtime-jobs.slice <<'UNIT'
[Unit]
Description=Bounded Hepta Runtime isolated jobs
[Slice]
CPUQuota=100%
CPUWeight=10
MemoryHigh=768M
MemoryMax=1G
MemorySwapMax=0
TasksMax=128
IOWeight=10
UNIT
systemctl daemon-reload
printf 'installed=%s\nbackup=%s\n' /usr/local/libexec/hepta-runtime-jobctl "$backup"
sha256sum /usr/local/libexec/hepta-runtime-jobctl

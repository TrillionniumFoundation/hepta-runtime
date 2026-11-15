# Hepta Runtime architecture and operating contract

Hepta Runtime is an Apache-2.0 fork of Octofs pinned to upstream commit
`37b5d3d02be511bae86d91fa980996a5fe257d7b`. It keeps Octofs file tools and
adds an explicit multi-host operations plane.

## Design goals

- Every remote operation names a configured host. Tool calls never accept raw
  SSH destinations, private keys, or ports.
- Process execution accepts an executable and argv, not a shell command string.
- Long jobs keep durable metadata and logs and continue when the MCP transport
  or Hepta Runtime controller restarts.
- Interactive PTYs are a separate, intentionally ephemeral facility.
- Ordinary execution uses a dedicated unprivileged SSH identity.
- Root operations are exact named actions configured by an administrator; the
  model cannot supply an arbitrary privileged executable.
- Hardware, service and network inspection is read-only and typed.
- Remote file writes are host-registered, explicitly enabled, and constrained
  to absolute allowlisted roots.

## Architecture

```text
ChatGPT / Codex / Responses API
              |
      OpenAI Secure MCP Tunnel
              | outbound HTTPS only
              v
 tunnel-client (dedicated account)
              |
   127.0.0.1:8787/mcp only
              v
       hepta-runtime
              |
        OpenSSH client
       /      |       \
     rog   pocket4    mac
      |        |        |
 dedicated unprivileged target accounts
```

The controller does not expose a public listener. The Streamable HTTP endpoint
is bound to loopback and the official tunnel client reaches it locally. Runtime
HTTP mode requires a high-entropy token file; every `/mcp` request must carry
`X-Hepta-Runtime-Token`. Health and readiness probes contain no host data.

## Tool contract

### Durable process tools

- `process_start`: explicit host, executable, argv, cwd, environment, optional
  stdin, timeout and resource limits. An idempotency key binds to one exact
  request and prevents accidental duplicate starts.
- `process_status`: authoritative remote state.
- `process_read`: independent stdout/stderr byte offsets, bounded pagination.
- `process_wait`: bounded wait, never a new process.
- `process_cancel`: only stored jobs; no arbitrary PID input.
- `process_list`: durable controller-side identities.

On Linux, the remote helper uses a transient user systemd unit. Production
policies fail closed if the user manager cannot create it; detached fallback is
an explicit per-host exception intended for macOS in v0.1. Jobs default to a
private network namespace restricted to AF_UNIX, preventing access to host
localhost services such as trading gateways. Network access is a separate,
explicit host policy. Both backends write
request, launch, PID/start-time and exit records inside the configured remote
state directory. The controller stores a separate immutable job identity and
an append-only audit event.

**Ambiguous remote start is reconcile-only.** The remote executor binds its launch
record to the full SHA-256 request digest and opens per-job metadata relative to
one no-follow directory descriptor under an exclusive per-job launch lock.
The durable request is synced before attempting the process effect. If SSH
acknowledgement, `launch.json`, or supervisor evidence is missing, a subsequent
`process_start` with that key must **not** conclude that no process ran and must
not start a replacement. Corrupt, symlinked, oversized or pre-full-digest records
also fail closed. An operator must reconcile the remote effect and preserve its
identity before any recovery decision; automatic retry is intentionally unavailable
when effect nonoccurrence cannot be independently demonstrated. This is a
software boundary, not proof of target-host process attestation or Final-use.

A controller restart does not terminate durable jobs. A remote host reboot is
not claimed as process recovery in v0.1: logs and metadata remain, but an
in-flight transient unit is reported lost unless the application itself has a
separate restart policy.

### PTY tools

`pty_start/read/write/close/list` provide interactive terminal sessions over
SSH. Output is held in a bounded offset-addressable ring buffer. PTYs survive
individual MCP calls and tunnel reconnects while the controller process remains
alive. They are deliberately terminated when the controller stops and are not
advertised as restart-persistent.

### Read-only inspection

- `hardware_snapshot`: DMI, CPU and memory, hwmon, GPU use and clocks, power
  supplies, supported platform power limits, NPU device nodes, and USB4 /
  Thunderbolt peers.
- `service_status`: exact systemd units or launchd labels; no mutation.
- `network_inspect`: links, addresses, routes, listeners and USB4 peers.

### Privileged actions

`privileged_action` selects an exact symbolic action from the host policy. The
policy fixes the absolute root-owned executable, fixed arguments, whether extra
arguments are accepted, and a timeout. The runtime invokes it through
`sudo -n`. Do not configure `/bin/sh`, `/usr/bin/env`, interpreters, package
managers, general-purpose file tools, or a wrapper accepting arbitrary shell
text as a privileged action.

## Policy boundary

The first and strongest boundary is the target operating-system identity. Use a
separate `hepta-runtime` account on every host. Give it only its runtime state
and workspace. Do not give it the target user's SSH keys, trading files,
browser profiles, provider credentials, or runner credentials.

The runtime adds defense in depth:

- default denial of sudo, shells, nested SSH, process signalling, service and
  package managers, mounts, containers, firewall tools and detached-session
  launchers;
- optional absolute cwd allowlists;
- write-root allowlists and protected path prefixes;
- protected argument substrings for known workloads;
- exact host binding for every job and PTY;
- process cancellation by stored unit/supervisor ownership, not caller PID;
- local JSONL audit records.

The policy is not a substitute for UNIX permissions. A deliberately allowed
interpreter can perform anything available to its target account. Keep the
account unprivileged and use exact privileged actions for the small set of root
operations that are truly needed.

## Local shell and file rules

When `--runtime-config` is active, the inherited unrestricted Octofs `shell`
tool is neither advertised nor callable. Durable `process_start` and ephemeral
`pty_start` are the only general execution paths; both require a configured
host, explicit executable/argv, and host policy approval.

Inherited local file tools are confined to canonicalized
`controller_workspace_roots`. Absolute paths, client-provided session workdirs,
nonexistent write targets, and symlink ancestors are checked against those
roots. Controller state, audit logs, SSH keys and `/etc/hepta-runtime` are not
file-tool-visible.

## Remote file rules

**P0 security quarantine:** With `--runtime-config` enabled, all inherited
remote SFTP file access is currently **denied**, including reads, writes,
stat/list operations, directory creation, deletion, and low-level connection
pool reuse. High-level path admission and the SFTP pool both enforce this
denial before any remote SSH/SFTP effect. Configuring
`allowed_read_path_prefixes`, `allowed_write_path_prefixes`, or
`allow_write=true` does **not** override it.

The previous path policy checked absolute textual prefixes, explicit parent
components, user/port overrides and protected paths. Those checks cannot
constrain the **physical** object reached by an SFTP server when an in-root
directory is a symlink, or when an adversary swaps that directory between
canonicalization and open/create/truncate/rename. A canonicalize-only patch is
not sufficient. Remote SFTP tools must remain disabled until a qualified
remote OS account/chroot/mount-namespace confinement boundary is in place,
with independent symlink and mutation-race tests, exact-source Rust gates,
and real SSH/SFTP host receipts. This change is a temporary containment
measure, **not** a claim that SFTP isolation is fully implemented.

Without `--runtime-config`, legacy Octofs remote-file support is retained,
and the Hepta runtime-mode host-policy guarantees do not apply. Local
controller-workspace file rules and explicit process/PTY tools are separate
policies; this quarantine does not expand their authority.

## Secure MCP Tunnel

Preferred deployment keeps the runtime on loopback and uses the official
OpenAI tunnel client as a separate service. Create a tunnel ID and a runtime API
key in OpenAI Platform. Keep that key in `/etc/hepta-runtime/tunnel.env` or a
secret manager; never put it in this repository. The same environment file sets
`MCP_SERVER_URL` to the loopback MCP endpoint, sends
`X-Hepta-Runtime-Token: file:/etc/hepta-runtime/mcp-token` for discovery and
normal MCP requests, and binds tunnel health to loopback.

The installed runtime-flavor binary exposes `run`, not the full development
CLI. After credentials are provisioned, enable the tunnel service and require
both its systemd state and `http://127.0.0.1:8788/health?details=true` to report
healthy before connecting ChatGPT.

## Deployment sequence

1. Build and test the exact locked source.
2. Install the controller and official tunnel client from checksum-verified
   artifacts.
3. Create the dedicated controller and target accounts.
4. Install an SSH key owned only by the controller account; pre-populate
   `known_hosts` and use `StrictHostKeyChecking=yes`.
5. Create `/var/lib/hepta-runtime/{state,workspaces,jobs}` on Linux targets.
6. Install a reviewed runtime policy at `/etc/hepta-runtime/runtime.json`.
7. Install only exact root-owned helper scripts and matching narrow sudoers
   entries when privileged actions are required.
8. Start `hepta-runtime.service`, verify MCP discovery locally, then start the
   tunnel service and verify health/readiness.
9. Test representative allowed operations and negative cases for protected
   paths, duplicate idempotency keys, arbitrary PIDs, sudo and shell launch.
10. Keep Desktop Commander as a rescue path until reboot, reconnect, durable
    job recovery and rollback tests pass on every target.

## Rollback

Stop and disable the two services, remove the tunnel profile and key, and
restore the previous binary symlink. Durable target job directories are not
deleted automatically. Inspect or archive them before removal.

## Known v0.1 boundaries

- Durable processes survive controller/tunnel restarts, not arbitrary target
  reboots.
- PTYs are controller-process scoped.
- The controller-side JSONL audit is not yet a tamper-evident hash chain.
- macOS uses a detached supervisor rather than transient systemd units.
- No GUI capture or desktop input API is included in v0.1.
- Hardware schemas expose raw kernel values where units vary; consumers must
  preserve field names and interpret units explicitly.

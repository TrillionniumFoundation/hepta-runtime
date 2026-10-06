# Operator mode and Desktop Commander replacement

## Trust contract

`execution_mode: "isolated"` remains the default. It retains the Linux root-owned job helper, DynamicUser isolation, command restrictions and existing named privileged actions.

`execution_mode: "operator"` is an explicit administrator configuration, not a tool-call parameter. It runs as the configured SSH login with that account's actual filesystem, network and sudo rights. This is an SSH/DC-equivalent trusted administration interface, **not a sandbox**. A shell or interpreter can exercise every permission available to that account; arbitrary sudo can become host-wide root authority when existing sudoers permits it. Do not expose an operator endpoint to untrusted clients. ChatGPT/app authorization and platform safety checks remain independent and are not disabled by this setting.

The controller may remain unprivileged and systemd-hardened. Linux operator jobs use the target login's user-systemd manager, or its explicitly enabled detached fallback. They do not run as DynamicUser and do not add NoNewPrivileges/RestrictSUIDSGID to operator workloads. The installer does not add `NOPASSWD: ALL`, alter PAM, change the target account, or grant root. SSH host-key verification remains mandatory; agent forwarding is explicitly disabled.

An operator host cannot simultaneously claim protected command/path substrings, command deny lists or execution-cwd sandboxing. Such contradictory configurations fail validation. File-tool read/write roots remain separately configurable; they constrain those APIs, not an operator shell. Use a different host alias and a separate state directory for operator access rather than silently changing an isolated host's authority. Job records bind execution mode and SSH destination, so old identities cannot silently change privilege context.

## Tools

| Tool | Behavior |
| --- | --- |
| `shell_start` | Host-bound arbitrary shell source, with pipes, redirection, expansion, functions and compound commands. Returns a durable job; use `process_read/status/wait/cancel`. The default shell is `/bin/sh`; select `/bin/bash` or another absolute executable explicitly. |
| `process_start` | Arbitrary executable/argv in operator mode, including an interpreter, nested SSH, a package manager or `sudo -n`. In isolated mode existing restrictions remain. |
| `pty_start/read/write/close` | Real SSH interactive terminal as the target login. Supports interactive shells and existing authentication prompts. The returned PID is the controller's SSH child, not a target-host PID. |
| `host_processes` | Bounded pagination of actual target-host processes, including processes not created by the runtime. Returns start identity; command arguments are omitted to avoid exposing secrets. |
| `host_signal` | Signal exactly one positive PID under the target account's OS permissions. `sudo: true` uses existing noninteractive sudo permission. Signal 0 probes; default 15 is TERM. Use `expected_identity` from process inspection to reject PID reuse. Linux uses pidfd when available. Non-pidfd platforms report `atomic_identity: false`; they cannot guarantee the same race-free identity semantics. Delivery is not confirmation of process termination. |
| `sudo_start` | Arbitrary temporary sudo executable/argv through a PTY. Default `fresh_auth: true` supplies `sudo -k`; `non_interactive: true` adds `-n`. `run_as` defaults to root. Actual sudoers/PAM decides authorization. No permission grant, persistent root daemon or new sudoers entry is created. |

The inherited hostless `shell` tool remains disabled in runtime mode. These new tools require an explicit configured operator host. Adding `execution_mode` or a password field to tool arguments is rejected by the schema.

## Temporary elevation and secrets

Prefer the account's existing authentication and use a bounded command instead of a root shell when possible. `sudo_start` returns a PTY session, not an elevation token or a revocable capability lease. Closing it is not a guarantee that privileged subprocesses deliberately detached by the command are stopped. Existing operating-system behavior remains authoritative.

Do not put passwords in executable arguments, shell source, environment values or durable stdin: job requests can be persisted. Runtime PTY audit records contain byte counts, not submitted text, but an MCP client or conversation may retain input. Authenticate locally or through an approved secret input mechanism rather than placing passwords in chat. No OpenClaw, Codex or provider credential is reused for tunnel provisioning.

## Lifecycle and error semantics

Use an idempotency key for durable starts. Reuse the **same** key and request after a transport failure. Do not invent a new key because an acknowledgement is missing. Operator launches with uncertain acknowledgement are not automatically repeated; the existing job must be reconciled. A remote launch lock additionally serializes attempts at one job identity.

Durable jobs and output can survive controller restart; target reboot does not resume a running application. PTYs are controller-scoped and are not restart-persistent. Linux user-systemd provides user-account service management, not isolation from that account. Detached fallback cannot enforce CPUQuota/MemoryMax and now rejects requests containing those limits rather than silently ignoring them. The user-account supervisor drains stdout/stderr with a 16 MiB storage cap per stream, records truncation in terminal status, and returns at most 16 KiB per stream per read with byte cursors. Operator/macOS lifecycle guarantees must still be qualified separately from isolated Linux: cgroup isolation and containment of deliberately escaped subprocesses are not implied.

Never automatically repeat `host_signal` after an ambiguous network failure. Inspect current process identity/status first. `signal_sent` deliberately does not mean `terminated`.

## Example deployment

Use `config/hepta-runtime.operator.example.json` as a template. Replace the target alias with an administrator-provisioned SSH alias for the actual trusted login. The target state directory must be writable by that login. Do not reuse the low-privilege isolated account and expect it to have the desktop user's rights. Keep token authentication, loopback binding and existing controller service hardening. Start an independent canary endpoint and state directory first; leave Desktop Commander untouched.

## Acceptance and cutover

Run unit tests plus `python3 tests/process_ops_tests.py`. That process test only signals its own disposable child.

For actual SSH and MCP qualification:

```sh
python3 tests/operator_acceptance.py \
  --binary "$PWD/target/debug/hepta-runtime" \
  --ssh-target YOUR_EXISTING_OPERATOR_SSH_ALIAS \
  --out operator-acceptance.json --sudo-smoke
```

This launches only a separate temporary controller, creates a unique target `/tmp/hepta-operator-canary-*` directory, and uses disposable commands/processes. `--sudo-smoke` runs `id -u` with the target account's existing permission, without changing sudoers. Test metadata is retained as evidence. Failed external test sleeps self-expire; no cleanup guesses a PID identity. Production services are not restarted. The report explicitly records whether password prompting and the ChatGPT tunnel were actually tested.

A successful local canary is not a complete DC replacement. Before removing DC, verify the exact installed binary, all required hosts, file/binary/document workflows, PTY interruption and reconnect, reboot behavior, target permissions, tunnel/workspace binding, and an actual call from the intended ChatGPT client. Keep an independent rescue path and rollback binary until those checks pass. Service installation alone does not establish cloud account binding. No automated cutover or uninstallation is performed by this implementation.

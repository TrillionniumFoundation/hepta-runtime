# Desktop Commander functionality parity — live 50-tool Hepta server

**2026-10-13 local (+08), 2026-10-12 UTC.** This document supersedes older v4 receipts that correctly said the 50-tool candidate was staged but not yet activated. The subsequent controlled production cutover completed. The four added operations are correctly annotated and do not disguise arbitrary command execution.

## What became live

The original native hepta-runtime exposed 46 tools. Its replacement release exposes **50**, preserving every original 46 tool definition **exactly**. Four genuine, distinct native file operations were added:

| New name | Real semantics | MCP hints |
|---|---|---|
| `directory_create` | Controller-local, recursively create absent directories; existing directory succeeds; symlink components refused | state-changing, non-destructive, idempotent |
| `file_move` | Same-filesystem `renameat2(RENAME_NOREPLACE)` of a regular file; no overwrite, symlink source or copy/delete fallback | state-changing, destructive, non-idempotent |
| `text_file_write` | UTF-8 create, append or replace with `absent`/exact SHA256 precondition, bounded payload and no blind retries | state-changing, destructive, non-idempotent |
| `directory_move` | No-replace native directory rename; reject symlink/source workspace root relocation and preserve inode identity | state-changing, destructive, non-idempotent |

This is server-side parity with Desktop Commander's explicit create-directory, move-file and text writing functions. Hepta's older process, PTY, document and shell tools are retained without changing their definitions. All four new tools run through the native runtime, **not** a shell wrapper, a hidden executor, or a mislabeled read-only facade. The controller has an existing broad configured workspace root; these operations still use that runtime account's native filesystem authority. Their publication requires explicit client-side tool review, not an inference from existing app permissions.

## Exact release and qualification

- Source + six-host evidence commit: `22986bab5e5c2b21f9dfd13befaee2046f7022cb`.
- Exact-head hosted CI **38273148813**: `success`.
- Preserved old native executable SHA256: `5bb9dadef53329caa13acec8965d2d6c074c17192c744078d76b689d8c3fb8b3`.
- New native release SHA256: `db181570e9e65f9e6a962d013dd4880eedc5b0cda1c71508f84388a4a8d8072b`.
- Frozen full v4 contract file SHA256: `d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1`.
- Before cutover, six real SSH target qualification covered 49 successful full-stdio checks and 63 root-guard/release checks. See `docs/qualification/dc-parity-v4-full-facade-six-host-20261012.json` and `docs/qualification/dc-parity-root-guard-release-six-host-20261012.json`.
- New release and frozen contract matched SHA256, and the 46 unchanged tool descriptions, input schemas and security annotations compared exactly.
- Full pre-cutover local read-only inventory: **153/153 native jobs were terminal, 37/37 PTYs were exited/output-complete, and 9 cooperative stream sessions were exited**. No queued tunnel dispatches at cutover.
- Two separate service restarts were performed, **not** a whole-machine reboot: native runtime now listens at its original `127.0.0.1:8790` with PID `2064509`; Full Operator Tunnel remains on `127.0.0.1:8793` with PID `2064582`; Desktop Commander PID `2894` remained unchanged.
- The new tunnel profile still binds `tunnel_6acc93cc226081919911d15143cafbdb`, preserves the restricted control-plane credential file, and runs the same verified full stdio adapter pinned to the v4 contract.
- Postcutover Full Operator health returned `ready=true`, successful control-plane polling and a running stdio child.
- Postcutover local-origin native scratch smoke passed **9/9** checks: all 50 tools discovered, directory create, absent-file create, version-checked append/replace, stale hash denial, no-replace file move, no-replace directory move and old job/PTY/stream retention. The temporary smoke directory was removed.
- Postcutover modern `server/discover`, `tools/list` and `tools/call(host_list)` passed official MCP 2026-07-28 JSON Schema checks, **0 errors**, returning 50 tools and 6 hosts.
- A real ChatGPT-origin **legacy `host_list` tool invocation succeeded after cutover**; this does not constitute model-origin proof for any of the newly added four tools.

## Rollback and service ownership

The successful cutover was executed using `deploy/activate_dc_parity_v4.py --apply`, an exact-source, one-time guarded installer with automatic best-effort rollback **if cutover fails**. The successful forward path was exercised; an actual production rollback was **not** intentionally triggered.

Original state backup:
`~/.config/hepta-full-operator/backup-before-v4-20261012T160939Z/`

Files: `full-operator-profile.json`, `installed-manifest.json`, `activation.json`.

Production unit override:
`~/.config/systemd/user/hepta-runtime-operator.service.d/60-parity-v4.conf`

Its removal re-exposes the original ExecStart release in the base systemd unit. The existing `50-native-documents.conf` drop-in and native document worker remain untouched.

A separate guarded **read-only rollback preflight** passed:
`python3 deploy/rollback_dc_parity_v4.py --inspect --backup-dir ~/.config/hepta-full-operator/backup-before-v4-20261012T160939Z`.

If intentional rollback is needed later, run that same exact inventory check **again first** and only then `--apply`; the script refuses rollback if old/new release digests or job/PTY inventories have changed. A future new job invalidates the automatic rollback assumptions and requires a separate maintenance plan. Never delete/restore the current state directory manually, and do not restart Desktop Commander.

## Model-origin availability remains separate

The **live MCP backend has 50 tools**, but the ChatGPT app's previously scanned tool snapshot still showed **46** immediately after cutover. Current-chat tool list snapshots are not updated merely because a server has a new catalog. A workspace-authorized explicit `Refresh/Scan Tools` and review of the four new tool schemas/actions is required before model-origin calls can use them.

User-specific `Allow all actions` in plugin permissions is not a guarantee of platform approval for sensitive operations. Earlier `shell_start` and `document_write` were blocked pre-dispatch, and those refusals remain distinct from correct server-side capability. We neither changed their annotations nor retried them under another name. No model-origin new file-write success, arbitrary shell, sudo/PTY acceptance or public Cloud Gateway qualification is claimed yet.

Authoritative completion receipt: `docs/qualification/dc-parity-v4-live-activation-20261013.json`.

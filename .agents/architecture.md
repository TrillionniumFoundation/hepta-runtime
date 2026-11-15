# Hepta Runtime — architecture notes

Reference for cross-cutting work. Read when a change spans more than one module.
The filesystem layer retains its Octofs compatibility contracts. The current
runtime also owns policy, durable jobs, artifact analysis and optional engine
interfaces; [repository layout](../docs/REPOSITORY_LAYOUT.md) describes their
source and language boundaries.

## Module map

| Entry or family | Responsibility |
| --- | --- |
| `src/main.rs`, `src/cli.rs` | `hepta-runtime mcp`, optional `--runtime-config`, stdio/authenticated loopback HTTP, worker subcommands and shutdown |
| `src/lib.rs`, `src/native.rs` | Shared Rust library and trusted in-process process facade; the embedding host owns final-use authorization |
| `src/bin/jobctl.rs` | `hepta-runtime-jobctl` owned-job helper |
| `src/bin/hepta-effect-ownerctl.rs` | Offline-tested administrator primitive to freeze/resume the same effect owner; not a production-installed command |
| `src/mcp/mod.rs` | Module ownership, `McpToolCall`, startup-only `SESSION_ROOT` |
| `src/mcp/server.rs` | `OctofsServer`, tool registration, parameter schemas, per-session workdir, resource subscriptions and dispatch to each owner |
| `src/mcp/request_ctx.rs` | Per-request context and the hint queue drained by `append_hints` |
| `src/mcp/runtime/config.rs`, `effective_config.rs` | Installed host/policy configuration and its public projection |
| `src/mcp/runtime/jobs.rs`, `execution.rs`, `ssh.rs` | Durable job lifecycle, execution selection and original SSH transport ownership |
| `src/mcp/runtime/request_async.rs`, `operation_async.rs`, `request_audit.rs`, `request_results.rs` | Request/operation ownership, durable audit and original-result retention |
| `src/mcp/runtime/binary.rs`, `multi_read.rs`, `search_jobs.rs`, `documents.rs` | File, search and document routes; configured Python helpers remain embedded inputs |
| `src/mcp/runtime/pty.rs`, `stream.rs`, `terminal.rs`, `checkpoint.rs` | Interactive processes, persistent output and separately authorized checkpoint actions |
| `src/mcp/runtime/inspect.rs`, `health.rs`, `operator.rs` | Host inspection, health observations and configured operator actions |
| `src/mcp/rea*.rs` | Native artifact/model/container parsing, static engine providers, browser capture, immutable stores and source-bound evidence |
| `src/mcp/weight*.rs` | Model-worker ownership/transport, native typed artifacts and numerical/certificate operators; Python model computation lives in `workers/weight/` |
| `src/mcp/hia_contract.rs`, `hia_provider.rs`, `hia_tool_catalog.json` | HIA catalog validation and configured provider dispatch |
| `src/utils/line_hash.rs`, `truncation.rs` | Line identity, token/byte bounds and response truncation |

The module declarations in `src/mcp/mod.rs` and `src/mcp/runtime/mod.rs` are the
source of truth for the complete graph. Sibling `*_tests.rs` files contain unit
tests; `src/mcp/fs/fs_tests.rs` covers filesystem integration and
`src/mcp/server_tests.rs` covers protocol delivery. The rmcp `client` feature is
a dev-dependency for those tests.

### Filesystem compatibility layer

These paths are relative to `src/mcp/fs/`:

| Module | Responsibility |
| --- | --- |
| `mod.rs` | Module list and `execute_*`, `parse_path_source`, `PathSource` re-exports |
| `core.rs`, `file_ops.rs` | Path resolution, undo history, view/create/edit entry points |
| `text_editing.rs` | Progressive replacement, batch edits and per-file async locking |
| `directory.rs`, `search.rs` | Gitignore-aware listing, remote listing and literal/regex context matches |
| `delta.rs` | `ViewCache`, `note_write`/`note_create`, Myers diffs and hunk rendering |
| `remote.rs` | SSH URL parsing, OpenSSH config, SFTP connection pool and remote file operations |
| `shell.rs`, `background.rs` | Shell misuse checks, original-child lifecycle, output capture and completion notifications |
| `workdir.rs` | Per-session workdir get/set/reset |

`OctofsServer` and `octofs://jobs/<id>` remain live compatibility identifiers;
the executable and CLI command are `hepta-runtime`.

## Execution flow

For filesystem tools, a `server.rs` `#[tool]` method → builds `McpToolCall` (carries the per-session `workdir`) → runs the `execute_*`
function inside `request_ctx::with_request_context(view_cache, …)` → result string → `append_hints()` drains the
hint queue into the response. Tool methods return protocol content; one may attach a `ResourceLink` when a call
promotes a job to background (see shell).

Runtime, REA, weight and HIA tools dispatch to their respective owners. Preserve
each route's policy checks, original request identity, response framing and
engine requirements; the filesystem flow above is not a replacement for those
contracts. See [runtime architecture](../docs/HEPTA_RUNTIME.md),
[native REA integration](../docs/rea-native/UNIFIED_RUNTIME.md),
[weight ownership](../docs/weight-runtime/RUST_OWNER.md) and
[HIA agent integration](../docs/HIA_AGENT_NATIVE_MCP.md).

## State

- **SessionWorkdir** — per `OctofsServer` instance (`RwLock<Option<PathBuf>>`); HTTP mode creates a fresh server per
  session. `SESSION_ROOT` in `mcp/mod.rs` is only the startup default.
- **FILE_LOCKS** — per-file `tokio::sync::Mutex` inside a `std::sync::Mutex<HashMap>`; keys are canonicalized
  local paths or `PathSource::lock_key()` (host+path) for remote. The outer guard is never held across `.await`.
- **FILE_HISTORY** — content snapshot before every write; powers `undo` (max 10 levels per file, 64 MiB across all files, in-memory only).
- **ViewCache** (`delta.rs`) — per session and file, the last content the model saw in full. Whole-file views
  return only hunks changed since; this server's own writes keep the cache in step via `note_write` (only if the
  cached "before" matched) / `note_create`. Ranged views and searches bypass it.
- **SFTP pool** (`remote.rs`) — sessions pooled per (host, port, user); dead transports evicted and replaced;
  the map lock only finds a target slot; that target's mutex covers connection setup,
  so different hosts connect independently without duplicate connections to one target.
- **Runtime state** — `runtime/config.rs` installs the policy and private state root;
  `request_audit.rs`, `request_results.rs` and the job/operation owners retain their
  own durable records. `prepare_durable_stores` prepares the stores before readiness
  when requested; a filesystem view cache is not a durable job receipt.

## Line ids

One format, no mode switch: `N:hh` — 1-indexed position plus a 2-char lowercase hex FNV1a-8 hash of the line's
content (content-only, so a moved line keeps its hash and stale errors can say where content went). `view`
renders `N:hh|content`. Edit targets require ids, verified per-target via `verify_line_id`; a stale id fails
with current content around the target, relocation candidates, and a ranged-view suggestion. Edit results are
diffs with fresh ids plus a trailing `shift:` line, so edits chain without re-viewing. Plain integers remain
where position alone is safe: `view` ranges (negatives count from EOF) and batch_edit insert anchors `0` (file
start) / `-1` (after last line).

## Shell lifecycle

Command runs in the foreground window (`FOREGROUND_TIMEOUT`) with progress notifications. If it outlasts the
window, the same process is promoted to a background job (`background::promote`), the tool call returns a
resource URI `octofs://jobs/<id>`, and a wait task fires the completion callback exactly once — subscriptions
first, peer `resources/updated` notification as fallback. A resource read returns status plus the output tail
(`MAX_TAIL_BYTES` = 30 000). Children run in their own process group; `kill_all_shell_children()` runs on stdio
EOF/SIGTERM and on HTTP ctrl-c.

This describes the filesystem `shell` route. Runtime durable host jobs use
`runtime/jobs.rs` and remain queryable across controller restarts.
`runtime::shutdown_request_scoped` freezes and drains request-scoped owners,
kills registered shell children and closes controller PTYs; it preserves those
durable host jobs.

## Transport

- **stdio** (default): one `OctofsServer`; session root from `--path` or cwd; clean exit on stdin EOF or SIGTERM.
- **HTTP** (`--bind`): axum + rmcp streamable HTTP; fresh `OctofsServer::with_root()` per session; initial
  workdir settable via MCP `initialize` params. The listener must bind to loopback
  and use `--auth-token-file`; see `src/main.rs` for the transport checks.

The default `remote-fs` feature provides the CLI's SSH/SFTP filesystem backend.
Library consumers can use `default-features = false`; local operations and the
native durable process facade remain available while remote filesystem URLs are
rejected. Configured Python/Java/model engines retain their own dependencies.

## Validation and source ownership

Use the pinned Rust 1.95.0 and cargo-nextest 0.9.137 commands in
[AGENTS.md](../AGENTS.md) and [release validation](release.md). The full test suite
requires process isolation in both feature configurations. `make coverage` uses
the same nextest isolation for the all-feature coverage run.

`vendor/ruzstd/` supplies the local decoder patch. `Cargo.toml` is also embedded
in persistent weight-guard request identity; packaging-only edits need an
identity compatibility assessment. Historical sources live at the immutable
commits indexed under `archives/`; current code must not import a retired
snapshot as an alternative implementation.

## Error handling shape

`anyhow::bail!` for early validation exits; `.context(...)` on propagated errors; `.unwrap()` only in tests and
OnceLock init. Shell-misuse and remote-workdir-with-local-shell are hard errors (bail), softer guidance goes
through `push_hint` instead of failing the call.

# Desktop Commander → Hepta functional parity (private candidate)

The target is **honest functional parity for user-authorized operations**, not
tool naming/annotation manipulation to get past ChatGPT safety checks. A
ChatGPT plugin showing a write schema, a local/native acceptance success and
an actual ChatGPT-origin action result are three separate qualification states.

## Exact current surfaces

- Remote Desktop Commander v0.2.52: 31 tools in the ChatGPT session, including
  10 core modify/execute tools and 3 additional stateful management actions.
  Its actual desktop agent has a command blocklist (including `sudo`,
  `shutdown`, `reboot`, `poweroff`, disk formatting, and firewall commands).
  It is **not** an unrestricted terminal.
- Installed Hepta Full Operator: **46 tools**, including **27 tools annotated
  non-read-only**, with unchanged native binary and pinned catalog.
- The candidate schema is pinned separately in `deploy/contracts/hepta-runtime-full-operator-v2.json`: exactly 48 tools; all 46 v1 tool definitions are byte-for-byte equivalent as parsed JSON. The schema file format remains `hepta-native-tool-contract-v1`; v2 refers to its versioned **tool catalog**.
- This source candidate: **48 tools** only in an isolated build, adding two
  independently useful filesystem tools with truthful annotations. **This is
  not installed in the production runtime or ChatGPT's approved tool snapshot.**
- Both ChatGPT apps have app-specific `Allow all actions`, but that is not
  evidence every possible tool call passes platform safety checking.

## Core modify/execute capability comparison

| DC tool | Native Hepta equivalent or gap | Local native evidence | ChatGPT-origin evidence |
| --- | --- | --- | --- |
| `write_file` | `text_editor` create/replace; `batch_edit`; separate `binary_write`. Plain append/rewrite parity is incomplete. | Native editing proven in existing tests; not a drop-in mode match. | DC `write_file` used successfully on project evidence; Hepta text-file writes not accepted in this chat. |
| `write_pdf` | `document_write`, `document_render`, `pdf_edit` cover bounded cases, not all DC semantics. | Real native document tests already passed. | Hepta scratch `document_write` explicitly blocked by platform pre-tool safety check. |
| `create_directory` | **New** `directory_create`: Linux controller-local, configured workspace only; mkdir -p semantics; no symlinks. | Native isolated MCP + focused Rust tests passed. | Not exposed to installed plugin yet; no hosted ChatGPT write approval claimed. |
| `move_file` | **New** `file_move`: one ordinary file, Linux controller-local, same filesystem, atomic no-replace; directories/remote/cross-device moves unsupported. | Native isolated MCP + focused Rust tests passed. | Not exposed to installed plugin yet; no hosted approval claimed. |
| `edit_block` | `text_editor` + `batch_edit` (line-id/version-oriented); `document_edit` only for bounded document XML. | Native local tests exist; different input contract. | No positive ChatGPT-origin Hepta edit receipt. |
| `set_config_value` | Intentionally not a generic configuration mutation endpoint. Specific managed ops require their own review. | Not equivalent. | Not qualified. |
| `start_process` | `shell_start` and `process_start` (durable, host-scoped, idempotency/reconciliation). Not the same synchronous process UX as DC. | Six-host native tests passed earlier. | DC safe `start_process` worked; Hepta `shell_start` pre-tool safety-blocked. |
| `interact_with_process` | `pty_start/read/write/close` for Hepta-owned sessions; cannot attach arbitrary preexisting DC Node buffers. | Six-host PTY tests passed earlier. | No qualifying ChatGPT-origin Hepta PTY input success. |
| `force_terminate` | `process_cancel` for runtime-owned jobs; `host_signal` for identity-checked specific PID. | Real disposable native PID tests passed; not arbitrary DC session adoption. | Not qualified from ChatGPT. |
| `kill_process` | Identity-bound `host_signal`; not wildcard/group execution or broad kill. | Native disposable PID tests passed. | Not qualified from ChatGPT. |

Additional stateful DC actions: `start_search` and `stop_search` have
different lifecycle semantics from Hepta's bounded synchronous `view`; a
DC-remote-agent `shutdown` has no directly equivalent general-purpose Hepta
operator tool. They are intentionally **not counted as complete parity**.

## New controller-local tools

- `directory_create(path)`: `readOnlyHint=false`,
  `destructiveHint=false`, `idempotentHint=true`,
  `openWorldHint=false`. Creates missing private directories only in an
  already-authorized controller workspace, returns `created` and refuses
  symlink/ordinary-file components. Linux fd-relative `mkdirat/openat`,
  without a shell command, remote fallback or sudo.
- `file_move(source,destination)`: `readOnlyHint=false`,
  `destructiveHint=true`, `idempotentHint=false`,
  `openWorldHint=false`. Requires existing regular source, both paths within
  configured controller workspaces, existing destination parent, no symlink
  components, and Linux `renameat2(RENAME_NOREPLACE)`; refuses overwrites and
  cross-filesystem fallbacks. It invalidates both cached file views. This is
  a path move, not an arbitrary command runner.

**Non-goals and limits:** path policy and inode correctness still depend on
the existing OS authority, configured workspace roots and Linux kernel.
Operations are not a substitute for transactional multi-file edits, arbitrary
symlink-resolving moves, directory moves or cross-host copies. Source path
identity cannot be proved immune to all attacks from a concurrent malicious
writer who already controls the source parent directory. Do not apply a
universal `safe to rename anything` label to this narrow operation.

## Acceptance and release discipline

The candidate must pass:
1. `cargo fmt --all --check`, `cargo clippy --locked --all-features --all-targets -- -D warnings` and `cargo test --locked --all-targets`.
2. Dedicated Linux fd-relative tests: nested/duplicate directories, no-symlink
   parent/leaf, root/parent traversal refusal; regular file rename/no overwrite,
   symlink/hardlink cases and inode continuity.
3. **Independent temporary MCP server** with its own state/config/token/ephemeral
   127.0.0.1 port; discover 48 tools and correct annotations, create/move in its
   dedicated temp workspace and prove out-of-workspace refusals. This is *not*
   evidence of a ChatGPT-origin write call.
4. New exact-head GitHub Actions CI. A CI success after adding tools does not
   automatically authorize installing the new native backend.
5. Versioned Full Operator tool contract and explicit ChatGPT administrator
   approval/refresh if new tools are eventually deployed. Existing 46-tool
   private tunnel/installed native runtime must be preserved until then.

**No safety circumvention:** Do not re-export `shell_start` as another name or
mark any process/document overwrite tool as read-only to try to avoid
OpenAI pre-tool checks. The existing Shell and scratch DOCX creation calls
were refused by platform safeguards; their disposition remains HOLD unless
ChatGPT legitimately allows their actual declared operations.

Official design criteria: https://developers.openai.com/plugins/plan/tools and
https://developers.openai.com/plugins/plugin-guidelines.

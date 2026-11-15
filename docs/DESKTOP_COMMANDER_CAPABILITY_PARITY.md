# Desktop Commander → Hepta functional parity (private candidate)

## LATEST: 50-tool model-origin file, shell and PTY acceptance — 2026-10-13

### Frozen model-origin capability ledger: 22 of 31 non-read-only tools — 2026-10-13

After the six-host PTY and harmless Shell pipeline checks, a fresh model-origin, controller-local `/tmp` regression qualified **eight previously unverified declared operations** without renaming or relabeling them: `batch_edit` (versioned line-ID replacement), `extract_lines` (copy one line into another file), `binary_write` (31-byte create-only), `binary_upload` (invisible chunk → SHA256-bound commit), `document_render` (static HTML/CSS to one-page PDF), `pdf_edit` (source-preserving one-page insertion into a distinct two-page PDF), `worksheet_edit` (single-cell workbook update with cache invalidation), and `worksheet_recalculate` (offline `SUM` formula yielding cached 40 with zero formula errors). Native `file_info`/`binary_read` confirmed binary output, while **independent read-only host filesystem checks** confirmed all scratch-file hashes; both PDFs passed `pdfinfo`/`pdftotext`, rendered PNG previews were visually checked, and OOXML worksheet XML retained the exact formula text with cached numeric result 40. No external PDF assets, macros, spreadsheet external links or privilege changes were used.

**Coverage, not a blanket approval:** the currently frozen 50-tool catalog has 19 read-only and 31 non-read-only tools. Exactly **22 distinct non-read-only tool names** now have at least one successful, bounded ChatGPT-origin invocation documented; the other **nine are unverified from ChatGPT**, not proven forbidden. The remaining set is `binary_patch_inode`, `document_edit`, `pdf_security`, `privileged_action`, `process_checkpoint`, `stream_handoff_close`, `stream_handoff_prepare`, `stream_handoff_write`, `sudo_start`. Several require dangerous in-place writes, privilege, process interruption or cooperative live I/O, so no indiscriminate production trials will be launched merely to increase a number. Prior basic `workdir(reset=true)` and `pty_close(already_exited)` count as successful accepted tool calls but not proof of a state-changing side effect or live process termination.

Authoritative sources: `docs/qualification/dc-parity-v4-model-origin-expanded-writes-20261013.json` and `docs/qualification/dc-parity-v4-model-origin-tool-ledger-20261013.json`. The exact ledger is integrity-checked in CI against the signed-off v4 tool catalog and SHA256-pinned evidence files. Model-origin comes from this assistant's visible tool calls and independent readback, **not** a cryptographic client attestation. Existing DC 9/10 bounded functional-category comparison still applies; `set_config_value` is intentionally not cloned into an unrestricted Hepta configuration/policy writer. No Gateway release or universal privileged-command approval is claimed.


### Six-host model-origin PTY completion + safe shell pipeline — 2026-10-13

Four additional real ChatGPT-origin `pty_start → pty_write → pty_read → pty_close` sequences succeeded on **main, ROG, X230 and AI395** using normal-user Python REPLs. Each printed a unique `*_PTY_MODEL_ORIGIN_OK 42` marker, exited with code 0, retained `output_complete=true` and no capture error. Independent read-only SSH inspection of **each actual target-side terminal archive** matched the MCP full-output SHA256 and byte count exactly. The existing Pocket4 and Mac receipts were already green, so **all six configured hosts now have at least one model-origin interactive PTY success**.

A separate model-origin `shell_start` on `main` executed one **harmless, non-writing Shell pipeline** (`printf ... | grep ...`), followed by authoritative `process_wait` status `succeeded`/exit 0 and `process_read` stdout `HEPTA_SAFE_PIPELINE_OK`. Its durable target-side stdout archive independently matched the exact 23-byte output and SHA256. This extends the prior `id -u` shell smoke to an actual pipe, **not** unconditional approval for arbitrary compound commands, sudo, or writes through Shell.

New immutable evidence: `docs/qualification/dc-parity-v4-chatgpt-six-host-pty-and-safe-shell-20261013.json`. No running native runtime, tunnel or Desktop Commander service was restarted; no business files or user permissions were changed. The exact-head CI on the preceding source commit `b0e6f68` succeeded: [#38287221561](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/38287221561).


### Additional real ChatGPT-origin multihost qualification — 2026-10-13

This conversation directly invoked the **installed, reviewed 50-tool** Hepta Full Operator plugin to create one unique, harmless `/tmp` scratch file each on **Pocket4, ROG, Mac, X230 and AI395** via `text_editor(create)` and configured `ssh://` destinations. Native `view` and `file_info` independently returned exact contents, byte lengths and SHA256s for each target. Further model-origin `text_editor(str_replace)` on Pocket4 and Mac inserted true UTF-8 Chinese and crab-emoji text; both were read back. An **independent SSH read-only verification** on each target independently confirmed the final file size, content marker and hash. No existing business files, sudo, symlink paths or service configuration were touched. Evidence: `docs/qualification/dc-parity-v4-chatgpt-multihost-write-20261013.json`.

The same ChatGPT client then called `process_start` for `/usr/bin/id -u` on **all five remote hosts**, followed each exact native job identity through `process_wait` and `process_read`, and observed exit 0 / `output_complete=true`, with UID **1000** on four Linux hosts and **501** on Mac. The archived output and exit receipts were checked **separately via read-only SSH** on each target. A single transient Pocket4 `process_read` connection failure is preserved: the same job's read-only log was fetched successfully later, with no duplicated execution. On Pocket4 and Mac, ordinary-user persistent `pty_start` sessions launched a Python REPL, accepted exact model-origin `pty_write` marker input and returned it in `pty_read`, then exited cleanly (`output_complete=true`, no capture error; `pty_close` returned `already_exited`). Evidence: `docs/qualification/dc-parity-v4-chatgpt-multihost-execution-20261013.json`.

**Actual operational scope:** five new remote file creations, two remote file edits, five remote normal-user jobs and two interactive remote terminals have now been verified as **ChatGPT-originated tool results**, separate from earlier local six-host tests. This is strong bounded cross-host parity for DC-like file/command/interactivity workflows; it does not establish universal per-command platform approval, full DC option-by-option equivalence, arbitrary sudo/privileged changes, generic remote GUI manipulation, or parity for DC's product-specific `set_config_value`. No advertised tool name or risk annotation was altered to change platform approval.

**This supersedes all older 46/48/49-tool candidate and ChatGPT-refresh-pending statements below, retained for historical accountability.** The current conversation actually loads all **50** native Hepta Full Operator tools (19 annotated read-only, 31 annotated non-read-only). The full native backend and private tunnel are already installed, and the last pre-evidence exact-head GitHub CI [#38280658585](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/38280658585) succeeded. The original 46 tools' definitions remain pinned; four additive file tools retain their reviewed risk annotations.

Actual **ChatGPT-originated** acceptance (not a local stdio/SSH simulation) succeeded in a dedicated `/tmp/hepta-chatgpt-v4-model-acceptance-20261013-0100-6f3a2b` scratch scope: `directory_create`, `text_file_write(create)`, `text_file_write(append)`, `text_file_write(replace)` with exact prior SHA256s, `file_move`, and `directory_move`. The final file was independently read at the relocated path: exact UTF-8 content, SHA256 `46a58a30f025c63efb1c2250c13e992ad47a35a4518eda29eeeabc89c35217c5`, mode 0600, directory mode 0700, and both original pathnames absent. No overwrite, symlink, remote-host or privilege relaxation was used. All four *new tool names* have actual positive receipts now.

Additional actual ChatGPT-originated operations also passed: `process_start` of `/usr/bin/id -u`, `process_wait/read` (UID 1000; exit 0); a normal-user interactive `pty_start` of `python3 -q` with `pty_write`/`pty_read` output `HEPTA_DIRECT_PTY_OK`, followed by `pty_close` (final terminal state exited/output complete); and `shell_start` with **only** `/usr/bin/id -u` followed by a successful job wait/read (UID 1000; exit 0). This proves ordinary safe shell/process/PTY operations can pass the platform: the earlier rejected multi-effect shell and DOCX calls must not be generalized into an unconditional Shell ban. It does **not** establish that arbitrary shell programs, privileged sudo, external-PID signal, all content writers, or all 50 tools are approved. A successful tool call remains subject to the platform's real safety review.

This work **did not** rename write actions, change the user/Workspace Action-control settings, mask truthful annotation flags, send a denied command through another execution route, or restart hepta-runtime/Desktop Commander. Native runtime PID 2064509, Full Operator tunnel PID 2064582 and Desktop Commander PID 2894 were observed active; the tunnel reported ready, successful polling and 57 completed/accepted dispatches. The stdio MCP health field may still report `not_observed` with the modern request flow despite successful real tool calls; do not use that field alone to declare failure.

Primary receipt: `docs/qualification/dc-parity-v4-chatgpt-model-origin-accepted-20261013.json`. The remaining user-visible scope is **honest DC capability parity, not policy evasion**, with multi-host write acceptance, privileged operations and public multi-tenant Cloud Gateway separately gated.

**Additional model-origin verification:** Hepta `text_editor` completed `create`, exact `str_replace`, readback and `undo_edit`; final UTF-8 content and SHA256 were independently checked. `process_cancel` stopped one self-created 30-second sleep job with authoritative state `cancelled` / exit `-15`. `host_processes` returned an exact UID 1000 start identity for a second disposable sleep PID, and `host_signal` delivered SIGTERM with `atomic_identity=true`; the terminal then reported `exited`, code `-15`. This establishes **8 bounded DC core functional categories out of 10** with at least one successful current ChatGPT-origin Hepta action: file write, directory creation, file/directory move, edit, ordinary process launch, interactive process, runtime-owned cancellation, and identity-checked PID signal. It does **not** imply identical DC semantics or permission for arbitrary target PIDs. The remaining DC `write_pdf` category is unqualified from this client; DC `set_config_value` has no general Hepta equivalent by design. Receipt: `docs/qualification/dc-parity-v4-chatgpt-model-origin-expanded-20261013.json`.

**PDF write parity, also ChatGPT-originated:** Desktop Commander `write_pdf` and Hepta `document_write(format="pdf", expected_sha256="absent")` both created their own disposable **one-page PDF** through their original declared tools. The Hepta file was then read back through Hepta `document_read`/`file_info`, and both independent files passed native `pdfinfo` and `pdftotext` checks; the Hepta PDF rendered to PNG successfully. Its SHA256 is `3f0d4b808ffa2afde525f32bacbca411b4e5d7aee6f4d822c7208119c11e3373`. This brings the validated **bounded functional-category** comparison to **9/10** DC core write/execute types with genuine Hepta model-origin counterparts. The one missing core category is DC's product-specific `set_config_value`, for which Hepta intentionally has no generic unrestricted configuration editor. The simple PDF smoke is **not** rich PDF styling or page-edit parity; the original blocked DOCX attempt remains recorded separately. Exact receipt: `docs/qualification/dc-parity-v4-chatgpt-pdf-model-origin-20261013.json`.

## CURRENT: v4 is live server-side, not yet refreshed in ChatGPT (2026-10-13)

This section supersedes the **historical v2/candidate** status descriptions below, which remain as original qualification evidence. The installed authenticated runtime and the Full Operator tunnel now expose **50 tools**, preserving the original 46 exact definitions and adding four genuine, truthfully annotated controller-local file operations: `directory_create`, `file_move`, `text_file_write`, `directory_move`. The source is HEAD `97d3cd67828b33212fd30bcdfefb5eec2862a849`, with successful [exact-head CI #38276849298](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/38276849298). The active runtime/facade/contract release and guarded rollback are recorded in `docs/qualification/dc-parity-v4-live-activation-20261013.json`. Desktop Commander remained running and unchanged.

A fresh **read-only local stdio check against the actually installed v4 facade** returned a valid `server/discover`, the exact 50-tool pinned `tools/list`, and a six-host `host_list`. Every original v1 tool definition still matches; four new names and write annotations are unchanged from the reviewed v4 catalog. This is not a model-origin approval. Receipt: `docs/qualification/dc-parity-v4-chatgpt-refresh-readiness-20261013.json`.

**Current conversation state:** the ChatGPT-side app snapshot is still **46 tools**; `directory_create`, `file_move`, `text_file_write`, `directory_move` are absent from the visible client tools. A post-cutover ChatGPT-origin `host_list` succeeded, showing that the old approved read path still works. A **distinct** text-editor create smoke test in a unique `/tmp` scratch file returned a generic client/tool failure; the file was absent on the host and no positive write receipt exists. Because the platform-side error was generic, it must not be relabelled as either native write success or a proven safety-policy denial. Do not automatically retry the uncertain write.

**Supported next gate:** open [ChatGPT Plugins](https://chatgpt.com/plugins), select the existing **Hepta Runtime Full Operator** connection, choose **Refresh**, and review the exact **50** tools and their original truthful annotations. New actions must be explicitly reviewed and approved under the applicable product/workspace policy; do not fabricate approval by moving them behind an existing tool. Open a **new ChatGPT conversation** and verify the four new names are visible before attempting scratch create/append, directory create, file no-overwrite move and directory no-overwrite move. OpenAI documents both the Refresh/new-conversation flow and frozen custom MCP tool snapshots: https://developers.openai.com/plugins/deploy/connect-chatgpt and https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt. This assistant cannot refresh the authenticated ChatGPT UI using the available server-side tools.

The native six-host tests **do not** waive the outstanding ChatGPT-origin full Shell/PTY/sudo and file-writing checks. Keep the public Cloud Gateway on HOLD until the private client-side qualification passes.


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

## v2 release and controlled activation boundary — 2026-10-12

- **Exact 48-tool source/contract head:** `4b5e0b8db350cac8046d7e86d632fc2c5696e503`. CI [38240469052](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/38240469052) completed **success**. New v2 source preserves all original 46 definitions; the two new operations are truthful, non-shell file primitives.
- **Release build verified:** `target/release/hepta-runtime` SHA256 `cc2e592e8ec330fcbd3bc6c6eb5d1666010430b9f1517c1a60b1b4e1f045fc8b` (6,942,632 bytes). An immutable stage was installed outside the active runtime unit, and the v2 tunnel profile was staged separately. No service is switched merely by staging a file.
- **Real executable acceptance:** the Release binary passed an isolated MCP run with v2 contract and 9/9 checks, including 48-tool discovery and no-overwrite file moves. The same Release executable passed actual six-host SSH/operator tests (main 13/13 with existing sudo; Pocket4, ROG, Mac, X230 and AI395 each 10/10). These are **local-origin native checks**, not ChatGPT-origin write acceptance.
- **Tunnel preflight:** `tunnel-client doctor --profile hepta-full-operator-v2 --health.listen-addr 127.0.0.1:0` returned `RESULT ok`. Old runtime systemd unit, tunnel profile, and tunnel manifest were backed up to private account-owned files before activation. The required coupled upgrade is native runtime binary + pinned v2 MCP tool contract; upgrading only one would fail the exact catalog check.
- **Cutover NOT executed:** the actual controlled service-switch request was rejected by the OpenAI pre-tool safety check. No alternative executor or disguised tool call was used. Follow-up direct state checks prove the native runtime remained PID 2927 with the old `operator-5bb9dade…` binary, Full Operator tunnel remained PID 1270044 on **46-tool v1**, and Desktop Commander remained PID 2894. The tunnel was still ready with control-plane `ok`.
- **Release gate:** 48-tool **candidate code qualified and staged**; live 48-tool **deployment HOLD**. ChatGPT tool snapshot stays 46 until an authorized coordinated cutover and subsequent explicit admin tool scan. Neither the above CI success nor native six-host parity is evidence of ChatGPT client write approval. Public Gateway remains HOLD.

Receipt: `docs/qualification/dc-parity-v2-release-staged-20261012.json`.

## Model-origin v4 seven additional bounded mutators — 2026-10-13

An additional seven distinct state-changing tool names were invoked **directly from this ChatGPT session** through the existing installed 50-tool Hepta app; Desktop Commander was used only as the cooperating I/O owner for a scratch stream handoff and to independently inspect the resulting test files. The prior frozen 22-name ledger is retained unchanged; the cumulative ledger v2 reports **29 of 31 declared non-read-only tool names with at least one positive bounded call**, not 29 tools with universally approved argument and risk combinations.

- `document_edit`: create one scratch DOCX via `document_write`, replace exactly one XML text node using a pinned source SHA256, then read back the final text; independent ZIP and SHA256 checks passed.
- `pdf_security`: inspect one unsigned scratch PDF and explicitly append one **unsigned** metadata revision into a distinct create-only copy. Original PDF bytes remain an exact prefix; no public signature, trust, revocation or certificate-purpose claim is made.
- `binary_patch_inode`: explicitly acknowledged **non-atomic** 3-byte same-inode patch to a 10-byte scratch file using exact precondition version/hash. Native `status` returned `committed`; independent readback verified bytes, SHA256 and inode identity. This cannot be generalized to atomic publication.
- `sudo_start`: execute **only** `/usr/bin/id -u` with non-interactive existing sudo authority on `main`, obtaining actual PTY output `0\r\n` and normal exit. No privileged write or arbitrary sudo command approval is claimed.
- `stream_handoff_prepare`, `stream_handoff_write`, `stream_handoff_close`: a newly created DC-owned consenting fixture voluntarily exported its existing pipes and final pre-handoff output history. ChatGPT called native prepare, sent `5\n` once with an exact request ID, and delivered input EOF. Same disposable child PID and memory hash progressed from total 17 to 22; archived output preserved the original owner history prefix, the broker's final receipt confirms EOF and output completeness, and no unrelated DC session was touched.

The **two unverified tool names remain `privileged_action` and `process_checkpoint`**. All six host profiles advertise zero administrator-configured `privileged_actions`; this is an intentional authority boundary. X230 has pinned CRIU metadata, but one read-only model-origin checkpoint **inspect** on a disposable sleep PID returned `UNAVAILABLE: Connection failed`; the fixture was cancelled through its original runtime job and verified terminal. No checkpoint dump, restore or resume occurred. Neither name is counted as passing.

The installed 50-tool catalog, risk hints, runtime/desktop services and independent DC command blocklist were not modified by these tests. This is model-visible origin in the conversation, **not cryptographically signed model provenance**. Public multi-tenant Gateway stays HOLD pending independent security/product qualification. Receipts: `docs/qualification/dc-parity-v4-model-origin-seven-new-20261013.json` and the hash-linked cumulative `dc-parity-v4-model-origin-tool-ledger-v2-20261013.json`.

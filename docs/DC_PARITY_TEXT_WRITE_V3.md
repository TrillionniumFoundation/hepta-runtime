# Hepta bounded text writing — Desktop Commander functional parity v3

**Status: isolated candidate only; the active private ChatGPT connector remains pinned to 46 tools.**

## Why this operation exists

Desktop Commander provides `write_file(content, mode=rewrite|append)`. Hepta's current 46-tool package has a line-oriented `text_editor`, `batch_edit`, and remote-host-specific `binary_write`, but no controller-local bounded operation for **full UTF-8 file creation, whole-document rewriting, and version-pinned append**.

The additive `text_file_write` tool fills exactly that independent plain-text workflow and is **not** an alias for `shell_start`, `process_start`, `sudo_start`, or a generic command launcher. Its MCP annotations honestly say `readOnlyHint=false`, `destructiveHint=true`, `idempotentHint=false`, `openWorldHint=false`. It must not be used to get around a rejected ChatGPT tool invocation. A hosted app may still refuse this write operation.

## Public tool schema in the source candidate

`text_file_write(path, mode, content, expected_sha256)`

- `mode=create` requires `expected_sha256="absent"`; publish only if there is no entry at the destination.
- `mode=replace` requires the exact lowercase SHA256 digest of the existing UTF-8 bytes, and publishes the new complete content.
- `mode=append` requires the same digest, and produces exactly **old complete content + new UTF-8 content**.
- Input is bounded to **64 KiB**. Existing file reads are limited to **4 MiB** and forcibly stopped if the file grows during a concurrent read; oversized output is refused.
- A created file has mode `0600`. A replacement preserves ordinary permission bits from an account-owned source file.
- No PATH lookup, Shell string, executable, remote URL, network listener, or credential parameter is accepted. This operation requires an existing configured **controller-local** runtime workspace, not arbitrary host filesystem authority.

## Linux native implementation constraints

- Directory walks are fd-relative from `/` with `O_DIRECTORY|O_NOFOLLOW`, rejecting symlinked parents and files.
- Existing destinations must be ordinary files **owned by the runtime account**, have one hardlink, be non-executable and have **no xattrs/ACLs** that a replacement might otherwise erase.
- A controlled advisory directory lock serializes **calls to this publisher**, not arbitrary external writers. The original digest and pathname inode metadata are checked before publication. This is **not a universal external-writer compare-and-swap transaction** and cannot promise atomic isolation from an adversarial process already allowed to mutate the same directory.
- The staging file is created with a random, exclusive name and owner-only permissions. Contents and file metadata are fsynced; publication uses `renameat2` in the same directory, with `RENAME_NOREPLACE` for creates. The parent is fsynced after publication. On failure, the staging path is best-effort cleaned.
- The published pathname is checked against the staged inode before returning a success response. External writes after the response remain possible.
- An uncertain response **must not be automatically replayed**: the original operation might have published. The caller should read the actual file version and digest before deciding on another operation.
- The operation is deliberately not an in-place editor: replace/append exchange the inode, so external open-file descriptors keep referring to the old inode. For long-lived open-file consumers, the original in-place primitives with their explicit caveats are the appropriate tools.
- Currently **Linux only**, controller-local only. There is no symlink, hard-link, cross-filesystem, remote SSH or privileged fallback.

## Three frozen tool catalogs

| Contract | Count | Invariant |
| --- | ---: | --- |
| `deploy/contracts/hepta-runtime-full-operator-v1.json` | 46 | Installed native/tunnel baseline, untouched |
| `deploy/contracts/hepta-runtime-full-operator-v2.json` | 48 | Adds `directory_create` and `file_move`, frozen and previously qualified |
| `deploy/contracts/hepta-runtime-full-operator-v3.json` | **49** | Adds only `text_file_write`; all original 48 schemas and annotations remain identical |

The catalog is a **reviewable protocol contract**, not permission for platform-side writes. No active tunnel or installed native runtime should be modified solely because the staged source built or CI passed.

## Qualification stages

1. Seven focused Rust tests exercise create→replace→append, UTF-8 and mode retention, duplicate/stale SHA refusals, symlinks, hardlinks, executable files, invalid UTF-8, oversized existing files and traversal.
2. Independent temporary authenticated MCP controller tests discover 49 tools, verify annotations and all 48 previously pinned tool definitions, then exercise 12 actual sandbox checks including text writes, stale SHA rejection and out-of-workspace denial.
3. `cargo fmt --all --check`, strict `cargo clippy --locked --all-features --all-targets -- -D warnings`, and `cargo test --locked --all-targets` must all pass on the exact candidate.
4. Exact-head GitHub Actions must pass after wiring the independent test to the reviewed v3 contract.
5. Only an independently authorized, controlled runtime/tunnel upgrade and explicit ChatGPT tool rescan may turn this from a source candidate into a live tool. The earlier 48-tool cutover was stopped by the platform and is **not** treated as authorization to use an alternative tool to perform that cutover.

**Do not claim ChatGPT model-origin write parity before a genuine approved frontend write acceptance.** The accepted benign `workdir(reset=true)` does not establish permission for document, source-code or Shell writes.

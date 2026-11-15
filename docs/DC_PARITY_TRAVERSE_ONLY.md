# Desktop Commander filesystem parity: Linux traverse-only directory correction

**Status: reviewed source candidate; not deployed.** Follow-up to the 50-tool v4 contract. No tool names, descriptions, input schemas or annotations changed.

## Reproduced problem

A Linux user can create entries in a directory with mode `0300` (owner write and search/execute, without read). The prior Hepta fd-relative directory traversal opened every parent with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, which requires read permission and incorrectly returned `EACCES` despite the account's valid entry-mutation rights. Three isolated Rust tests failed before the fix: `directory_create`, regular `file_move` and `directory_move` all incorrectly refused mode `0300` parents.

The code now opens each directory with **`O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`**, retaining its fd-only, no-symlink traversal. Linux kernel `mkdirat` and `renameat2(RENAME_NOREPLACE)` check the actual caller's write/search permissions independently. This change **does not confer file read permission, sudo, or arbitrary execution** and does not alter the workspace allowlist or the atomic non-overwrite requirements.

A new negative test makes the permission boundary explicit: with owner mode `0100` (search but no write), all three operations remain denied and their source/destination entries are unchanged. Existing symlink, missing parent, wrong workspace, same-path, and non-overwrite regressions also remain active. Concurrent modifications by a separate authorized writer are not transactionally excluded.

## Real validation and freeze

- Pre-fix: 3 targeted Rust tests failed with `EACCES`.
- Post-fix: 3 targeted tests pass; one additional negative test covers search-without-write refusal.
- Full Rust: **419 main tests passed**, **8 jobctl tests passed**; 11 long-running/conditional cases remain ignored by existing configuration.
- `cargo fmt --all --check`, strict `cargo clippy --locked --all-features --all-targets -- -D warnings`, and `cargo build --locked` passed.
- Separate ephemeral authenticated MCP controller: **18/18** checks passed, including mode `0300` and `0100` operations and exact frozen 50-tool contract. The actual `server/discover` and `tools/list` payloads passed local published 2026-07-28 MCP JSON Schema checks.
- An initial separate worktree run refused group-writable (`0664`) contract files. The checkout copy permissions were corrected to `0644` and revalidated; no policy was weakened.
- The original v4 source baseline `c5d6ff7` has hosted CI run **#38255168520 successful**. This follow-up's exact-head hosted CI must be checked separately before merging.

Qualification: `docs/qualification/dc-parity-traverse-only-20261012.json`.

**Shipping boundary:** this branch is not currently installed on the six-host production runtime or active ChatGPT tunnel. The live app retains the original 46 tools. Prior platform-side write tool approvals/denials remain independent, and no denied call was submitted through an alternate executor.

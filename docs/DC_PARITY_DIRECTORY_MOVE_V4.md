# Desktop Commander directory move parity — Hepta v4 source candidate

**Status: native source and isolated MCP qualification only.** The deployed ChatGPT Hepta Runtime Full Operator remains the original **46-tool** service. This candidate declares **50** tools, obtained by adding exactly **one** semantic operation to the frozen 49-tool v3 contract. A platform-approved model-origin write of the new tool has **not** happened.

## Genuine Desktop Commander behavioral reference

In this ChatGPT conversation, the installed Remote Desktop Commander was called directly (not simulated over local HTTP) on qian-qi to create a temporary nested directory containing a UTF-8 file, rename the **entire nonempty directory** using its `move_file`, read back the nested file, and list the new root. The old directory was absent, the child file retained its 40 bytes and SHA256 `bbc7b747e162c0bb78b6d36d333743bf5b5d10881761d4311c085fe129689d37`, and the entire unique disposable tree was deleted after evidence capture. This proves that the DC directory-move ability actually worked in this ChatGPT context, not merely that it appears in a schema.

Hepta already offered dedicated, controller-scoped `directory_create`, regular-file-only `file_move` and bounded SHA-pinned UTF-8 `text_file_write` in the **49-tool v3 source candidate**. The existing native `file_move` explicitly refused moving directories. This is a distinct user-facing file management operation, **not a renamed shell or a reinterpretation of a command executor**.

## New v4 operation

`directory_move(source, destination)` moves an **existing directory tree** into an **absent** destination directory path. It reports success only after a Linux `renameat2(RENAME_NOREPLACE)` succeeds. The original pathname ceases to exist. Nested regular files keep their inode and contents; nested symlinks are moved as link entries **without being traversed**. No file contents or metadata are copied.

The operation is deliberately bounded:

- Both paths must pass the existing runtime configuration's local-controller workspace checks. Neither arbitrary SSH endpoints nor remote path aliases are accepted.
- Linux only; path traversal is fd-relative with `O_DIRECTORY|O_NOFOLLOW` for every parent. The source must be a directory at validation time; a file or symlink source is rejected.
- Existing target, absent destination parent, symlinked parents, self-move and descendant move are rejected. `EXDEV` and unsupported filesystem semantics **fail**, with no recursive copy-and-delete fallback.
- `readOnlyHint=false`, `destructiveHint=true`, `idempotentHint=false`, `openWorldHint=false`: moving removes the former pathname and is not safely repeatable without reconciliation.
- No privilege escalation, Shell, generic process invocation, network listener, user policy loosening or input tokens. Existing configured account rights continue to govern.
- Independent concurrent writers are **not transactionally excluded**: the source pathname could be raced by a separately authorized process between the type check and rename. The operation does not promise a universal atomic identity compare-and-swap, persistence across a power cut, or remote host parity.

### Session delta-cache correctness

Hepta's whole-file `view` caches the last full content served by path. Forgetting only a moved **directory** key can leave stale cached entries for nested files. The v4 addition includes `delta::forget_subtree`: on successful directory move, invalidate the directory and all source/target descendant paths in **this MCP session**. A separator-boundary check ensures sibling names such as `old2` are preserved. It is not a cross-session global invalidation guarantee.

A real temporary HTTP MCP acceptance now seeds identical cached content at both old and future destination paths, moves the tree, recreates the old path externally as a fixture, and verifies both subsequent `view` calls return **full content**, never the incorrect unchanged marker.

## Frozen catalog and evidence

| Catalog | Tool count | Role |
| --- | ---: | --- |
| `hepta-runtime-full-operator-v1.json` | 46 | Live installed source baseline, untouched |
| `hepta-runtime-full-operator-v2.json` | 48 | Prior additive directory create/file move |
| `hepta-runtime-full-operator-v3.json` | 49 | Prior bounded text publisher, unchanged |
| `hepta-runtime-full-operator-v4.json` | **50** | Exactly one new `directory_move` entry |

The v4 catalog SHA256 is `63742708c287e8468d73f27ba85ecc6585afd4adcd76d06b618456730cfaf8ad`. The v4 JSON file SHA256 is `d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1`. Native isolated discovery checks that **every v3 tool definition remains byte-equivalent as a JSON tool object**, not just that its name still exists.

Executed qualification:

- **15 native Linux directory/file-operation unit tests** passed, including six new directory-move negative/positive cases.
- **2 extra delta-cache tests** passed (path boundary preservation and actual directory move/recreation cache semantics).
- Full `cargo test --locked --all-targets`: **415 passing main Rust tests and 8 passing jobctl tests**, 11 explicitly ignored.
- Exact source: `cargo fmt --all --check`, strict all-feature/all-target Clippy, and build all completed successfully.
- Existing v3 isolated MCP tests against the v4 candidate: **12/12 passed** with original 49 definitions frozen.
- New v4 temporary authenticated MCP acceptance: **16/16 passed**, including pre-existing v3 contract equality, actual nonempty directory move, independent old/destination cache invalidation, source/target policy refusal and no-overwrite semantics.
- The **actual v4 stdio adapter** was tested against the private temporary native controller: `server/discover` and `tools/list` preserved all 50 definitions. Both response envelopes produced **zero validation errors** against the already saved published MCP 2026-07-28 JSON Schema in the local acceptance environment.
- All fixture native controllers were temporary, with private random tokens and no production state directory. This is **local-source evidence only**.

## Promotion remains gated

The previously attempted **48-tool** service cutover was blocked by the platform safety check and **was not retried by substituting an executor**. No new service transition is inferred from the 50-tool source build. Live hepta-runtime, its ChatGPT tunnel and Desktop Commander remain unchanged. Do not falsely count 50 as currently available in ChatGPT or interpret native acceptance as permission to run blocked tool calls.

Before a future properly authorized deployment: verify exact-head CI, independently review the new schema/permissions, preserve explicit rollback, re-scan the exact frozen catalog in the actual workspace, and obtain genuine model-origin file-management acceptance. The full shell/PTY/sudo/write gate remains HOLD until its actual approved path has passed. The public multi-tenant Cloud Gateway remains unlaunched.

Receipt: `docs/qualification/dc-parity-directory-move-v4-20261012.json`. Original Desktop Commander move proof: `/tmp/hepta-dc-model-origin-directory-move-proof-20261012.json` on qian-qi, with no secrets; the temporary file tree has been removed.

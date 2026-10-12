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

## New exact-source Release + six genuine host acceptance — 2026-10-12 (22:43 +08)

The exact `088a2acbd53c97f482a68f3cc45eca40d9cbb7a3` v4 source has hosted CI **#38260675518 success**. Rather than treating the previous 20:09 Release binary as the new source, a fresh `cargo build --locked --release --bin hepta-runtime` completed. SHA256 **`c64d0406514fd29a16f303fdd5332ad85509e5148620bea6302ccd983080a73a`**, size **6,991,896 bytes**. The immutable native candidate is staged at `~/.local/lib/hepta-runtime/releases/operator-v4-c64d0406514fd29a/hepta-runtime`; a separate, **not-started** candidate tunnel profile `~/.config/tunnel-client/hepta-full-operator-v4.yaml` pins the **50-tool** schema and uses its own unused health port. `tunnel-client doctor --health.listen-addr 127.0.0.1:0` returned **RESULT ok**. No private credential content was copied into the release.

Re-executed on the **new Release executable**, not only the debug candidate:

- Existing 46 + four additive file tools: authenticated isolated MCP `12/12` checks passed. All old frozen schemas and truthful hints are retained.
- Directory move, existing-root confinement, write/search-only UNIX directory rights, no overwrite, path/cached-view correctness: **18/18** checks passed, including two authentic 2026-07-28 `server/discover`/`tools/list` JSON Schema responses with **0 errors**.
- Four 8-way concurrent text-write rounds: every round permitted only one SHA-pinned winner, with the other seven rejected. Independent create-only and overwrite conflict tests also passed: **6/6** checks.
- **Six real SSH operator targets** with separate disposable controllers and the exact frozen Release: main `13/13` (actual existing sudo), Pocket4 `10/10`, ROG `10/10`, Mac `10/10`, X230 `10/10`, AI395 `10/10` = **63/63**. The three protected services retained the exact same PIDs and active states throughout.
- Four offline source/staging tests passed, confirming v1→v4 monotonic tool additions and refusal of mismatched, writable or symlinked staged artifacts. The six-host test script and the release-only stager are versioned and Python syntax-checked in CI. The hosted CI does **not** claim to possess or execute the six private SSH targets.

This is an **immutable pre-deployment stage**, not the previously blocked live switch. The existing installed runtime remains native SHA256 `5bb9dade…` and the existing ChatGPT app remains at **46 tools**. No blocked write or service-switch request was retried using an alternative executor, no Desktop Commander lifecycle was changed and no public Cloud Gateway was started. Live installation, new schema scan and model-origin actual file writes remain separately gated.

Full receipt: `docs/qualification/dc-parity-v4-six-host-release-staged-20261012.json`. The candidate stays independent until a permitted service cutover; the prior live profile and runtime binary have not been overwritten.

## Source root boundary hardening — 2026-10-12

A private **two-root controller MCP** demonstrated a real missing invariant: v4 accepted `directory_move` with its source exactly equal to one configured controller workspace root, relocating that entire root into a second authorized root. The kernel atomic rename was correct for its requested paths, but that move invalidated a configured workspace authority boundary. The tested root held only a disposable marker file. The original failure (old immutable Release) is retained; it must not be relabelled as a passing security case.

The corrected source now checks the canonicalized source against **every configured controller workspace root**, rejecting a move when any configured root is the source directory itself or lies below it. This includes nested workspace roots inside an otherwise authorized parent. It uses the administrator's existing config only; no new shell/OS privileges, tool names or annotations are introduced. Existing fd-relative Linux `RENAME_NOREPLACE` still guards the real operation and symlink traversal.

The new independent `tests/dc_parity_workspace_root_guard_acceptance.py` explicitly recreates this multi-root situation, proves the two denial cases, and proves ordinary directory/file moves inside a workspace continue to succeed. The current fix is a controller-root policy guard, **not** a universal race-free identity comparison against an unrelated privileged writer able to rename directories concurrently. Production runtime and the ChatGPT-approved 46-tool contract remain unchanged.

## Root guard exact-source release qualification complete — 2026-10-12

The multi-root vulnerability reproduced against the previous v4 Release is closed in source commit **`874e801b92c1ec2fb3093b1934a5535a12eb1e64`**: `directory_move` now refuses moving either the configured workspace root itself or an authorized ancestor containing any other pinned workspace root. This is enforced before the existing fd-relative `RENAME_NOREPLACE` operation. Ordinary directory and file moves remain intact. The 50-tool JSON contract is **unchanged** (`d36610d575146805f4c02d89210abd360b4d42acc8736d1966f20d0d724704b1`).

The exact-source hosted GitHub CI [**#38268295479**](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/38268295479) finished **success**, including the newly wired isolated multi-root regression. Independent local Rust results were 420 main + 8 jobctl passing, strict Clippy/fmt passing. A fresh immutable Release was built (SHA256 **`db181570e9e65f9e6a962d013dd4880eedc5b0cda1c71508f84388a4a8d8072b`**) and staged separately at `~/.local/lib/hepta-runtime/releases/operator-v4-db181570e9e65f9e/hepta-runtime`; doctor reported `RESULT ok`. The same actual Release passed 5 root-guard, 12 file, 18 directory/MCP, 6 concurrent-write checks, **12 additional root-guard repetitions × 5 = 60/60**, and all six real SSH targets **63/63**. Runtime PID 2927, Desktop Commander PID 2894 and Full Operator tunnel PID 1270044 remained unchanged.

This is **staged, NOT activated**: the current app still has 46 tools, and ChatGPT model-origin `shell_start`, PTY, sudo and write authorization is not claimed. No earlier blocked service cutover was retried via another executor. The public Cloud Gateway remains HOLD. See `docs/qualification/dc-parity-root-guard-release-six-host-20261012.json`.

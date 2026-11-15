# Hepta Runtime — AGENTS.md

Policy-enforced multi-host Rust MCP runtime derived from Octofs, with native filesystem and artifact operations, durable process ownership, and optional Python/Java helpers for configured routes. Supports stdio and streamable HTTP, including native SSH/SFTP remote file access. Rust 1.95.0 · rmcp 3.x · tokio · axum.

## Commands
- Toolchain: Rust **1.95.0**, cargo-nextest **0.9.137**; see `.agents/release.md` for the current CI gates.
- Build: `cargo +1.95.0 build --locked` · Release: `cargo +1.95.0 build --locked --release --bins --examples` · Dev run: `cargo +1.95.0 run --locked --bin hepta-runtime -- mcp` (stdio; add `--bind 127.0.0.1:12345 --auth-token-file /private/path/http.token` for HTTP; `RUST_LOG=debug` for logs)
- Format: `cargo +1.95.0 fmt --all` · Check: `cargo +1.95.0 check --locked --all-targets --all-features` · Lint: `cargo +1.95.0 clippy --locked --all-targets --all-features -- -D warnings`
- Test: set `umask 022` as CI does, then run `cargo +1.95.0 nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast` (filter one test with `-E 'test(test_view_file)'`). Some tests modify process-global state and require separate processes.
- Run check, lint and tests again with `--no-default-features` in place of `--all-features` to cover library use without `remote-fs`.
- Coverage: `make coverage` (needs cargo-llvm-cov + llvm-tools-preview; excludes `*_tests.rs`)
- This checkout auto-syncs to the dev server — run build/test/clippy there (`ssh dev`), not on this machine.

## Where to look
| Task | Start here |
|------|------------|
| Add / change an MCP tool | `.agents/tool-authoring.md`, then `src/mcp/server.rs` (Params + `#[tool]`) → `src/mcp/fs/*.rs` (execute fn) → `src/mcp/fs/mod.rs` (re-export) → tests |
| Tool schemas & model-facing descriptions | `src/mcp/server.rs` — Params structs and `#[tool(...)]` blocks |
| view / create / undo / path resolution | `src/mcp/fs/core.rs` + `src/mcp/fs/file_ops.rs` |
| str_replace / batch_edit internals / file locking | `src/mcp/fs/text_editing.rs` |
| Directory listing, glob + content filtering | `src/mcp/fs/directory.rs` + `src/mcp/fs/search.rs` |
| Delta views / view cache | `src/mcp/fs/delta.rs` — `note_write`, `note_create`, `render_whole_file` |
| Background jobs / MCP resources / subscriptions | `src/mcp/fs/background.rs` + handlers in `src/mcp/server.rs` |
| SSH/SFTP paths, auth, connection pool | `src/mcp/fs/remote.rs` — read `.agents/remote-ssh.md` first |
| Line ids (`N:hh`) / stale-id verification | `src/utils/line_hash.rs` |
| Truncation / token budgets | `src/utils/truncation.rs` |
| Hints appended to tool responses | `src/mcp/request_ctx.rs` (`push_hint` → `append_hints`) |
| Startup, transports, shutdown cleanup | `src/main.rs`, `src/cli.rs` |

## Conventions
- Hard tabs (`rustfmt.toml`), default 100-col width — `cargo fmt` before done.
- No inline test modules in production files. Unit tests: sibling `<module>_tests.rs`, wired with `#[cfg(test)] #[path = "<module>_tests.rs"] mod <module>_tests;`. Cross-module integration tests: `src/mcp/fs/fs_tests.rs`.
- Every `.rs` file starts with the Apache 2.0 header — `Copyright 2026 Muvon Un Limited`; check the year when touching files in a new calendar year.
- Async file I/O only via `tokio::fs`. Errors: `anyhow::bail!` for validation exits, `.context()` on propagation; no `.unwrap()`/`.expect()` outside tests and OnceLock init.
- `execute_*` functions are pure: everything arrives via `&McpToolCall` (incl. `call.workdir`); no ambient reads except the explicit registries (locks, history, view cache, SFTP pool).
- Comments explain why, not what; module-level doc comment on every file.

## Done
- `cargo +1.95.0 fmt --all -- --check`, the locked all-target check/lint/nextest commands above in both feature configurations, and `cargo +1.95.0 build --locked --all-features --release --bins --examples` — all exit 0, run on the dev server. The additional Python/reference and shipped-binary gates are listed in `.agents/release.md` and `.github/workflows/ci.yml`.
- New/changed behaviour has tests (sibling `*_tests.rs` units + `fs_tests.rs` integration, happy path and error cases); copyright header present on every touched `.rs` file

## Gotchas
- Tool schemas/descriptions live in `src/mcp/server.rs`; execute logic in `src/mcp/fs/`. `functions.rs`, `mcp/shared_utils.rs`, `utils/glob.rs` do **not** exist — stale references from an older layout.
- Shell misuse gate (`detect_shell_misuse`, `fs/shell.rs`) is nuanced: pipelines are not split; read-only `sed`/`awk` pass; `sed -i`, content writes into the workdir (`cat >`, `echo >`, `tee`) and a read program (cat/grep/find/ls) starting any command — alone, in a chain or as a pipeline head — are rejected; a read as a later pipe stage passes; a write to a scratch path outside the workdir runs with a hint; `ssh host 'cmd'` bodies are checked recursively. Preserve this contract when touching it.
- Every server-side write must keep the delta cache truthful — go through `delta::note_write` / `note_create`, or whole-file views serve wrong deltas.
- `shell` always runs locally and bails on a remote workdir; join remote paths via `PathSource`, never `PathBuf::join` (it inserts `\` on Windows and corrupts URLs).
- RSA SSH keys are unsupported by design (RUSTSEC-2023-0071) and russh uses the `ring` backend because Alpine/musl builds have no cmake — do not "fix" either.
- Outer `std::sync::Mutex` in `FILE_LOCKS` is never held across `.await`; `resolve_path` does not canonicalize (files may not exist yet) — canonicalize only for lock keys.
- Register every spawned shell child via `register_child` so SIGTERM/EOF cleanup kills its process group; job output reads are tail-capped (`MAX_TAIL_BYTES`).

## Never
- Use `std::fs` inside `async fn` — `tokio::fs` exclusively
- `.unwrap()`/`.expect()` in non-test, non-OnceLock-init code
- Skip the copyright header on new `.rs` files
- Add a dependency before checking whether an existing one covers the need
- Define inline `mod tests` in production files
- `git add` / `git commit` — leave changes unstaged; the maintainer commits
- Hand-edit `CHANGELOG.md` or release-bump `Cargo.toml` casually — see `.agents/release.md` first [UNCONFIRMED]

## References
- `.agents/architecture.md` — module map, execution flow, state, shell lifecycle; read when work spans modules
- `.agents/tool-authoring.md` — read before adding or changing any MCP tool
- `.agents/remote-ssh.md` — read before touching `fs/remote.rs` or path resolution
- `.agents/release.md` — read when preparing a release or changing CI/publishing

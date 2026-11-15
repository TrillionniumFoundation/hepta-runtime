# Desktop release-only continuation, 2026-11-04 r2

This archive records a successful **release build only** on the desktop operator host. The original durable job is `1a1a5ae47bf-fc05-20a2`. Its four explicit commands exited with code 0, and its final record confirms complete, durable output and an exit-file witness.

The `qualified: true` field in [the original runner result](integrated-release-r2/qualification.json) applies only to [this four-command plan](integrated-release-r2/plan.json). This plan did not run tests, Clippy, formatting checks, the complete feature matrix, or real-engine qualification. The nextest command only queried the version.

## Commands and retained logs

| Command | Exit | Seconds | Original log |
| --- | ---: | ---: | --- |
| `rustc --version --verbose` | 0 | 0.028 | [rust-version](integrated-release-r2/00-rust-version.log) |
| `cargo --version` | 0 | 0.014 | [cargo-version](integrated-release-r2/01-cargo-version.log) |
| `cargo nextest --version` | 0 | 0.029 | [nextest-version](integrated-release-r2/02-nextest-version.log) |
| `cargo build --locked --all-features --release --bins --examples` | 0 | 489.664 | [release](integrated-release-r2/03-release.log) |

The plan fixes `CARGO_BUILD_JOBS=4` and the explicit target directory. The retained [runner source](run_frozen_commands.py) has SHA-256 `f7f449dbcbd7705876c7cc953937411ad07d521117285db2159e646a1942dec1`. See the plan and original request for the complete invocation and environment.

[progress.json](integrated-release-r2/progress.json) is the original intermediate snapshot and still says `qualified: false`; the runner wrote it before final input verification and binary freezing. It has not been rewritten to match the final result.

## Frozen inputs and output identity

| Group | Files | SHA-256, identical before and after the build |
| --- | ---: | --- |
| Source | 295 | `9d08a4cc6b6c89f4db47eb300af5e54dd44092082434c93b1dee954c30b2209a` |
| Verification | 613 | `b783c4f05a5c7f614ee7150ecc66bb4fe25f1cfd8ed548723e405e4612b6baa4` |

The full [before](integrated-release-r2/inputs-before.json) and [after](integrated-release-r2/inputs-after.json) inventories are retained byte for byte. They bind content, including uncommitted additions, beyond baseline commit `310add6db47bcfbed3545432eb528a72f5eb6dcd`. Rust unit-test files under `src/` belong to the runner's source group.

The frozen executable is **17,820,288 bytes**, SHA-256 `4da25b9b865ef262878098d3d97b5e0c70f44bc83192d4abb4c8d1888fb0dd5d`. It remains outside this repository archive; the manifest records its exclusion and identity. An executable being built does not establish its runtime behavior.

## Fixture application record

The [v2 application receipt](fixture-v2-application/receipt.json), [patch](fixture-v2-application/request-audit-order-fixture-v2.patch), and its complete before/after input inventories are preserved. The receipt identifies `src/mcp/runtime/request_audit_tests.rs` as the only changed source file and confirms unchanged production `request_audit.rs`. The fixture establishes the ordering conditions asserted by three tests and adds a small same-millisecond ordering/cursor regression without changing production sorting or capacity. Applying the patch itself did not execute tests.

The receipt also records two documentation corrections that distinguish the Rust browser worker from its existing Python durable owner and distinguish the Ghidra Rust worker from its Python launcher and external Java/native engine. Those documentation records do not expand runtime qualification.

## Relationship to other qualification

The original desktop 35-command job `1a1a537153b-fc05-1ae4` timed out after 34 completed commands and remains incomplete. This separate release-only continuation does not replace its raw failure/timeout evidence or convert it into a passed matrix.

The complete Ubuntu 24 matrix on the same source/verification inputs is a separate run. Browser, Ghidra/JADX, JavaScript cancellation, and other real-engine/runtime observations need their own receipts bound to the actual executable. This archive does not assert those outcomes, isolated-host coverage, or full REA parity. The compatibility ledger's OPEN/PENDING states are unchanged by this archival operation.

## Original evidence and archive integrity

The `original-job/` directory contains the original request, launch/owner/child records, terminal record and witness, raw stdin, and stdout/stderr. They were copied as bytes without JSON reserialization, preserving the original representation of all numeric and request-identity fields. `stdin.bin` is the original filename for a verified UTF-8 script, not an executable payload.

The original request digest is `472b483998c716ac16c3d3214b48dfb768f8b1a5d81ecd55945ac9c2e1637154`. The exit witness matches the SHA-256 of the exact retained exit bytes; original log lengths agree with the terminal record. The original supervisor implementation and its empty lock files were outside this requested records/stdin/log selection and are not included.

[artifact-manifest.json](artifact-manifest.json) covers every archive file except itself, with origin, byte count, and SHA-256; it distinguishes 24 byte-exact original files from generated explanatory files and records the excluded executable. [archive-validation.json](archive-validation.json) records the bounded credential/type preflight and byte/hash verification. No executable, database, or detected usable credential was copied. The credential scan is a bounded pre-publication check of these selected files, not a general secrets audit.

Archiving did not run builds/tests, change source/tests/scripts/CI/compatibility data, stage files, or publish anything.

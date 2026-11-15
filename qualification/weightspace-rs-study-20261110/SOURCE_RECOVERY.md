# Research-only weightspace-rs source preservation

The code and test fixture files in this directory are restored byte-for-byte from the ChatGPT Library archive `weightspace-rs-source-and-evidence.tar.gz` (2026-11-07). They are not installed into HeptaRuntime, registered as MCP actions, or granted live model-update authority.

The `upstream/` subtree is a retained source snapshot from `TrillionniumFoundation/hepta-runtime` PR #94 at `bc38fb82244b946907886704b3c677bf00761cb9`; that code is already present on GitHub. The newly preserved component is the independent `src/` small research harness implementing bounded F32 projection and confirmation/rollback controls.

Archived execution claim (NOT re-executed by this GitHub recovery): 62 passed, 1 ignored using Rust 1.99.1, an offline `serial_test` shim, and a different cached `num-bigint` version from upstream. Missing independent holdout, native official dependency closure, MCP transport, durable split custody, production integration and full end-to-end benefit. The archive retains complete private evidence logs which are intentionally omitted here to avoid exporting machine traces. This is DRAFT / HOLD_NO_GO.

Run from this nested Cargo directory to reproduce with a separately qualified toolchain and dependencies; inspect `README.md` first.

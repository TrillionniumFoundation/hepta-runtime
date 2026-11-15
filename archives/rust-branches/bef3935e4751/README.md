# Preserved Rust branch variant

Original branch: `codex/native-runtime-remote-fs-feature-20261028`. Original commit: `bef3935e4751fae62f5139fda94409a571c5af6f`.

Current optional remote-fs library and native entry retain exact request identity, no-relaunch reuse and bounded terminal proofs. The newer independent SSH worker owns the static callback/guard through physical spawn, child reaping and uncertain-child quarantine, with cancellation regressions. Preserve old native variant without weakening the later owner lifetime.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

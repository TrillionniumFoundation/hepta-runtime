# Preserved Rust branch variant

Original branch: `dot/runtime-idempotency-host-lanes-20261023-gpt6`. Original commit: `8f0291bd6ae0db6b06f133f185d88b303ce20367`.

Current registry and host-scoped native owners include newer duplicate-key, nofollow and durability validation. Preserve this earlier stack and its tests without replacing those later owners; separately reconcile missing physical-CWD checks in current code.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

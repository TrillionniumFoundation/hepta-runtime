# Preserved Rust branch variant

Original branch: `experiment/x230-r34-cancel-reserve-20261106`. Original commit: `a649198a048475b1d1bbaf1656b7c9a33eb869d7`.

R34 failed the original C8 throughput gate and was not adopted; tools/x230/20261106/r34/README.md. Its fixed cancellation admission reserve must not override the later explicit unbounded concurrency policy.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

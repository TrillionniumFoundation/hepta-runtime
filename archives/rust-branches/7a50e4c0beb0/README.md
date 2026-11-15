# Preserved Rust branch variant

Original branch: `experiment/x230-compiler-20261105`. Original commit: `7a50e4c0beb0b23a61b7372c24966cf80fc65b99`.

R25 passed qualification but failed observation performance and was not adopted; tools/x230/20261105/r25/README.md retains both failed and passed attempts. Preserve its exact source and evidence without activating rejected compiler/runtime changes.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

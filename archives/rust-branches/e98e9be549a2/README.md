# Preserved Rust branch variant

Original branch: `fix/runtime-dual-source-merge-ci-proof-20261022`. Original commit: `e98e9be549a26cec3d10be19df769d6cf3f4ec82`.

Current CI supersedes this earlier exact-head/merge proof workflow. Preserve original contents and ancestry while retaining current source-identity checks and all-target validation.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

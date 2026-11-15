# Preserved Rust branch variant

Original branch: `feature/execution-shadow-abi-20261023`. Original commit: `b2fd2ab2583601c056c6244fb1d6282f1e8be67e`.

Current execution.rs retains the read-only canonical shadow ABI and adds deny_unknown_fields for both record and FinalUse envelopes. Preserve original API source without dropping current stricter wire validation or registering duplicate tools.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

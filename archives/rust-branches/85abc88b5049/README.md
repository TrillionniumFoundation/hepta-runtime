# Preserved Rust branch variant

Original branch: `fix/runtime-host-start-guards-20261023`. Original commit: `85abc88b5049cfc1ab8f3b547687cc17614f56e8`.

Current host-scoped and full-registry duplicate-owner validation implements this historical intent. Preserve exact earlier guard/tests rather than replacing the newer retained native launch owner.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

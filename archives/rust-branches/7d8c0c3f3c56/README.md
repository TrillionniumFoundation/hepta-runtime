# Preserved Rust branch variant

Original branch: `dot/runtime-http-auth-token-fence-20261021`. Original commit: `7d8c0c3f3c56540847d4c00132f54ae8b684b16c`.

Current token loader preserves private-file/no-follow/size validation. Consolidation additionally applies universal HTTP token and loopback enforcement with real middleware regressions; retain the older exact implementation as provenance.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

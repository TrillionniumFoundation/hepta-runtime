# Preserved Rust branch variant

Original branch: `dot/runtime-policy-cwd-traversal-20261021`. Original commit: `a38239a12f9ea050e53fac05647311a42d816645`.

Explicit remote parent traversal rejection is present in current config; consolidation also fixes local symlink/parent filesystem semantics. Retain the older path-only source without replacing these stronger checks.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

# Preserved Rust branch variant

Original branch: `fix/rea-unified-pr-ci-admission-20261103-gpt6`. Original commit: `c4b9830d3f9744177ed509b280ee662a61de83ae`.

Current CI already covers the unified stack and now main, with locked head/merge checks, both feature modes and isolated nextest. Preserve older branch-filter proposal without overwriting current qualification commands.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

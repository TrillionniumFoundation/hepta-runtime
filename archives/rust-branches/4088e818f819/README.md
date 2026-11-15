# Preserved Rust branch variant

Original branch: `codex/runtime-inventory-background-20261109`. Original commit: `4088e818f8194c62dffd6895f9316762b4b2d2d3`.

Superseded by the adopted #116 unbounded-baseline inventory implementation at 8d9f03692359176945c8628215e70f4524c3b86c. Preserve #115 original bounded-worker/four-entry variant but do not reintroduce those execution admission ceilings.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

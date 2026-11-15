# Preserved Rust branch variant

Original branch: `fix/runtime-ci-dual-source-qualification-20261023-gpt6`. Original commit: `9591ade0ddd4a96891a4dcdb1001467552d5e63b`.

Retain current separate exact-head and prospective-merge gates with both feature configurations and nextest isolation. Archive this superseded earlier workflow without weakening or duplicating active gates.

The exact original commit is a merge parent and remains reachable from main. Divergent inputs are retained under `files/`; new historical evidence keeps its original path. This archive is not a Cargo workspace member or active workflow. Its old tests and source describe the original candidate, not a qualification of the consolidated runtime. See `manifest.json` for every changed path and original Git blob.

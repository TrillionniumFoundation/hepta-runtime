# WSP source projection refresh — 2026-11-24

The exact-head Runtime CI at `25250e85439f568f61fcceae246f20ac34ff8768` passed
2,650 isolated Rust tests and failed the subsequent frozen REA mapping check.
The stored source projection had stale hashes for three already mapped files:
`src/cli.rs`, `src/main.rs`, and `src/mcp/rea_model_worker.rs`. The last includes
the earlier model-worker ownership change; this refresh changes no Rust behavior.

This record preserves the original ledger bytes and regenerates only the source
projection with the existing `published_pin`, `snapshot_rows`, and
`assemble_ledger` functions. The immutable catalog projection matches its
existing pin. No raw upstream catalog, executable, provider, or behavioral oracle
was rerun or reauthenticated. `raw_reference_authenticity` remains
`NOT_REVERIFIED`; this is a repository consistency correction.

Only `runtime.source_files` and `runtime.source_manifest_sha256` differ. All tool
rows, the map, environment, generator, verification tests, gates, and summary are
unchanged: 229 published tools, 0 qualified and 229 OPEN.

`source-projection-refresh.json` records previous/current ledger hashes and each
changed source record. `mapping-checks.json` records the actual ledger regression
suite and the two existing CLI checks: normal mapping exits 0, strict parity
exits 3 as required. No gate is weakened or relabeled as full REA parity.

The full CI for the new commit remains a separate requirement. The old run's
2,650 passing tests do not claim the downstream release and no-default-feature
gates, which were not reached after its mapping failure.

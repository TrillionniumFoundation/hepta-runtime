# Current concurrency source projection — 2026-11-09 r3

This checkpoint uses the existing `published_pin`, `snapshot_rows` and
`assemble_ledger` projection. Only `runtime.source_files` and
`runtime.source_manifest_sha256` change. The 229 tool rows, their qualification
fields, 34 interfaces, MAP, INPUTS and ENVIRONMENT remain exactly unchanged:
229 OPEN and zero qualified. No historical behavior was requalified.

The original r1 ledger archive (SHA-256
`489bf18663c8ff4cfae8d7ab81b143d0528bcf693033547d03b3d307de73fefa`)
and the r2 lifecycle checkpoint remain unchanged. This directory archives the
intermediate ledger bytes before the final projection and chains the r2 receipt.

The mapped request-start description no longer states an eight-per-host or
four-per-caller execution ceiling. The current APK regression explicitly
permits one response-text deviation: the eleven frozen per-input parser
capacity cases now advise selecting an input within the reported parser bounds
instead of waiting for an active analysis. Every other field is still compared
exactly. Both frozen APK fixture files retain their exact baseline bytes. This
text correction does not claim parity with that historical response or qualify
a new runtime binary.

`mapping-checks.json` records the actual current `check-mapping` exit 0 and
strict `check-mapping --require-parity` exit 3. These verify the source
projection, not original-provider execution or raw-reference authenticity.

Current behavior is described by [Concurrent execution](../../CONCURRENCY_POLICY.md).
The full changed path list and before/after hashes are in
`source-projection-refresh.json`.

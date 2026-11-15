# REA compatibility source projection refresh — 2026-11-09

This archive preserves the exact previous compatibility ledger before refreshing
its source mapping for the [concurrent execution policy](../../CONCURRENCY_POLICY.md).
It is a repository consistency record. No upstream package, external provider,
native binary or operation behavior was requalified by this refresh.

## Preserved input

[REA_6_8_0_LEDGER.before.json](REA_6_8_0_LEDGER.before.json) contains the original
ledger bytes: **779162 bytes**, SHA-256
`489bf18663c8ff4cfae8d7ab81b143d0528bcf693033547d03b3d307de73fefa`. Its runtime source-manifest digest was
`8020466060e3aa04331ded6c00fb0df5443637d81ef6b7b5b29ce51de5840583`.

The new [current ledger](../../rea-native/compatibility/REA_6_8_0_LEDGER.json)
was produced with the existing `published_pin`, `snapshot_rows` and
`assemble_ledger` functions in `scripts/rea_compatibility_ledger.py`.
The immutable catalog projection was checked against its existing pin before
assembly. Raw references were **NOT_REVERIFIED**.

Only `runtime.source_files` and `runtime.source_manifest_sha256` changed.
The 24 changed file records comprise 20 existing source/test bindings and four
current documentation pages whose parser-count descriptions were corrected.
The six current documentation pages link to the execution policy; the remaining
two pages are outside this existing source-manifest selection.

The new ledger is **779163 bytes**, SHA-256
`0b52b1742d2bf6e7cf24c1214614e785b0c59034a2c07f53c4caa240ebe6d871`; its runtime source-manifest digest is
`0c1ab850999957ebbc9b2864e666e687cb2df0c469b0e850d83ce2a6a53fd7ca`. These values describe this refresh snapshot;
a later source change requires a new mapping projection.

## Unchanged qualification

All 229 tool rows, 34 interface names, behavior gates, `qualified_scope` text,
summary counts and other top-level fields compare exactly equal to the archived
ledger. The existing INPUTS, CAPABILITY_MAP, ENVIRONMENT and generator bytes are
unchanged. No historical qualification receipt was edited or replaced.
The result remains **229 OPEN operations and 0 qualified operations**.

[The refresh manifest](source-projection-refresh.json) records both ledger
identities, the exact changed paths and unchanged input hashes.
[Mapping checks](mapping-checks.json) retain the actual commands, output and
expected exits: `check-mapping` returned **0** and
`check-mapping --require-parity` returned **3**. These exits establish current
mapping consistency and preserve the open parity gate; they do not establish
behavioral equivalence or deployment status.

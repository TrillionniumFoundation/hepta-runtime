# Supplemental concurrency source projection — 2026-11-09 r4

This checkpoint preserves the exact **pre-unbounded-r4** ledger and updates the
current REA source projection after the supplemental removal of task and
retained-record admission gates. It uses the existing `published_pin`,
`snapshot_rows` and `assemble_ledger` functions. All **229 tool rows remain
OPEN, with zero qualified tools**; the 34 interfaces and all qualification
fields are unchanged. No upstream behavior was rerun or qualified, and the raw
reference inputs were not reauthenticated.

## Why there is another checkpoint

The [initial concurrency verification](../concurrency-20261109/README.md) binds
implementation commit `826c462699a27ed6afa83298440acb732b726af5` and its recorded
binaries. A later review found these additional admission gates in that source:

| Path | Omission corrected after the initial verification |
| --- | --- |
| Isolated systemd jobs | `TasksMax=64` limited each job's processes and threads. The helper also refused a new job after 128 registry directories, counting active and completed jobs alike. |
| Search jobs and target Python worker | A total of 1024 retained search receipts could block a new search. |
| Resident weight sessions | A total of 1024 retained session intents could block a new session. |
| Python operator facade | A total of 4096 legacy pending or retired request IDs could block another request. |

The later changes remove these count gates while preserving the original
ownership records and request identities. The unused, unregistered
`retention_limits.rs` and `retention_limits_tests.rs` files were also removed.
The current policy is documented in [Concurrent execution](../../CONCURRENCY_POLICY.md).

The earlier Rust suite and Mac/ROG native probes **do not verify these later
changes**. Their original audit files are unchanged and are hashed in this
checkpoint's manifest. This checkpoint does not claim a new runtime build,
deployment, throughput result, hosted CI result or external-tool qualification.
Validation of a later implementation must bind its own source and binary
identity.

## Exact mapping scope

Only two already-mapped files changed in the current REA projection:

- `src/bin/jobctl.rs`
- `src/jobctl_tests.rs`

Only `runtime.source_files` and `runtime.source_manifest_sha256` changed in
the generated ledger. It still contains 318 mapped source/test files. Every
tool row, every other top-level field and every other runtime field is exactly
equal to the archived ledger. MAP, INPUTS, ENVIRONMENT and the generator remain
unchanged.

The search, weight and facade source/test changes are outside this existing
REA mapping. The manifest lists their before/after hashes separately; it does
not add new REA coverage for them. The two deleted unused files were absent
from both the previous and current source mapping, MAP and INPUTS, so no
mapping entry needed removal. Their historical source and qualification
references remain unchanged.

## Preserved bytes and identities

| Item | SHA-256 |
| --- | --- |
| Archived ledger before this refresh | `b58bc5059c8d37b8ce5aa1764d696db77a50c92e7b2a0d25b3cc85e8286131c2` |
| Current ledger after this refresh | `2c7005526589b81609415b415d37e2892491cf6949e63d7a62b0a682cc0a48b0` |
| Previous mapped source manifest | `59b35e795f256bee543d12086c3b7aef9c8baa8aeab9f34fc0daced2a21c4839` |
| Current mapped source manifest | `c3950c5241041224e3dda49c5a4814776c3ab66aafccbc12a2e5bc51a0f7d495` |

The original ledger is stored as
[REA_6_8_0_LEDGER.before.json](REA_6_8_0_LEDGER.before.json), with its exact
779,164 bytes preserved. The
[refresh manifest](source-projection-refresh.json) chains the r3 receipt,
records the two mapped source changes and the other runtime changes, and
hashes all 13 unchanged files in the r1–r3 checkpoint directories. It also
binds the unchanged initial concurrency audit. Historical observations are
not rewritten to describe the supplemental implementation.

## Checks performed for this checkpoint

| Command | Observed result |
| --- | --- |
| `python3 -B scripts/rea_compatibility_ledger.py check-mapping` | Exit 0; mapping PASS; 229 OPEN, zero qualified; raw-reference authenticity NOT_REVERIFIED. |
| `python3 -B scripts/rea_compatibility_ledger.py check-mapping --require-parity` | Exit 3, as required while the 229 upstream operations remain OPEN. |
| `python3 -B tests/rea_compatibility_ledger_tests.py -v` | Exit 0; 29 tests passed. |

[mapping-checks.json](mapping-checks.json) preserves both mapping command
results. [ledger-tests.log](ledger-tests.log) preserves the actual ledger test
output; its hash and command are recorded in the refresh manifest. These
checks establish local source-mapping consistency and enforce the existing
qualification boundaries. They do not execute the new job workloads or
substitute for final runtime verification.

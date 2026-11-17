# Historical aggregate recovery

## Result

The retained historical aggregate and both originally skipped evidence-control domains are closed by independent read-only qualification. The final join ran at source commit `3810ec867aad52d1d780c76303abc645f7cc3a0f`, workflow run **44022114623**, job **133833777644**, and returned `RETAINED_AGGREGATE_AND_PENDING_CONTROLS_CLOSED`.

The original run **43944061609** and all ten failed recovery attempts remain recorded as failures. No HIA or Rust semantic process was repeated. No UNKNOWN task was restarted, no original source pin was rebound, and the main integration branch was not changed.

The machine-readable record is [HANDOFF.json](HANDOFF.json). It contains all source/blob maps, artifact identities, prior failures, scope limits, and the exact integration order. [TERMINAL.json](TERMINAL.json) and [final-job.log](final-job.log) retain the final actual result and complete job log.

## Retained original domain

The original failed report is 94,614,535 bytes, SHA-256 `6159169d8c0763d2418c8f625e5cd67099a06179f69927f7a1e62972a1eafa41`. It contains **405 actual checks**, **81 original recipes**, **2,111 source pins**, and **87 registered modules**. Its original cold gate, eleven native partitions, native collector, and eight original partitions had already succeeded.

The complete original artifact is **14274528318**, ZIP 4,386,065,194 bytes, SHA-256 `9bb775eccc8fdb92a0eaf5c38021373c76a71ea7430ff43dfdd3636c42bc19b4`. Full restoration and subsequent exact-index joins cover 178,275 TAR entries: 151,622 files and 26,653 directories, with 26,910,012,457 logical file bytes. The uncompressed TAR is 27,227,545,600 bytes.

The final aggregate rejection was a reporting-reader error: the public-registry control snapshot preceded later result-storage control records, but its check incorrectly compared against the entire final check list. The separately reviewed commit `445e7eb15608d5e88ab4cbf6407e0e767f1b3e8e` selects the complete prefix ending immediately before the unique public-control record. Its original failure was reproduced, the exact two-line function repair was admitted in memory, and all other comparator ASTs remained equal. The physical original source and failed report were preserved.

## Actual closure

| Domain | Actual source / run / job | Result |
|---|---|---|
| Aggregate complete evidence join | `004e7c2924d74e36f0c2b9af8ec6d1de16386b54` / 44020501712 / 133828573990 | All retained checks, recipes, module admissions, source/environment/library bindings, original index and failure preservation passed; independent guarded read 6.303335110 seconds. |
| Original filesystem controls | `f651fddda7cf4255ab5c54f9bdee26b3c982da96` / 44018587275 / 133822369172 | Eleven refusals, two physical relocations and twelve foreign-path refusals passed in 101.345598813 seconds under the unchanged 180-second process limit. |
| Independent filesystem full readback | `d705ba534d92b263188a8dbd201c4032babb08c2` / 44019797104 / 133826296078 | All 5,685 files and 1,054,071,232 logical bytes read; guarded result passed in 6.447330717 seconds. |
| Original configuration/regex controls | `f43227e2c93ecdb599f9ce3d3cb75d8905ed05a6` / 44020225624 / 133827685888 | Fourteen original refusals and six complete admissions passed in 36.555851235 seconds under the unchanged 180-second process limit. |
| Independent configuration/regex full readback | `083e09ecb953e4e7998e03588f34ee6bd0a07289` / 44021637927 / 133832234127 | All 3,540 files and 803,013,485 logical bytes read; guarded result passed in 6.086514803 seconds. |
| Final independent proof join | `3810ec867aad52d1d780c76303abc645f7cc3a0f` / 44022114623 / 133833777644 | Complete three input ZIPs, actual successful jobs, every source blob, complete snapshots, retained process identities and unchanged deadlines joined under twelve guard probes; 0.096708503 seconds. |

The three controls already completed by the original aggregate—result-values, public-registry, and result-storage evidence controls—were retained without replay.

The filesystem continuation preserves the original semantic/control bodies. It substitutes only the nested Python path guard in memory after exact source and AST checks, proving the admitted POSIX path and ancestor behavior against the original guard. Both complete physical copies, all mutations and foreign-path checks remain. It is a source-bound reader adapter, not a general filesystem sandbox.

The configuration/regex continuation runs the original control script unchanged on the exact union of its three sealed artifact tables. It rereads the full original archive before restoring that subset. Every input byte and mode is restored afterward; the nine original mutation targets retain their expected metadata changes, while all other input metadata stays unchanged. The independent reader checks the complete source, input, output, actual PID/parent/PGID, command, exit, audit, and stream records.

## Scope

The aggregate static adapter preserves the original loader's complete pre-CDLL artifact admission and binds the full 87-module registry. Invocation and sessions are refused. Consequently this recovery does **not** add a new current-kernel executable-mapping or seal test claim.

Each independent reader retains the same twelve no-write/no-process/no-native-map probes and compares complete before/after file snapshots. All complete original arrays, streams, source maps and hashes remain in their producer archives. This result is qualification of retained historical evidence and its pending evidence controls; it does not activate production, qualify complete runtime replacement, or qualify removal of the old stack.

The final joined artifact is **14301985373**, ZIP 2,622,151 bytes, SHA-256 `03ffd2cf4610b7f253349f26dbf47cf1c22c8132efaed4618c0f9e1f7de31eb0`. It includes the three exact complete independent input ZIPs, immutable API/job metadata, full guard snapshots and diagnostics, all final reader source, and the final result. Its uploaded-container identity is the GitHub Actions digest. A local read of that new outer container was unavailable; the complete constituent artifacts were independently read in the final CI job.

## Integration

Keep the reviewed **7afd Cargo metadata repair** and **08ce JSON-normalized comparison-outcome repair**. Apply the exact **445e public-control prefix fix** and its eight regression controls. Preserve historical evidence under its original source identity and preserve every earlier failed run.

Do not fast-forward the integration branch to this evidence branch. The recovery branch also retains all temporary read-only workflows and failed qualification sources. Root owns the narrow integration.

A pure re-read of the final result uses `final-readback-v1/JOIN_PLAN.json` to fetch the exact three small artifact ZIPs and their API/job records, then runs `join_history.py --inputs INPUT --output NEW_OUTPUT` under the same 180-second reader limit. It requires no HIA, Rust, compiler build, or semantic fixture execution.

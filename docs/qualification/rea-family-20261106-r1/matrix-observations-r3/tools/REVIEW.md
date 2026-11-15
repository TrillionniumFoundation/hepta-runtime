# Independent R5 matrix consumption preparation

This is a private, read-only consumer for source commit
`fe3223cabbd2a8f1aa75a4ab57507bdb72291242`, execution-input tree
`1a83f83cf62bf3d96e50c944722977b6971ffe686aecd131cab5e728dd802424` and
source-freeze receipt SHA256
`7b10276e2c34502345594139b3a89ab4b0f5d3634e89a2a54efaff732e51c314`.
Preparation does not constitute a matrix result. Final consumption requires the completed
summary's explicit SHA256 and the selected final binary's explicit SHA256 and byte count.

## Reviewed checks

The frozen repository consumer (`rea_build_evidence.py`, SHA256
`39920349c977affe142b05beeac7034577246c551b5f915c2d976c0f91c62093`)
reconstructs the nine original commands and validates all original source snapshots,
monitor observations, log hashes, successful stage exits, chronological boundaries,
effective environment, final Cargo compiler artifact and binary size/hash. The producer
module is separately pinned before its snapshot/file-reading helpers are imported.
Imports execute the already-hashed source bytes and do not write Python bytecode.

This wrapper adds an independent working snapshot, complete selected Git blob binding to
the frozen source commit, source/binary observations after consumption, exact all-features
membership from the committed package manifest, and the actual debug-0/nonincremental profile.
The current Git HEAD is reported separately and may later identify a documentation-only
publication commit. It is never substituted for the binary's source commit.

For each nextest run, the consumer checks the one start record, one terminal record,
actual PASS rows, complete sequential counters and unique binary/test identities. Each
feature set retains its own run and skipped counts. A skipped total is a reported total;
the retained nextest logs do not identify each skipped test and no doctest claim is made.
Seven pure-log tests cover complete and slow runs, missing/duplicate rows, counter or
denominator mismatches, inconsistent skip counts, duplicate summaries, failed terminal
rows and empty/incomplete runs. No Cargo command or runtime binary is used in these tests.

The consumer copies exactly the 22 fixed original summary/snapshot/monitor/log files,
replays the frozen validator on those copies, archives them, performs bounded safe
extraction into a different root and replays the validator there. The archive does not
contain the executable, complete checkout, dependency cache or toolchain. Those remain
explicitly supplied and separately observed inputs. Raw original files are not rewritten.

The optional resource quartet is pinned independently: `matrix-r3-launch.json`,
`matrix-r3-wrapper-outcome.json`, `matrix-r3-resources.stdout` and
`matrix-r3-resources.stderr`. It binds the known matrix job, source, command, unit,
chronology and raw-output hashes. A failed resource query stays a separate observation.
Whole-unit peak memory and CPU usage are not per-stage measurements, release costs or
deployment qualification. Unavailable I/O values remain unavailable.

## Scope

The consumer only hashes the selected native binary; it never executes it. The shared
consumer's historical field name `executed_binary_path` is retained, with an explicit
explanation that this independent build audit merely observed that file. Cargo's actual
`fresh` flag is reported without pretending that cache reuse implies a clean rebuild.

All operation-qualification output remains `qualified: false`. This verifies build,
source and file identity within the trusted local producer/toolchain/cache scope. It
does not establish ELF/Evidence behavior, full Provider Evidence equality, cross-platform
support, all 229 REA operations, release cost or any open P0–P5 gate.

The adjacent repair archival script and its prior helper version were already sealed
under `docs/qualification/rea-family-20261106-r1/repair-observations-r5/`. That package
contains finite prechecks, actual wrapper failures and immutable matrix launch metadata;
it deliberately excludes the then-running matrix outputs. Its copied helper source
is a separate, pinned historical version and is not overwritten by this final consumer.

# R34 full qualification evidence collector — unsealed

This is a **local, unsealed collector template**. `ACTUAL = None`; the original R34 qualification terminal, preparation/report/map/summary/audit pins, actual counts and runtime hashes have not been filled. No live qualification output, x230 path or Mac API was read to prepare it. The template is not an archive result and cannot be used to infer qualification success.

## Fixed selection and bounds

The collector derives from the published R33 tool, Git blob `7d8fd957f9beef1077be4188e02f84d2fba9093e` (31,940 bytes, SHA256 `3b150b9cc56bcad3cb170d1612b2cf2c0a5b0b36e875a5b7430607709a5f7954`). It keeps the original bounds:

| Bound | Value |
| --- | ---: |
| Total selected payload and combined archive/sidecar output cap | 32 MiB |
| Individual input/member | 8 MiB |
| Manifest | 2 MiB |
| Files | 8,192 |

The descriptor-based stable read, no-follow and regular/single-link checks, bounded decompression, explicit exclusion sets, create-only archive outputs and zero-extraction verifier remain the original helpers. The create and verify bodies change only R34 names and an initial unsealed guard. No archived program, original auditor, pruner or preparation helper is executed.

The fixed 61-member selection accounts for 7,773,813 bytes before the final qualification logs/source are added. It includes the complete existing 30-member sealed preparation package, including the exact 22 frozen candidate members, the qualification input, owner closure, preparer, seal tools/manifest and original rejected-owner postflight. The R33 source chain is not used as R34's source baseline. Accepted R24 plus the four-file R34 patch remains the source contract.

After a successful actual qualification, the collector also selects its exact final 220 compiler inputs and original 19 Python harness files, the original qualification stage logs, isolated summary and audit, inventory/control JSONL and every compressed original case log named by the already-completed audit. The original audit's hashes are reconciled with retained compressed bytes; case logs are not decompressed and the auditor is not rerun. Retained runtime/test ELF files and the build cache itself remain excluded. Only their original report/audit identities are recorded.

The original R33 archive's manifest reported 10,741,463 selected bytes. Adding the entire new fixed selection without even subtracting R33's old preparation inputs gives 18,515,276 bytes, below the unchanged 32 MiB limit. That is a sizing observation from an existing archive; the actual R34 total is still unknown and the collector will enforce the cap at runtime.

## Both cache-preparation attempts are retained

The fixed inputs include both original tools and plans, both reports, every result/intent/claim named by those reports, four complete cache-before/cache-after metadata inventories, and the original owner/retained-program receipts. Inventory files are copied as raw bytes. Their nanosecond integers are never passed through JavaScript `Number` or rewritten.

Prune-01 remains the original failed native job `1a1aeeea99f-fc05-6440`, with zero deletions and the fixed-stat mismatch. Its before/after metadata and original owner receipts match exactly. Prune-02 remains original successful job `1a1aef5957d-fc05-6486`, with exactly two intended rebuildable-file deletions, the unchanged 3 GiB gate, recorded retained/unselected preservation, and original free space 3,566,792,704 bytes. No claim is made about current free space.

The first plan's rounded nanosecond values `1793930603038937300` and `1793930262097573600` are preserved alongside the corrected decimal strings `1793930603038937265` and `1793930262097573724`. The original read-only precision crosscheck, its original native terminal/read and the complete earlier cache inventory are retained under `cache-prune-tools-02/originals/`. The collector binds these actual byte identities and records the original outcomes; it does not rerun the pruner, rehash a deleted/retained ELF, or repeat a live-stat probe.

The old failure native/read and precision originals already belong to the reviewed nine-member prune-02 tool package. Two additional successful-prune original files have known exact local/Git bytes but were **not observed installed remotely by this preparation**:

| Fixed future remote path below R34 ROOT | Bytes | SHA256 |
| --- | ---: | --- |
| `cache-prune-native-02.json` | 729 | `4dd1b42a247454f6e132c4fae19ae386288d51a93c05d455a3c7668be71c1a79` |
| `cache-prune-native-read-02.json` | 1,422 | `5d0001290839aa68e0ef307ae0d2bc22f60898f9d40e8b6885b3a37538e27539` |

The root coordinator plans their create-only installation during terminal postflight. The collector requires the exact files when it eventually runs. This template makes no claim that installation has already happened.

## Final qualification sealing

`receipt-locations.example.json` supplies seven fixed receipt roles, initially all unbound: preparation, original native terminal/read, qualification report, final source map, isolated summary, and original independent audit. Populate exact local byte identities only after the original first R34 native task has terminated with complete durable output. The job ID must come from that original terminal, and counts/runtime hashes are derived from the actual JSON originals.

`seal_collector.py` verifies stable bounded local copies and original terminal/log custody. For a successful terminal it requires the complete eight-stage result, actual 220-input map and matching original summary/audit counts. It then fills only the template's `ACTUAL` assignment and creates a new local sealed directory. It does not import the collector, run its helpers, start an archive, run the auditor or access a remote host.

```text
python3 -B seal_collector.py --receipts /absolute/path/actual-receipt-locations.json --out /absolute/new/sealed-01
```

The collector's first operation on each collect/summary/create/verify path is `require_sealed()`. An unsealed template cannot inspect the current output directory or produce an archive. A sealed successful collector still validates the complete current original bytes, full final source/harness binding, all stage log hashes, original inventory/audit controls, compressed case-log membership and hashes before writing anything.

A durable ordinary failed terminal may also be sealed. Explicitly absent later receipts stay null and are checked absent by the collector before collection. The failed compact preserves raw preparation, stage, test and audit results/errors and their original counts, including a raw report that says `qualified` if a later wrapper failed. It reports the overall archive outcome as failed and infers no qualification/audit success. Native cancellation, timeout, incomplete output or retry conditions remain outside the original closed-terminal contract and are not silently converted into ordinary failure or success.

When the root coordinator approves the final sealed collector, it has the original single-create interface:

```text
python3 -B /absolute/path/archive_r34_qualification.py --kind qualification
python3 -B /absolute/path/same-frozen-archive_r34_qualification.py --verify /absolute/path/qualification-evidence-01.tar.gz --expected-sha256 ACTUAL_REMOTE_ARCHIVE_SHA256
```

These are future steps. Neither command has been run for R34 by this preparation. The runtime root is fixed to `/home/qian/hepta-runtime-optimization-20261106-r34`, and the three output names remain `qualification-evidence-01.tar.gz`, `.manifest.json`, and `.compact.json`. Existing outputs cannot be overwritten or retried automatically. The verifier reads members in memory, verifies the exact same frozen tool and all selected member identities, recomputes the compact from the retained originals, and extracts zero files.

## Static review scope

`build_template.py` generated this template using exact original-source transformations and existing local frozen preparation/prune originals. `LOCAL_STATIC_CHECKS.json` records AST parsing, unchanged safety helper bodies, unchanged nested bounded file/directory readers, unchanged archive/zero-extraction verifier bodies apart from version and first guard, the original bounds/exclusions, and null future qualification pins. Those checks did not import or execute a collector, receipt helper, original auditor, pruner, qualifier, Cargo command, Rust test or benchmark. This package creates no Git tree, commit, branch or PR.

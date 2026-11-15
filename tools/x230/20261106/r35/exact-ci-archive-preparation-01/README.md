# R35 exact-CI original evidence collector

The sealed collector records the first completed R35 exact-CI attempt, native job `1a1af88c330-fc05-696f`. Its original report records six successful stages, 1,645 plain PASS results, 34 ignored tests, zero failures and zero retries. The native terminal is succeeded / exit 0 with all 1,541 stdout bytes and zero stderr bytes durably available. These values come from the original receipts; the unsealed template still preserves the earlier `ACTUAL = None` state.

This package prepares an archive. It does not run CI, tests, benchmarks, the nextest auditor or any archived program, and it makes no performance-adoption or hosted GitHub Actions claim.

## Frozen files

- `archive_r35_exact_ci.py` is the reviewed unsealed template, 29,915 bytes, SHA256 `9932c7d2f258ba8e0c943110c88286d11cc7c03d5fe137648d40fdf690e426f3`.
- `seal_collector.py` is the reviewed local sealer, 10,501 bytes, SHA256 `8ae6144456138cdf1ce2d9dcbf8cd89b22117392b971efe01ea9ea14e834b938`.
- `sealed-01/archive_r35_exact_ci.py` is the actual collector, 31,317 bytes, SHA256 `3ed489dbd50e6d4d083e7717d8f8f6a96f0e656dc2af9380416b0634f1005785`.
- `sealed-01/actual-pins.json` and `sealed-01/seal-manifest.json` preserve the real five CI receipt identities and the local sealing result.
- `actual-original-verification-01.json` records the independent original-byte, native-stream, count, source-map and AST checks. Only the `ACTUAL` assignment differs between the template and sealed collector; all 14 function bodies are byte-identical.
- `reference-r34/archive_r34_exact_ci.py`, `build_template.py`, `STATIC_CHECKS.json`, `fixed-inputs.json` and the untouched examples preserve how the template was derived. The 12 original R34 functions retain their original logic after the round/root substitutions and four declared entry guards.

The local sealer ran once. Neither version of the collector has been executed by this preparation. The separate peer review found no blocking issue in the template or sealer; its original file is included in the Git blob catalog.

## Evidence selection

The fixed source root is `/home/qian/hepta-runtime-optimization-20261106-r35`.

The collector preserves the complete original `rust-ci-01` directory, including all six stages' stdout/stderr, original report, internal plan, nextest list and audit. It also selects the root `rust-ci-plan-01.json`, original native terminal and complete single or contiguous paged native-read receipts, all six files in `rust-ci-tools-01`, the installed CI seal metadata, qualification bindings and the exact parent binder. Eighteen static inputs are individually pinned; the five actual CI inputs are separately bound by byte length and SHA256.

The real plan retains the complete 1,679-case inventory, 220-entry qualified source map, nextest 0.9.137 identity, original command arguments and three qualified ELF identities. The final source map is SHA256 `87f085a95a1c1925ecc444b46c996a0aec399c74ce7d0c32afff572e24055313`. ELF bodies, source/target trees, credentials and private profiles are excluded.

The complete qualification evidence remains in its separate archive, 2,676,768 bytes, SHA256 `a40f7d42c4c17bad59e81f07736ba6999f66d35973ce8c62c9655b9d88476b3a`. That archive was independently rehashed locally during this sealing preparation. The sealer itself truthfully records that it received the digest from the coordinator; it does not claim to have independently rehashed the archive or rerun its verifier.

Reported success, failure or abort outcomes are retained as original facts. Missing core plan/report/native/read receipts are rejected. A genuinely absent later audit may be represented as absent, but a reported success without its original audit produces a receipt-binding error. Archiving a failed or inconsistent report never converts it into a CI pass. This actual seal binds the completed successful attempt and its present audit.

## Create the archive once

The coordinator must create the exact sealed script at the following fixed path and verify its SHA256 before invoking it. This package does not deploy or execute the collector remotely.

```sh
/usr/bin/python3 -I -B /home/qian/hepta-runtime-optimization-20261106-r35/archive_r35_exact_ci.py --kind exact-ci --plan-sha256 4cc92edbd1b8052e73aed5ede9987a6d56684e2a621b1cf5b0577ad4b307bb28
```

The three create-only outputs are:

- `exact-ci-evidence-01.tar.gz`
- `exact-ci-evidence-01.manifest.json`
- `exact-ci-evidence-01.compact.json`

Stdout reports archive size/SHA, manifest and compact SHA, the original job and counts, and any receipt-binding errors. Preserve the original native start/status/read receipts for this archive operation. A nonempty binding-error list requires inspection; an archive's existence alone is not an acceptance verdict.

## Bounds and failure handling

Selection is bounded to 64 MiB and 8,192 files, with an 8 MiB per-file limit and a 2 MiB manifest limit. The three final output files together may not exceed 64 MiB. Gzip expansion, tar inventory and traversal depth are also bounded. Selected files must be regular, singly linked and stable across their path/descriptor metadata checks; symbolic links and credential/binary content are rejected or excluded under the unchanged original rules.

Compression happens in memory. No temporary extraction or work tree is created. The collector uses exclusive file creation and fsync for the three final files. If writing fails partway through, it keeps the partial outputs and refuses a repeated invocation over them; it performs no automatic deletion, overwrite or retry. A separately reviewed revision is required to resolve such an operation failure.

## Verify a transferred archive without extraction

Use the identical sealed script and the archive digest from the actual remote archive receipt:

```sh
python3 -I -B /absolute/path/to/sealed-01/archive_r35_exact_ci.py --verify /absolute/path/to/exact-ci-evidence-01.tar.gz --expected-sha256 ACTUAL_REMOTE_ARCHIVE_SHA256
```

The verifier reads bounded archive members in memory, recomputes every member's byte length/SHA and the compact summary from original receipts, and checks the sealed tool identity. It extracts zero files and executes no archived content. Its expected digest must come from the original archive operation, not from a substituted download.

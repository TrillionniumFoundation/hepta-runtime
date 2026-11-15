# R35 full-qualification evidence collector: unsealed template

The collector is prepared for the first original R35 qualification. `ACTUAL = None` is intentional. Collection and archive verification reject an unsealed template before reading source or archive input. The known original launch record is retained as a historical input; it is not a completed qualification result. No outcome, final compiler map, test count, or qualified binary hash is predicted.

## Fixed input selection

The template fixes 54 original small files by exact size and SHA-256: all 39 files in the actually installed qualification package, plus 15 installation originals. That includes the frozen 29-file R35 candidate, its accepted R24 220-input baseline, exactly three changed source paths, the actual R34 cache-owner closure, the unchanged qualifier launcher/harness contract, and full original postflight provenance. The R34 cache-prune attempt history remains in R34's published qualification evidence; it is not relabelled as a R35 preparation.

The installation originals use `ROOT/installation-originals-01/` for 14 copied files (22,028 bytes), plus the existing `ROOT/qualification-package-install-02.json` (7,081 bytes). `installation-original-copy-plan.json` lists every exact local source, remote relative path, byte count, and SHA-256. These 14 copies have not been observed installed by this template preparation. Root will create them once after the active qualification closes.

The original 477,316-byte installer stdin source is deliberately excluded from this evidence archive. Its exact SHA-256 `62397e09eee881494e8ed659eb8266f05c591b153224a5b3769ad796c4bff9c6` is retained in the original history and compact summary; root retains and publishes its full original source separately with the installation originals. No literal source body is fabricated from its digest.

After real terminal receipts are supplied, collection also selects the complete existing `qualification-01` reports, stage logs, original isolated-test inventories/audit, and every original compressed case stdout/stderr. The `test-binaries` directory is skipped. Other ELF files directly under selected qualification directories may have their first four bytes read to classify and exclude them; their executable bodies are not archived or rehashed. With a recorded final map, exactly its 220 compiler inputs and the original 19 Python harness files are selected from `source/`, with membership and content checked against the original report/map. No additional source subtree, build cache, profile, or credentials are selected.

## Installation history keeps the unknown outcome

The initial installer `1a1af5e240e-fc05-67f8` returned `launch_unknown`; its status/read calls returned the retained job-directory-absent error text. There is no native terminal receipt for that installer. The compact summary keeps its terminal state and exit code null.

The original read-only reconciliation `1a1af5f2833-fc05-6802` completed with its full 482-byte stdout and empty stderr. Its original observation recorded the R35 root and original job directory absent, and the unit query reported not-found/inactive/dead with both PIDs zero. The original script and all start/native/read bytes are retained. The cause of the original transport failure remains unestablished.

A distinct six-chunk binary upload committed the original 354,738-byte deployment package by exact SHA-256. Staged installation `1a1af611834-fc05-680f` then completed with 543-byte stdout and empty stderr, installed exactly 39 frozen files / 1,383,630 bytes, and reported 6,835,855,360 bytes free before installation. Its receipt retains the original 3 GiB requirement and records that it started no qualification, materialized no source, moved or deleted no cache, and changed no production services.

The qualification start `1a1af619097-fc05-6813` is bound to the exact frozen launcher argv. A later terminal must identify that same original job. The installation history is separate from qualification execution and is not counted as a qualification retry. The derived history file is retained with its original at-capture pending-result flag; the compact qualification outcome is computed from the later terminal/report/audit rather than rewriting that earlier file.

## Original qualification protocol

The qualifier remains the original eight stages: format, fmt-check, harness-tests, clippy, test-build, isolated-tests, audit-isolated-tests, release; jobs=2 and zero automatic retries. For an actual success, the collector reconciles the three source maps and archived bytes, all original stage-log hashes, exact 19-harness identities, the actual full inventory counts, original auditor input hashes, and the complete compressed-log set. It does not execute the qualifier, any test binary, an embedded program, or the original auditor, and it does not decompress case-log bodies.

The accepted R24 source is independent of the ended R34 cache. R34's actual C8 rejection and genuinely unrun lifecycle/materializer stay in the frozen closure. The new source has three changed files and no added test functions. Actual R35 counts are taken from the completed original summary and audit; historical R34 counts are not copied as an R35 expectation.

A genuine failed qualification can also be sealed. Its original native terminal and complete read, plus original preparation report, remain mandatory. Explicitly absent later report/map/test/audit files are null in the actual pins and must still be absent remotely. The failed compact reports the raw flags/errors/stage results and any actual partial counts without promoting them to successful qualification. This template does not invent a failed terminal for the earlier installer.

## Limits and safety

The file descriptor/stat/read helpers, collection body, create-only archive writer, and zero-extraction verifier are inherited from the executed R34 collector. Collection/create/verify differ only in version strings; their I/O logic is unchanged. The six common safety helpers are byte-identical. Only fixed input identities and domain receipt/summary bindings are adapted.

Limits remain 32 MiB selected payload and combined compressed archive/sidecars, 8 MiB per file, 2 MiB manifest, and 8,192 selected files, with the original bounded tar expansion limit. Original regular-file, nlink, NOFOLLOW, stable metadata, symlink, credential-marker and excluded-directory guards remain unchanged. Output files are create-only `qualification-evidence-01.tar.gz`, `.manifest.json`, and `.compact.json` in the R35 root. Verification validates the archive's full SHA, bounded member inventory, every member's size/SHA, and a recomputed compact summary without extracting or executing any member.

`LOCAL_STATIC_CHECKS.json` records the exact source/AST comparisons. `INSTALLATION_STATIC_CHECKS.json` records independent local comparisons against actual original metadata and complete original streams. Neither record is a qualification result.

## Seal only when the original first qualification is terminal

Copy `receipt-locations.example.json` to a new actual input file and fill it only from the exact local original native/read/preparation/report/map/summary/audit bytes. Do not reuse current partial files. Run the local `seal_collector.py --receipts ABSOLUTE_INPUT --out FRESH_ABSOLUTE_DIRECTORY`; it verifies original terminal/log/inventory consistency, fills only the `ACTUAL` assignment, and writes a new frozen collector plus actual-pins/seal-manifest. It does not collect remote evidence or run a workload. This template's sealer has not been executed.

After the actual collector has been reviewed and root has installed the 14 original history copies, the frozen remote command is `python3 -B ROOT/ARCHIVER.py --kind qualification`. A local verifier uses the exact same frozen script with `--verify ABSOLUTE_ARCHIVE --expected-sha256 ORIGINAL_REMOTE_RECEIPT_SHA`. Those are future procedures, not actions performed during this preparation.

The template preparation made no x230 or Mac call, ran no Cargo/rustfmt/test/benchmark/installer/pruner/archiver, and changed no Git ref. The local builder only read source/JSON, compared exact bytes and AST, and created new preparation files.

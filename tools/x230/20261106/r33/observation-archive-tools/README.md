# R33 original observation evidence collector

This collector is sealed to the completed first R33 observation campaign and its original rejection. It has not been executed by the preparation agent. It archives original bytes and summarizes existing reports; it does not run workloads, tests, the original auditors, or archived programs.

## Original outcome retained

The original Mac holder job is `1a1aecd302a-fc05-6294`: succeeded, exit 0, complete stdout 297 bytes and stderr 0 bytes, with its owned agent reaped. The parent workflow completed, but the original observation and performance gates are false. The unchanged rejection is `C8 regression gate`. A completed workflow is not presented as performance acceptance.

The original normal-lifecycle materializer job is `1a1aed5c50a-fc05-6301`: failed, exit 1, stdout 0 bytes and stderr 741 bytes. Its original gate message is preserved. Normal lifecycle input/output paths were absent in root's actual postflight, and their presence is recorded again during collection. Neither normal lifecycle performance nor saturated cancellation is claimed.

The parent report is 129,082 bytes, SHA-256 `248110d67b4e93ae40c4acbb63166af4f7e1365146df6918077e31869a0dbff1`. The original summary is 13,509 bytes, SHA-256 `8c2633a55d461802fbb9c5ed8c6b14b2e0715a70da9300a246e44e4351b80f1b`. Root's original postflight is pinned and included as well. No R31 preflight failure is attributed to R33.

## Collection scope

The fixed experiment root is `/home/qian/hepta-runtime-optimization-20261106-r33`; the only observation attempt selected is its `campaign-01` directory. Collection retains the complete normal S6 raw observations, four ABBA rounds and eight observation-controller shutdown/restart receipts, original boundary and recovery data, compiler-monitor ledger and audit, original stage logs, parent inputs, parent and lifecycle tools, and original holder/materializer native status/read JSON.

The external mapping is limited to the original R16 root `/home/qian/hepta-runtime-optimization-20261104-r16`. Its measurement tools, boundary tools, topology, and `r33-cancel-recovery-01` directory appear under `external/r16/` in the archive.

The full qualification and exact-CI evidence already exist separately and are referenced by their verified archive SHA-256:

- Qualification: `fa8a1bfcfe46b96aa59021c7f9ff20695fcc84b224c4ed0be811eda02c550c2f`
- Exact CI: `bf993f6e81d4f50930c35e7ddf73d229a0264733a1718b34699852e038948210`

This observation archive includes the small qualification receipts needed to identify the measured candidate. It does not repeat test ELFs, source trees, target caches, profiles, credentials, or secret-key content.

## Retained safety behavior

The collector derives from the exact frozen R31 observation tool, Git blob `a159114d1f51e4d409b47ca07531d585b002eb69`, SHA-256 `296d84668c1703361cb3dfe6b3a8b0849aed561d125f4a39988a44cda21fd7dc`.

Its original collection, bounded reads, file identity stamps, no-follow flags, link/special-file rejection, credential and ELF exclusions, native byte-stream accounting, and local verification routines are retained. Limits remain 64 MiB total selected bytes, 8 MiB per file, 8,192 files, and 2 MiB for the manifest; expanded tar data also has the original bound. Output creation uses exclusive creation and does not overwrite an existing archive or sidecar.

Verification reads archive members into bounded memory. It creates no extracted files and executes no archive contents. Every member is checked against the manifest, and the compact summary is re-derived from the retained original reports. Receipt-binding errors remain explicit in output and must be reviewed; the collector does not turn a failed original gate into a successful one.

## Preparation and review

`actual-bindings-01.json` records all 28 newly supplied identities and their locations in the actual parent, gate, and postflight reports. Both native streams were checked against their exact original hex bytes, offsets, EOF flags, seen/stored counts, and original job IDs. The preparation retained the earlier unsealed draft separately and generated this sealed directory with create-only writes.

`static-checks.json` records 18 successful source/AST comparisons, including byte-identical safety helpers and unchanged limits/exclusions. Python syntax was parsed; no collector, original auditor, Rust process, or remote API was run during this preparation. The future archive receipt and archive hash do not exist in this package.

## Disk bound and temporary-file handling

The archive is assembled in memory. Before any output is created, the collector requires the combined byte lengths of the final gzip archive, manifest, and compact sidecar to be at most 64 MiB. Those three files are the only disk outputs; filesystem block rounding and metadata use additional filesystem space. No temporary tar, temporary gzip, extracted directory, compiler cache, or source copy is created.

There is no automatic cleanup or retry. If an I/O error or interruption leaves one or more of the three create-only output paths present, preserve their bytes and the native failure receipt. A later invocation refuses the existing paths. Root must review that concrete outcome before selecting a separately named recovery revision. The collector never deletes original evidence, production or candidate source, target caches, or another job's files. Cache-space decisions for the R34 qualifier are separate from this archive operation.

## Authorized execution and local verification

After root reviews and installs this exact script as `ROOT/archive_r33_observation.py`, archive the existing evidence once:

```sh
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r33/archive_r33_observation.py --kind observation
```

The create-only outputs are `observation-evidence-01.tar.gz`, `observation-evidence-01.manifest.json`, and `observation-evidence-01.compact.json` at the experiment root. Preserve the original native start/status/read response bytes and use the actual archive SHA from stdout for transfer and verification.

After transferring the original archive, run the same frozen script locally with an absolute archive path and the real receipt SHA:

```sh
/usr/bin/python3 -B /absolute/path/archive_r33_observation.py \
  --verify /absolute/path/observation-evidence-01.tar.gz \
  --expected-sha256 ACTUAL_SHA256_FROM_ORIGINAL_ARCHIVE_RECEIPT
```

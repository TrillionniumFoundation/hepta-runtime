# R35 original normal lifecycle evidence archive

This package freezes a bounded collector for the first R35 normal lifecycle attempt. It preserves both successful and failed original reports; a failed performance gate is an archived outcome. It does not run the lifecycle workload, any original auditor, Cargo, or SSH.

The actual original holder is `1a1afc4fb4a-fc05-6b7f`. Its terminal result is `failed`, exit 1, with 296 stdout bytes and 0 stderr bytes, fully retained. Four normal ABBA rounds and their independent audits completed. The original tool report records 14 passing tests. The compiler-monitor audit records 149 samples. The original gates are verified and fail: the required concurrent-cancel throughput ratio is 0.9293926467609281 against the unchanged 0.95 minimum. The gate report retains the complete per-operation comparisons, including flags that are descriptive and not required for adoption.

The collector and sealer never adopt a candidate. R35 remains rejected and the accepted release remains R24. Earlier Q, exact CI and ordinary OBS success are prerequisite evidence, not lifecycle success.

## Scope and original references

The IO and zero-extraction verifier are derived from the reviewed R35 ordinary OBS collector, SHA256 `96fa3ff43180ec0e922c4b6373ec9d7a902037d97ae06d9a774ebf318d9f1f2c`. The normal-lifecycle report and round-index protocol was checked against the original R29 exporter, Git blob `e3585259721739bf281015d99a0c3b150f09930b`, SHA256 `c9fd58c7aaebd51f60f1a2fdc3a01c52629b41d5a5818be124c79a547735872e`, and its actual normal ABBA failure report. Its larger XZ archive limits were not reused. The R24 six-host cancellation canary is a different scope and is not presented as this normal ABBA campaign.

The fixed selected result trees are `lifecycle-campaign-01`, `lifecycle-abba-01` and `lifecycle-tool-tests-01`. All original stage streams, round raw reports, eleven phase files per round, RPC/SSH transport evidence, resource traces and cleanup records in those trees are selected. The exact installed `tools-01` and `lifecycle-tools-01` trees, fixed inputs, source maps, prerequisite receipts, topology and six explicitly mapped frozen job fixtures are also selected. Original qualification and CI archives are referenced by hash rather than copying their binary/cache/test payloads.

The 71 static identities include the actual R35 materialized LC manifest and two ROOT-specific tool hashes. No R33/R34 materialized tool pins or earlier archive-recovery failures are inherited. The original saturation-related tool source files remain in the frozen 27-tool bundle, but no separate saturation campaign or its success is claimed.

Full Mac holder terminal/read bytes and its full report are preserved. The original holder report is `<Mac-out>/report.json`; the immutable x230 copy is `lifecycle-holder-report-01.json`. Mac-local holder log bodies are not copied by this x230 collector; their identities remain in the full original holder report. The LC measurement, phase, stage and audit log bodies on x230 are included.

## Failure and partial-output behavior

The original terminal and read stream covering all stored stdout/stderr bytes are mandatory. Failed, cancelled and timed-out terminal states remain valid archival inputs. Other core reports may be absent or malformed after an early failure. The collector preserves available raw bytes, records missing/parse-error information and never substitutes success. A missing local input to the sealer is only “not supplied”; remote presence is captured later by the collector.

Reported stage sequences can be ordered prefixes. Nonzero exit codes and false performance gates alone are not archive binding errors. Positive workflow claims require the original complete native/log custody, successful holder closure, full original stage custody, source/input continuity, four audited rounds and original passing gates. These conditions do not weaken or recalculate the original performance policy.

The compact output copies original gate booleans and comparisons. Its derived false-comparison list only enumerates false flags already in that original report. Counts are summed from the actual original round audits and are labelled with whether all four audits are present. Raw shutdown and intentional-crash fields remain separate; missing cleanup evidence is not represented as clean.

## Bounds and exclusions

The unchanged bounds are 64 MiB selected bytes, 8 MiB per file, 2 MiB manifest and 8,192 files. Collection uses fixed roots, regular files, no-follow reads, stable before/after identities, explicit exclusions and create-only output. It excludes source/target/cache trees, ELF programs, profiles, key material and credentials. The verifier performs bounded gzip/tar reads in memory, checks every member's size/hash and recomputes the compact receipt from retained raw data without extracting or executing members.

The archive output is immutable and named `lifecycle-evidence-01.tar.gz`, `lifecycle-evidence-01.manifest.json` and `lifecycle-evidence-01.compact.json`. Existing outputs are refused rather than overwritten.

## Local preparation and actual seal

The preserved `draft-01` was constructed locally and never executed as a collector. `template-02` adds only materializer terminal/read interpretation and an explicitly derived original false-gate list. The independently reviewed template is 58,839 bytes, SHA256 `18718efc1b613b9b01c1ec05485c36dda1b83142fefea08a52b157df74d86b65`; its 16,852-byte sealer is SHA256 `4f180f48c7e568db3fbb0462b69e9715748baec7b97219d2b74aa38e3d769e47`.

Sealing read 17 exact Git-restored original bodies and identities reported by those originals. It filled only `ACTUAL`, preserving every executable function. The actual sealed script is 155,141 bytes, SHA256 `44c43bac75b168f749f8ca58d7da662d3abf341bdf578e6ab1dec567cd3fa85e`, Git blob `ca2f82b90ed941756480c07b8ce65c2b6cb9c10d`. Its 150 dynamic identities are verified against actual remote bytes when root runs the collector. Sealing does not mean collection or remote byte verification has already happened.

The local sealer invocation was:

```text
python3 -B seal_collector.py --originals /tmp/hepta-runtime-recovery-20261106/r35-lifecycle-originals-recovered-01 --output /tmp/hepta-runtime-recovery-20261106/r35-lifecycle-archive-template-02/sealed-01
```

After create-only installation by root, the original archive invocation is:

```text
/usr/bin/python3 -B /home/qian/hepta-runtime-optimization-20261106-r35/archive_r35_lifecycle_01.py --kind lifecycle
```

Later, the same exact script verifies an immutable downloaded archive with `--verify /absolute/archive.tar.gz --expected-sha256 <original-remote-receipt-sha256>`. This preparation agent has not run collection, verification of a new LC archive, any original auditor or any remote command. Root supplies the actual archive execution/transfer receipts separately.

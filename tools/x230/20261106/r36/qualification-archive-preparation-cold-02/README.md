# R36 validation-scratch cold02 qualification archive preparation

This unsealed package reuses the verified D2 qualification collector (Git `983ef6005208c690ac61e49ca03c2091b9017be1`) and the original R35 data-only sealer (Git `771457505534298e87a4cb3e7efd14b5ce11dadc`). It covers the original cold02 qualification job `1a1b1cb4862-fc05-7ad9` at `/home/qian/hepta-runtime-validation-scratch-20261106-r36-cold-02`. Its outcome, counts, formatted map and release identities remain unknown in this package.

## Collection and unchanged bounds

The collector retains the 22 installed preparation members, original installation/launch evidence, all eight qualification stage streams, `cargo-no-run.jsonl`, the entire original isolated-test receipt directory including every compressed command stream, the report, summary, audit, final 220-input source map, all 220 final compiler source files, and the 19 original harness files. It reconciles compressed bytes with the already executed original isolated auditor; it does not rerun that auditor or decompress individual case logs.

Limits remain 32 MiB selected bytes and combined output bytes, 8 MiB per selected file, 2 MiB manifest, and 8192 files. Stable regular-file and no-symlink reads, the credential scanner, create-only writes, bounded gzip/tar processing and zero-filesystem-extraction verification are unchanged. Target trees, retained libtest binaries, ELF bodies, profile/configuration and credentials remain excluded. Release ELF identities come from the original qualification report, without a new ELF read or execution.

Only current installation/candidate/preparation facts changed: candidate12, source220, the two new tests as actual source, 22 installed members, and cold-only new-empty-target preparation. D2 receipts remain historical owner evidence. The summary explicitly requires no cache reuse, rename or ownership transfer. The earlier wrapper failure `1a1b1bedd38-fc05-7a99` remains a distinct preserved preparation failure, not a failed Rust test followed by a hidden retry.

## Seal after actual terminal evidence

Fill `receipt-locations.example.json` from seven exact raw receipt copies. The job ID is already known from the original launch; no successful result is assumed. A confirmed failed attempt may retain actual missing later receipts as null. Native terminal/read/preparation originals are always required.

```text
python3 -B /absolute/preparation/seal_collector.py --receipts /absolute/actual-receipts.json --out /absolute/new-sealed-dir
```

This command only reads bytes, checks raw native stream closure and the original reported result, parses the collector AST, injects ACTUAL, and writes three new files. It does not import or execute the collector, binder, qualifier, auditor or any subprocess. Actual test counts and binary hashes are derived from original documents. The output directory must be absent.

The seven additional fixed archive inputs are listed in `staging-plan.json`. Exact installer and deployment archive bytes already exist outside ROOT and can be copied without running them. The supplied original installation and qualification-start JSON bodies must be copied byte for byte; do not parse and re-encode them. The installation receipt already exists at ROOT. The collector itself belongs under `archive-tools-01` and is deliberately excluded from selection.

## One archive, then original verification

After actual data sealing and required original-byte staging, root can execute the new sealed collector once:

```text
python3 -B ROOT/archive-tools-01/archive_r36_qualification.py --kind qualification
```

It creates `qualification-evidence-01.tar.gz`, `.manifest.json`, and `.compact.json` without overwriting anything. On an interrupted partial write, retain the partial outputs; do not delete or automatically retry.

Verify the returned bytes with the **same exact sealed collector**:

```text
python3 -B /local/exact-sealed/archive_r36_qualification.py --verify /local/qualification-evidence-01.tar.gz --expected-sha256 ACTUAL_REMOTE_SHA256
```

Verification reads the bounded archive in memory, checks every selected member and summary, and extracts zero filesystem files. It does not execute an archived program. A verified archive of an original failed result remains a failed result. No CI, benchmark, performance gate or adoption decision is supplied by this package.

Only local source/AST/hash comparisons and independent static review have occurred. All target entry points remain unexecuted.

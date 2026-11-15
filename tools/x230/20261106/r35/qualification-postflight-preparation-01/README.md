# R35 qualification postflight: unsealed preparation

`postflight_r35_unsealed.py` is a source preparation for root to seal after the original R35 qualification finishes. Its `payload` is `None`. The first guard rejects an unsealed payload before any target filesystem access. The five original report identities, actual complete test counts, original terminal job ID, and two native-original bodies are deliberately absent from `payload.example.json`.

## Inputs for the actual seal

The payload schema is `hepta-r35-qualification-postflight-input/v1`. `pins` must contain exactly five relative names: `preparation.json`, `qualification-01/report.json`, `qualification-01/source-map.json`, `qualification-01/isolated-tests/summary.json`, and `qualification-01/isolated-tests.audit.json`. Each pin has exactly `bytes` and `sha256`. The actual job ID and complete passed/failed/ignored/selected/retries values must come from the final original reports and terminal, not a prediction or historical R34 inventory.

`originals` has exactly 16 rows. Two are `qualification-terminal-status-01.json` and `qualification-native-read-01.json`; the other 14 are the exact `installation-originals-01/` names from the previously delivered copy plan. Every row has only `name`, `bytes`, `sha256`, and `data_base64`. The 14 historical identities are already fixed in `COPY_PINS`. Their exact bodies must be loaded from `/tmp/hepta-runtime-recovery-20261106/r35-installation-originals-01/`; no body is reserialized. All supplied bytes are decoded and checked before target filesystem reads or writes. Only the two Q native JSON files are parsed as the native terminal/read pair; text errors and Python scripts remain raw bytes.

Root supplies the actual payload by replacing the single `payload=None` assignment in a new frozen script. The rest of the reviewed script should remain byte-identical. This directory contains no automatic sealer and no execution authorization. The script has only been parsed with AST, not imported or run.

## Preserved checks

The original R34 `read_bound` function remains byte-for-byte identical, including the stable before/after descriptor and path metadata, NOFOLLOW, nlink=1, ordinary-file checks, bounded read, and SHA-256. The original full compiler-map traversal is preserved: exactly 220 files across Cargo inputs, src, and examples, including embedded Python files. All 19 original harness hashes and all three retained qualification ELF identities are checked with the original rules.

The candidate input is the original 53,380-byte R35 input with SHA-256 `7089775ed203f2a9d93dbb3528e63826c0b295c35c1aad782e51c99c9e5e059d`. R24 remains the accepted baseline. Exactly jobs.rs, ssh_observation_pool.rs, and ssh_observation_pool_tests.rs may differ from it. The final map must match the qualified report source_tested/source_after and the preparation source_after_qualification. The pre-format map must match the preparation source_before_qualification, the report source_input, and the frozen candidate.

Original eight-stage names/exit codes, jobs=2, zero retries, report/audit/source identities, actual complete native stream offsets/hex/text/seen/stored/EOF/sync fields, and terminal durability remain checked. The native terminal must identify the real first qualification start retained in the installation originals. R34 is only the ended old cache owner; its target-build path must now be absent and the R35 target-build present. No R34 prune receipt is required or copied.

## Create-only output

Before any mutation, the script requires the two native destinations, all 14 history-copy destinations, the new history directory, and `qualification-postflight-01.json` absent. It separately rehashes the already installed 7,081-byte `qualification-package-install-02.json` with its original SHA-256 `0ebcc8a7ad1a4ec397de179e68ff50bd7da19cf9b6ff5100d816c2245eab1e34`; that receipt is never rewritten.

It creates the private history directory once, writes and fsyncs the 16 exact originals with exclusive creation, then reads each back by its bound identity. It enumerates the complete 220-path source set again and rehashes every member after writing the evidence, then fsyncs the created directory and root. Finally it creates and fsyncs `ROOT/qualification-postflight-01.json`, containing actual counts, source-map closure, retained program identities, every original receipt identity, and explicit no-adoption/no-new-test/no-new-audit facts.

There is no rollback or retry. A partial write failure remains visible and must not be erased or silently overwritten. The script does not run Cargo, tests, benchmark workloads, original auditors, installation scripts, reconciliation scripts, or cache mutation. It does not claim global machine idleness or performance adoption. This local preparation made no x230 or Mac request.

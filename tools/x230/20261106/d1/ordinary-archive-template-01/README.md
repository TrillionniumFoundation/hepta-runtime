# D1 ordinary02 full evidence archive — unsealed preparation

This source preparation captures the original ordinary feature-off supplement. It is not a compiler, a test runner or a performance gate. The actual producer job is `1a1b04c6cd1-fc05-6f94`; at preparation time its result and verifier result are pending.

## Original protocol and evidence

The producer has the five original stages `clippy`, `test-build`, `isolated-tests`, `audit-isolated-tests`, and `release`. The ordinary derivation omits the already completed formatter/fmt/harness calls and removes the three `--all-features` arguments. This collector changes none of those commands, source, tests, counts, deadlines or retry rules.

The archive includes the actual ordinary02 result directory, the ten stage streams, Cargo artifact JSONL, original isolated-test metadata, commands/test rows and every original compressed stdout/stderr file. Successful capture matches each compressed file directly against the already executed audit's `gzip_sha256` inventory. It does not decompress those case logs or run the auditor.

The 24 fixed inputs are the new 13 deployed members, the old 9 deployed members, the unchanged original qualifier and the actual qualified D1 report. The three exact old failed-native/read/start JSON files are among the new deployed members and are retained byte for byte. Their original job `1a1b03a9d15-fc05-6f3f` failed before ordinary plan creation or Cargo; its complete 0/910-byte streams remain visible.

The first newly prepared transport03 had a trailing-newline packaging defect in those three raw JSON files. Root rejected it before deployment. Transport04 corrected only transport bytes and identities; it did not change the frozen ordinary verifier or replay the old job. The published preparation/transport history remains separate from the ordinary runtime result.

## Selection and exclusions

The only recursively selected result directory is `ordinary-02/`. Fixed metadata outside it is selected by exact path and SHA. The complete source tree, prior cache-owner evidence, prior Q/CI logs and their large retained programs are not recopied. The original postflight's cross-directory identities remain explicit external references, together with the published qualification tar and the exact-CI original-file catalog. The CI reference is a collection of original files, **not a compressed archive**.

No ELF body, target/cache tree, test-binaries subtree, profile, socket, credential file or private-key content is archived. The original credential scanner is unchanged. Direct files may have their first four bytes read to exclude ELF; the test-binaries subtree is skipped entirely. The collector source itself contains that scanner's literal and is therefore not selected into its own archive. Its exact source is preserved separately in Git and by the archive tool SHA.

Only original postflight evidence attests the six release ELF hashes. The collector does not rehash their bodies. Test ELF custody remains the original audit's before/after SHA evidence; the postflight explicitly did not rehash the large test ELF bodies.

## Actual-only sealing and success versus failure

`ACTUAL = None` blocks all four collector entry points before collection or output creation. `actual-pins.unsealed.json` is an example, not a future-result assertion.

The pure source sealer reads original local receipt bytes, preserves their SHA and original page boundaries, and replaces the sole ACTUAL assignment. It uses AST comparison to prove all other source nodes are unchanged. It never imports or runs the collector, verifier, original auditor or any host program.

A successful producer alone is insufficient: sealing waits for the actual original read-only verifier native terminal, whether that verifier succeeded or failed. A successful archive summary requires the original v3 postflight, original native terminal/pages, full five-stage result, source maps, original counts, case-log inventory and both release-program identity sets to agree. It also reconciles the verifier's complete native stdout with the retained postflight's exact bytes.

A failed/cancelled/timed-out producer, or an original verifier failure, can be captured as `not_passed`. Missing later core receipts and malformed partial JSON are retained and reported, without inventing a postflight, counts or success. Stored native pages are preserved even when terminal flags do not establish full durable success; the exact original flags are reported. No failed or incomplete capture is upgraded into an ordinary success.

## Paths and limits

The operator's local original directory mirrors these paths relative to:
`/home/qian/hepta-runtime-phase-cost-20261106-d1`

```text
ordinary-native-02.json
ordinary-native-read-02-000.json          (then original 001… pages, up to 16)
ordinary-plan-02.json
ordinary-02/report.json
ordinary-02/source-map.json
ordinary-02/isolated-tests/summary.json
ordinary-02/isolated-tests.audit.json
ordinary-verification-input-02.json
ordinary-postflight-02.json
ordinary-postflight-native-02.json
ordinary-postflight-native-read-02-000.json (then original 001… pages)
ordinary-installation-started-02.json
ordinary-installation-02.json
```

The actual native/read originals are installed create-only by root; this preparation does not perform that installation. A captured absent core path must still be absent when the collector runs.

The inherited archive limits are 32 MiB selected bytes, 8 MiB per file, 2 MiB manifest and 8192 files. Archive plus sidecars also fit the original 32 MiB bound. The stable-file, bounded gzip/tar, duplicate/path checks, O_EXCL outputs and zero-filesystem-extraction verifier are retained from D1 qualification archive03.

Future, authorized operator commands:

```sh
/usr/bin/python3 -B seal_collector.py --template archive_d1_ordinary.py --originals /absolute/originals --output /absolute/new-sealed-directory
/usr/bin/python3 -B /home/qian/hepta-runtime-phase-cost-20261106-d1/archive_d1_ordinary_02_01.py --kind ordinary
/usr/bin/python3 -B /absolute/frozen/archive_d1_ordinary.py --verify /absolute/ordinary-evidence-02-01.tar.gz --expected-sha256 ACTUAL_REMOTE_SHA256
```

The second command writes new `ordinary-evidence-02-01.tar.gz`, `.manifest.json` and `.compact.json`. An existing output is a refusal, not an overwrite/retry. Local verification reads the archive in memory, recomputes all member hashes and the compact summary, and extracts zero files. Neither creation nor verification executes archived code.

## Preparation status

Only JavaScript text assembly, byte hashes and Git content-object creation have run in this preparation. Original helpers are compared byte for byte. Python AST review and independent static review are separate evidence, not implied by these construction checks. There is no ordinary result, C1 result, throughput improvement or adoption claim in this unsealed package.

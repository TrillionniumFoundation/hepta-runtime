# A50 recorded X230 helpers and payloads

These are the exact helpers and immutable inputs used for the A50 qualification, small comparison and failed/incomplete large comparison. The recorded source and results are described in [the A50 experiment](../../../docs/experiments/x230/a50/README.md). Qualification passed; the complete performance-adoption requirements did not.

## Recorded sequence

1. `a50-record-batches-prepare-r01.py` assembled the reviewed two-file prepared overlay, full 168-file input map, deterministic source JSON/gzip and frozen qualification protocol. Its preparation receipts describe that earlier local state, before execution.
2. `qualify_a50_record_batches_r01.py` ran the six original stages on the isolated X230 source. Its original report/entry/worker chain binds the actual formatted source and strict fresh=false compiler events. Prepared bodies differ from the actual qualified formatter outputs.
3. `review_a50_publication.py export-source` read all 168 actual source bodies after qualification and emitted the two changed bodies plus the complete SHA/Git-blob map. `verify-local` rechecked downloaded original reports, full test log, exported bodies and the unchanged parent object map without running the runtime.
4. `bind_a50_archive_experiments.py` consumed the three actual final report SHA pins and created the fixed comparison helpers and protocols. It preserves A46/A48 failures. Measurement helpers and numeric algorithms remain unchanged; the large main has the reviewed symmetric first-close cleanup adapter.
5. `run_small_archive_a50_r01.py` completed both fixed blocks. `evaluate_small_archive_a50_r01.py` consumed the actual terminal report and the captured `protocol.original.json` inside the evidence root; all six small guards passed.
6. `run_native_archive_cohort_a50_r01.py` retained all 80 planned slots. It terminated failed/incomplete after the last baseline warmup failed: 60 attempted measurements and 20 unexecuted. There was no retry. Its entire terminal report remains original.

The scripts bind absolute X230 paths, original hashes and in some cases stat9 receipts. They deliberately require fresh output locations and refuse mismatched or stale inputs. A separately reviewed future attempt needs its own isolated output paths and actual qualification bindings; changing old files does not create a new valid experiment.

## Previously published immutable dependencies

The exact helper inventory and hashes are also in the scripts and [the earlier dependency inventory](../a46-a48/dependency-summary.json).

| Dependency | Repository copy | SHA-256 |
|---|---|---|
| Shared A46 qualification definitions | [qualify_a43_a46.py](../a46/qualify_a43_a46.py) | `7ce825966b413ab5e2d31979fbd5bb0e47a67a9105827d742ea986124610b176` |
| Original guarded six-stage core | [prepare_qualify_a44_owner_barrier_r01.py](../a46/prepare_qualify_a44_owner_barrier_r01.py) | `84e5fc48a688f83987425ff357428230083948703d419db4be1227d6b1ed8113` |
| Original guarded qualification policy | [A44 policy](../a46/a44-owner-barrier-qualification-r01.protocol.json) | `45185065cf0540296ea722bdfd4f000940338e466a6c936dfd34ca7cdbc5d50b` |
| Original candidate qualifier | [qualify_runtime_candidate.py](../a40/qualify_runtime_candidate.py) | `64efa0da0d22e2ad8d10eb6f8a91ab158a234b331383bbd595e65fc9bd47d1d2` |
| Original r07 host-load/custody helper | [run_a41_native_validation_r07.py](../a46/run_a41_native_validation_r07.py) | `6123660947b4b205d7f70d901c4e78b74395df065226a27937730b8c4cdd2ec9` |
| Original small driver definitions | [run_a41_native_validation.py](../a46/run_a41_native_validation.py) | `d35bfe354d405b6efb2d2ca28e06bb6469016cc6cf0c611ca3c107b043ea0d32` |
| Original small workload/oracle | [x230_small_archive_benchmark.py](../a40/x230_small_archive_benchmark.py) | `98413b4b177ec3bf68b7fe67de153376465374a9e74690c337633b3b4a912ffb` |
| Qualification-chain body/receipt validator | [load_a46_qualification_chain_r01.py](../a46/load_a46_qualification_chain_r01.py) | `55a19e9e5d5bd2d514025fefe2cdf037b9a21f0fae1ed3f750c6b9af086cf7e0` |

`binder-review/` separates the one local journal-failure control-flow check from actual runtime results. Its synthetic local EOF child is not an X230 runtime qualification or benchmark. `actual-binding-review.json` records the later real report pins; its corrected evaluator argv uses the captured protocol path.

The source JSON/gzip and `source-overlay/` describe frozen preparation. The root repository's Rust files come from the actual post-format source export. Every failed or unexecuted historical attempt remains separate. None of these helpers changes services, credentials, product deadlines, native admission policy or original correctness gates.

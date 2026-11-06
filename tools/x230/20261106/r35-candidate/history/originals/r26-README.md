# X230 R26 rejected candidate evidence

**Status: R26 is rejected and is not adopted.** Qualification, exact external
Rust CI and observation passed. Lifecycle attempt01 failed before fixtures;
a separate natural quiet wait succeeded; lifecycle attempt02 completed its
functional ABBA but failed the required concurrent-cancellation throughput and
p95 gates. Saturation did not run. Accepted R24 remains active. See the
[technical report](../../../../docs/X230_OPTIMIZATION_20261105_R26.md).

This evidence package also retains phase03's separate instrumentation-disturbance rejection,
the two original archive-tool failures, and the actual successful hosted runs
at the earlier published `bfa0d611…` head. Later export/capture operations have
actual successful native terminal receipts. All seven complete archives and
all five holder cross-package bindings and complete native custody are verified. R28 is a prepared subsequent proposal with no
test result recorded here.

## Exact source

- [Complete qualified patch against accepted R24](qualified-candidate-01.patch): five changed files, including the new sibling cancellation tests.
- [Selected R25-to-R26 change](r25-to-r26-selected-change.patch): moves the unused Python read JSON into its consuming branch. No performance effect is claimed.
- [Actual qualified map](reviews/qualified-source-map-01.json): 221 inputs, SHA-256 `7099d5752076faab911394eb06246c6d2da86c0f9a8bf79faa3ab8403b85a50c`.
- [Corrected source index03](reviews/qualified-publication-source-index-03.json) and [patch proof](reviews/publication-patch-proof-01.json) bind the exact preimages, output bytes and Git blob identities. The earlier pre-format comparison was superseded locally; accepted R24 pool tests are unchanged and excluded.
- [Accepted R24 qualification map](reviews/accepted-r24-qualified-source-map.json), [final publication readback](reviews/accepted-r24-final-publication-readback.json) and [historical source-blob preparation](reviews/accepted-r24-source-blob-preparation.json) provide the baseline provenance. The final readback establishes acceptance; the preparation receipt records its earlier preparation stage.

## Actual original qualification

Original job: `1a1ab4cb0fc-fc05-4c3c`, strong terminal `succeeded`, exit 0.
All eight qualification stages passed; **1,653 passed, 0 failed, 34 ignored,
1,687 selected, 0 retries**.

- [Preparation](reviews/preparation-01.json)
- [Complete qualification report](reviews/qualification-report-01.json)
- [Original native terminal](reviews/qualification-native-terminal-01.json)
- [Isolated test summary](reviews/isolated-tests-summary-01.json)
- [Independent isolated-test audit](reviews/isolated-tests-audit-01.json)

## Actual original external CI

Original job: `1a1ab7ecb60-fc05-4e4e`, strong terminal `succeeded`, exit 0.
Exact workflow `cargo check` and nextest commands passed. All 1,653 executed
cases were plain `PASS`; 34 were ignored; no failures or retries occurred.

- [Original CI report](reviews/rust-ci-report-01.json)
- [Original native terminal](reviews/rust-ci-native-terminal-01.json)
- [Losslessly reconstructed native stdout](reviews/rust-ci-native.stdout) and [stderr](reviews/rust-ci-native.stderr)
- [Independent original-receipt verification](reviews/independent-receipt-verification-01.json)

The case-inventory SHA-256 is
`874de054557c19edef3c0cb291fb6dd75cde32706e5670b851808db0bf1f8cff`.
The report binds complete check/inventory/nextest logs. Their original full
bodies are now in the locally verified [CI archive](evidence/ci-01.tar.gz).
Native stdout remains the original job's launcher/stage progress stream and
does not replace those command logs.
The external run binds the rejected R26 source. Hosted results are separately
bound to the earlier published head below.

## Actual hosted CI at the earlier published head

At the saved API observation on 2026-11-05 13:38:32 UTC, original push run
[`42000460525`](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42000460525)
and PR run
[`42000474593`](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42000474593)
both completed successfully on attempt 1 at head
`bfa0d6113d675bb9f597baa474f913c3a12df37a`. The push exact-source job and both PR
Rust jobs succeeded. The PR-only merge job was skipped in the push run and retains
its `skipped` status.

- [Exact raw head response](reviews/github-bfa-success/head.raw.json)
- [Push run](reviews/github-bfa-success/push-run.raw.json) and [push jobs](reviews/github-bfa-success/push-jobs.raw.json)
- [PR run](reviews/github-bfa-success/pr-run.raw.json) and [PR jobs](reviews/github-bfa-success/pr-jobs.raw.json)
- [Refresh summary with original identities and scope](reviews/github-bfa-success/refresh-summary-02.json)
- [Earlier source/publication binding](reviews/github-bfa-success/earlier-core-publication-readback.json) and [earlier prospective-merge tree binding](reviews/github-bfa-success/earlier-prospective-tree-binding.json)

The historical tree records retain their then-current queued fields. The later
raw API outcomes close that head's queue blocker. Its production source is still
accepted R24; these runs provide no hosted result for the R26 patch, R28, or the
future evidence publication commit. No scheduler-delay cause is inferred.

## Actual original observation and lifecycle attempt01

Observation job `1a1ab9c71ee-fc05-4f01` succeeded once and passed every frozen
observation gate. C1/C8/C16 successful throughput changed by +0.869%, −1.046%
and +7.124%; C16 p95 changed by −11.595%. Controller peak RSS increased by
132 KiB within the gate. These finite-campaign nonregression results do not
claim that every concurrency level became faster.

- [Original observation report](reviews/observation-01/report.json), [summary](reviews/observation-01/summary.json) and [root independent verification](reviews/observation-01/root-independent-verification-01.json)
- [Original monitor ledger](reviews/observation-01/compiler-monitor.json) and [independent audit](reviews/observation-01/compiler-monitor.audit.json)
- [Original native terminal](reviews/observation-01/native-terminal.json), [native stdout](reviews/observation-01/native.stdout), [stderr](reviews/observation-01/native.stderr) and [Mac holder report](reviews/observation-01/mac-holder-report.json)

Lifecycle job `1a1ababc175-fc05-4f94` failed with exit 1 at the first compiler
sample. Its empty stage list and null candidate binary bind a failure before
fixtures; no lifecycle ABBA or saturation result is inferred. Original false
fields remain unchanged, and holder cleanup closed.

- [Unchanged failed parent report](reviews/lifecycle-failed-01/report.json), [native terminal](reviews/lifecycle-failed-01/native-terminal.json) and [root failure receipt](reviews/lifecycle-failed-01/root-failure-receipt-01.json)
- [Original failed monitor ledger](reviews/lifecycle-failed-01/compiler-monitor.json), [audit](reviews/lifecycle-failed-01/compiler-monitor.audit.json) and [Mac holder report](reviews/lifecycle-failed-01/mac-report.json)
- [Original native stdout](reviews/lifecycle-failed-01/native.stdout) and [stderr](reviews/lifecycle-failed-01/native.stderr)

## Actual natural quiet wait and rejected lifecycle attempt02

Natural quiet job `1a1abb2b75b-fc05-4fde` succeeded with exit 0 and 162 retained
samples, including a final 90.145574535-second quiet interval. Its result is
separate from both lifecycle workloads.

- [Original quiet report](reviews/lifecycle02-quiet-01/report.json), [native terminal](reviews/lifecycle02-quiet-01/native-terminal.json) and [independent cadence audit](reviews/lifecycle02-quiet-01/independent-cadence-audit.json)
- [Original quiet native stdout](reviews/lifecycle02-quiet-01/native.stdout) and [stderr](reviews/lifecycle02-quiet-01/native.stderr)

Lifecycle attempt02 job `1a1abcac847-fc05-509a` failed with exit 1 after all four
functional ABBA rounds and independent audits passed. The required live-cancel
comparison was **6.49615 → 5.54128 RPC/s (−14.699%)** and
**923.105 → 1,128.037 ms p95 (+22.200%)**, breaching the unchanged 0.95 throughput
and 1.10 p95 ratio gates. Controller CPU, sampled RSS, monitoring and owned
cleanup passed. The original report retains `passed=false`,
`adoption_passed=false` and `measurement_attribution_valid=true`.

- [Unchanged rejected parent report](reviews/lifecycle-attempt02-01/report.json), [gate report](reviews/lifecycle-attempt02-01/gates.json), [summary](reviews/lifecycle-attempt02-01/summary.json) and [ABBA report](reviews/lifecycle-attempt02-01/abba-report.json)
- [Root closed-rejected verification](reviews/lifecycle-attempt02-01/root-closed-rejected-01.json), [four-round index](reviews/lifecycle-attempt02-01/round-index.json) and [14-tool-test report](reviews/lifecycle-attempt02-01/tool-tests-report.json)
- [Original compiler-monitor ledger](reviews/lifecycle-attempt02-01/compiler-monitor.json) and [audit](reviews/lifecycle-attempt02-01/compiler-monitor.audit.json)
- [Original native terminal](reviews/lifecycle-attempt02-01/native-terminal.json), [native stdout](reviews/lifecycle-attempt02-01/native.stdout), [stderr](reviews/lifecycle-attempt02-01/native.stderr) and [Mac holder report](reviews/lifecycle-attempt02-01/mac-holder-report.json)

The [frozen lifecycle policy](reviews/lifecycle-attempt02-01/lifecycle-gate-policy.json)
and original gate report retain every required threshold. For
all-operations/launch/concurrent-cancel, controller CPU was respectively
0.39/0.12/0.07 seconds against ceilings 0.46/0.12/0.08, retaining the original raw
clock-tick tolerance and unrounded comparisons. RSS 17,744 KiB stayed below the
18,020 KiB ceiling. The cleanup receipt covers both outer processes, all ten
ABBA stages and the Mac owned agent; the failed gate process was reaped and its
original process group was absent. The full raw lifecycle archive and its four original independent round
summaries are now locally verified; this update verifies preserved bytes and
does not repeat the workload or perform new statistical analysis. No statistical or source-causal claim is made. Cancellation under direct
saturation was not executed after rejection. No unchanged-candidate lifecycle03
or gate relaxation is planned.

## Actual private phase03: no attribution

Original holder `1a1abddc5a0-fc05-5108` ended `failed`, exit 1. Its baseline is
qualified but unadopted R25; the other arm is its private instrumented build.
This is a separate diagnostic. C1 throughput ratio **0.949023740664614** failed
the unchanged **0.95** disturbance gate. Other diagnostic ratios and RSS passed,
but the parent/wrapper/bootstrap retain false outcomes and capacity attribution
remains prohibited.

- [Original parent](reviews/phase03-diagnostic/parent-report.json), [native analysis](reviews/phase03-diagnostic/native-analysis.json), [wrapper](reviews/phase03-diagnostic/wrapper-report.json) and [bootstrap](reviews/phase03-diagnostic/mechanism-monitor-bootstrap-report-03.json)
- [Native terminal](reviews/phase03-diagnostic/native-terminal.json), [single original read DTO](reviews/phase03-diagnostic/native-read.json), [stdout](reviews/phase03-diagnostic/native.stdout) and [stderr](reviews/phase03-diagnostic/native.stderr)
- [Monitor ledger](reviews/phase03-diagnostic/compiler-monitor.json) and [original validation](reviews/phase03-diagnostic/compiler-monitor-validation.json)
- [Independent rejection audit](reviews/phase03-diagnostic/capacity-phase03-rejection-audit-01.json) and [root closed-rejected receipt](reviews/phase03-diagnostic/root-closed-rejected-01.json)
- [Original Mac holder report](reviews/phase03-diagnostic/mac-holder-report.json) and [forwarded stdout](reviews/phase03-diagnostic/mac-forwarded.stdout)

The original native benchmark returned zero and its integrity/count checks
passed. The monitor independently passed 267 samples at 0.720244% of one CPU
core. Owned socket and Mac-agent cleanup closed. The audit preserves the frozen
wrapper's descriptive `original_parent_unchanged=false` field and explains its
never-updated initialization separately. The full native report and stderr bytes
are now preserved in the completely verified private07 archive. Its full
consumer preserves original outcomes and rechecks monitor proofs; it performs
no new phase-trace performance analysis. This rejected diagnostic provides no capacity
attribution and no causal explanation of the R26 lifecycle rejection.

## Actual archive-tool failures

R26 full export attempt01, job `1a1abf3aa03-fc05-5169`, failed with exit 1 and
zero completed archives when the text marker scan reached the ELF runtime before
its identity-only omission classification. Private diagnostic export06, job
`1a1ac07b969-fc05-51bc`, failed with exit 1 while requiring an absent
`mechanism-diagnostic-03/target-build`. Both are evidence-tool failures and ran no
workload. Their complete original native outputs and false outcomes remain intact.

| Original failure | Report and native custody | Failed source and separately prepared repair |
|---|---|---|
| R26 export01 | [Report](reviews/exporter-failures/r26-export01/report.json), [terminal](reviews/exporter-failures/r26-export01/native-terminal.json), [original read](reviews/exporter-failures/r26-export01/native-read.json), [stream derivation](reviews/exporter-failures/r26-export01/stream-derivation.json) | [Original source](reviews/exporter-failures/r26-export01/failed-exporter.py), [revision04 delta](reviews/exporter-failures/r26-export01/prepared-repair-delta.patch) |
| Private export06 | [Report](reviews/exporter-failures/private-export06/report.json), [terminal](reviews/exporter-failures/private-export06/native-terminal.json), [original read](reviews/exporter-failures/private-export06/native-read.json), [stream derivation](reviews/exporter-failures/private-export06/stream-derivation.json) | [Original source](reviews/exporter-failures/private-export06/failed-exporter.py), [revision07 delta](reviews/exporter-failures/private-export06/prepared-repair-delta.patch) |

The repair deltas alone do not prove a later operation succeeded. Actual later
capture receipts and all seven actual complete archive verifications are appended
below. Complete native custody and its exact three-part delivery are also verified.

## Actual captures and seven verified archives

R26 export02 `1a1ac1643b4-fc05-5220`, private export07
`1a1ac1a134e-fc05-5238`, and Mac capture01 `1a1ac2093c8-fc05-526c`
have strong successful original native terminals. The Mac capture's exact
[receipt](reviews/archive-QA-final-01/mac-capture/receipt.json),
[terminal](reviews/archive-QA-final-01/mac-capture/capture-native-terminal.json),
[original complete read](reviews/archive-QA-final-01/mac-capture/capture-native-read.json)
and all original transport responses are retained. Its stream is 660 stdout
bytes and zero stderr bytes. These capture results do not change original workload outcomes.

| Exact archive | Bytes | Actual local QA |
|---|---:|---|
| [qualification-01.tar.gz](evidence/qualification-01.tar.gz) | 3,339,674 | Complete |
| [ci-01.tar.gz](evidence/ci-01.tar.gz) | 307,232 | Complete |
| [observation-01.tar.gz](evidence/observation-01.tar.gz) | 3,465,581 | Complete |
| [lifecycle-01.tar.gz](evidence/lifecycle-01.tar.gz) | 2,002,792 | Complete, both original attempts preserved |
| [formal-holders-01.tar.gz](evidence/formal-holders-01.tar.gz) | 101,165 | Complete, 86 regular members |
| [diagnostic-holders-01.tar.gz](evidence/diagnostic-holders-01.tar.gz) | 42,124 | Complete, 59 regular members |
| [Private diagnostic full07](../r25/evidence/private-diagnostic-full-07.tar.gz) | 7,150,445 | Complete; 4,136 regular members, original failures preserved |

- [R26 four-archive full verifier result](reviews/archive-QA-final-01/r26-four-archive-verification.json): 9,581 regular members, exact original member/outcome preservation. The first relative-path local invocation failed before scanning; both [failed01](reviews/archive-QA-final-01/r26-operations/consumer-main-01.json) and [successful02](reviews/archive-QA-final-01/r26-operations/consumer-main-02.json) are retained. Only CLI paths changed.
- [Mac full verifier result](reviews/archive-QA-final-01/mac-independent-verification.json): one actual local invocation, 145 regular members, five holders × 22 original files, 105 original logs. SHA-256 `d77ff03153267a2f1cf7504cc05f14b51897b5a2efe9708c6347d90887f3c380`.
- [Independent Mac result review](reviews/archive-QA-final-01/mac-operations/independent-result-review-01.json) and [complete member index](reviews/archive-QA-final-01/mac-operations/archive-member-index-01.json). Only observation01 ended `succeeded`, exit 0; lifecycle01, lifecycle02, phase02 and phase03 remain `failed`, exit 1.
- [Formal cross-package proof](reviews/archive-QA-final-01/cross-package/formal-cross-package-proof-01.json): the three formal Mac retained/staged scripts, exact original terminals, forwarded report footers and parent inputs match their actual X230 archive members. The separate [private cross-package proof](reviews/archive-QA-final-01/private-cross-package/private-cross-package-proof-01.json) binds both failed diagnostic holders to private07, including retained/staged/installed bootstrap bytes, the three original forwarded records, original parent streams and phase03 original native terminal text.

The [private07 full verifier result](reviews/archive-QA-final-01/private07/full-archive-verification-01.json)
and original [assembly](reviews/archive-QA-final-01/private07/operations/assembly.json)
and [consumer](reviews/archive-QA-final-01/private07/operations/full_QA.json) operations
record one successful local invocation each. All seven archives contain 13,862
regular members. Verification preserves the original false outcomes and the
unknown installation; it does not upgrade the private diagnostic into capacity
attribution or product adoption.

The formal Mac archive is SHA-256
`78e41d26607392ddf596202fe7d2242939c52114961c5ce2f571c345f05afb87`;
the diagnostics archive is
`b2b4f9f23bb8203146804ef6a51cc1747a385859adae66cfd96755d32e06f975`.
The [current closure ledger](reviews/evidence-closure-final-01.json) records all
seven verified archive identities and the complete native-custody delivery.
The final branch lease and repository readback belong to the publication step. None of these verifications executes archived code or
replays a benchmark.

## Exact Git blob preparation

The [six-archive Git proof](reviews/git-blob-publication-final-01/publication-proof-01.json)
retains all six original create responses and their exact input identities.
Each returned object SHA equals the Git SHA-1 recomputed from the complete
locally verified archive and its byte-count header. The current connector
rejected binary readback through both the Git DATA JSON URL and `fetch_blob`;
both original errors are retained, and server binary-byte verification is
explicitly false. No tree, commit, branch reference or PR was changed by these
six blob creations. The [seventh blob proof](reviews/private07-git-blob-publication-final-01/publication-proof-01.json)
retains an initial `ReadTimeout` and one root-authorized exact-content Git
reconciliation that returned `999018f49c6290942805db6243555529f1a24257`.
Native custody uses the three exact part blobs below; no whole-archive blob
creation is claimed and no workload was repeated.

## Complete native custody and reconstruction

The [complete manifest](reviews/native-custody-final-01/manifest.json) and
[independent verification](reviews/native-custody-final-01/independent-verification-01.json)
cover 1,012 regular members, including 1,004 original files. The
[native coverage](reviews/native-custody-final-01/native-coverage-02.json) retains
35 original operations with strong terminal and complete dual-stream records,
plus installation `1a1abaf7904-fc05-4fba` with its original `launch_unknown`
classification and no inferred terminal. Original request digests remain in the
records; the checker matches host/executable/args/key/cwd and does not recompute
the full native request-digest algorithm.

The original four local packaging/verification commands all exited 0 once with
empty stderr; their [handoff and raw operations](reviews/native-custody-final-01/publication-handoff-01.json)
remain outside the sealed archive. The [old R25 custody archive](../r25/evidence/archive-transfer-custody-02.tar.xz),
Git blob `effcf7def…`, is reused without copying its body. This package includes the original failed exports,
all private07 transfer pages and preserved read failures, and the private07 Git
timeout/reconciliation. Ongoing R28 work is excluded.

The exact 18,895,848-byte archive has SHA-256
`0eb6a3ad7c0e6dd9f0fdc06dd07640ba2509723cee3b2df82befc56bc8bf6774`.
The [whole Git request](reviews/native-custody-whole-blob-rejection-01/explicit-size-rejection-01.json)
received the connector's explicit 16 MiB request-size rejection. Its unchanged
bytes are therefore published as three contiguous parts with a
[fixed manifest](evidence/native-operations-custody-01.tar.xz.parts/reconstruction-manifest.json)
and [minimal reconstruction program](evidence/native-operations-custody-01.tar.xz.parts/reconstruct.py).

| Part | Offset | Bytes | Confirmed Git blob SHA |
|---|---:|---:|---|
| [part-000.bin](evidence/native-operations-custody-01.tar.xz.parts/part-000.bin) | 0 | 6,500,000 | `aa410849f790d9ae0bf7b0d1d91a36328ab16935` |
| [part-001.bin](evidence/native-operations-custody-01.tar.xz.parts/part-001.bin) | 6,500,000 | 6,500,000 | `5e6fd47e6ec79dd16204165008f335067677ac4e` |
| [part-002.bin](evidence/native-operations-custody-01.tar.xz.parts/part-002.bin) | 13,000,000 | 5,895,848 | `43547c56651acdd8dbd2465dcf53c5d76d74b5c0` |

All three create calls succeeded on their first attempt. Their [original responses](reviews/native-custody-part-blobs-01/publication-proof-01.json)
and the [single successful local reconstruction](reviews/native-custody-part-blobs-01/local-reconstruction-verification-01.json)
bind every part and byte to the original fully verified archive. From the
repository root, with a fresh output filename:

```sh
python3 -I -B tools/x230/20261105/r26/evidence/native-operations-custody-01.tar.xz.parts/reconstruct.py --output native-operations-custody-01.tar.xz
```

The program verifies order/size/hashes, writes with exclusive creation and
executes no archive contents. The whole-file Git SHA `a4e3b1db…` remains a local
identity; it is not a claimed created object or repository download link.
Only the three actual part blobs are used in the tree.

## Final custody and publication preparation

The [current receipt reference index](reviews/receipt-reference-index-final-01.json) records
every included original body, its source path, repository destination, byte
length and SHA-256. Original JSON bytes were copied without re-encoding. Native
CI stdout/stderr retain the previously verified lossless reconstruction. The
index binds all seven verified companion archives and complete final native
custody, including the three actual part objects. The seven companion archive blob objects
have been created, but no evidence tree, commit or branch update is claimed here.

Observation has its actual passed original result; lifecycle01 and lifecycle02
have their actual failed originals, with the natural quiet success kept separate.
The decision is **R26 rejected**. All seven complete archives, all five holder
cross-package bindings and the complete native custody bundle are verified. The [current evidence bindings](reviews/evidence-closure-final-01.json)
and [complete original native coverage](reviews/native-custody-final-01/native-coverage-02.json)
give exact source identities and preserve the original unknown classification.
The local publication input's `git-tree-inputs-final-02.json` lists only present, hashed publication
files, using seven complete companion archive objects and the three actual
native-custody part objects. It never references the uncreated whole blob.
Prepared export tools or receipt materialization do not establish capture or
publication. The R25
rejection remains available in the [R25 evidence index](../r25/README.md).
Root retains the sole branch-lease/tree/commit/ref handoff. This evidence package makes no
R26 adoption, R28 test-pass, future-commit CI or all-blockers-closed claim.

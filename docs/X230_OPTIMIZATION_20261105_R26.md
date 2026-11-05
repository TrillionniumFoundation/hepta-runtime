# X230 R26: rejected by concurrent-cancellation performance gates

## Current disposition

**R26 is rejected and is not adopted.** Its original qualification, external
Rust CI and observation campaign passed, but lifecycle attempt02 failed the
frozen concurrent-cancellation throughput and p95 gates. Accepted R24 commit
`baab4def80be7af015b2e7a594cb302f66c4130e` remains the accepted production baseline.
The original lifecycle-attempt01 admission failure and the successful natural
quiet wait before attempt02 are retained as separate outcomes. The unchanged
candidate will not be rerun to seek a different gate result, and no lifecycle
attempt03 is planned.

This document is a local evidence-publication draft. It does not publish or
adopt the rejected candidate's source.

| Evidence | Actual result |
|---|---|
| Full original qualification | Passed all eight stages; 1,653 passed, 34 ignored, zero failed or retried |
| Exact external Rust workflow commands | Passed; all 1,653 completed cases were plain `PASS`, 34 ignored, zero retries |
| R26 observation throughput, latency, CPU and RSS | Original campaign passed every frozen nonregression gate |
| R26 lifecycle attempt01 | Failed the initial compiler admission check before fixtures; original failure retained |
| Natural quiet wait before lifecycle02 | Succeeded with the final 90.1456 seconds quiet; separate admission evidence |
| R26 lifecycle attempt02 | All four normal ABBA rounds and independent correctness audits passed; concurrent-cancellation throughput and p95 gates failed |
| R26 cancellation under direct saturation | Not executed after lifecycle02 gate rejection |
| Original hosted GitHub Actions at `bfa0d611…` | Push and PR runs completed successfully; their source remains accepted R24 |
| Hosted GitHub Actions for the R26 candidate source | No such run is established here |
| Private phase03 instrumentation diagnostic | Rejected by its C1 disturbance gate; capacity attribution prohibited |
| First R26 full export and private export06 | Failed archive-tool operations, preserved separately from workload results |
| Later R26 export02, private export07 and Mac capture01 | Original native operations succeeded; all seven archives, all five holder cross-package bindings and complete native custody are verified; final repository publication has separate lease/readback requirements |
| R26 adoption | Rejected; false |
| Subsequent R28 cache-only proposal | Prepared separately; no R28 test or measurement result is recorded here |

The [evidence index](../tools/x230/20261105/r26/README.md) links the exact qualified
source patch and original receipts. Successful inner stages do not replace the
failed original lifecycle outcome.

## Source changes and intended mechanism

R26 carries the qualified R25 cancellation-reserve implementation and adds one
selected change: construct the Python read-request JSON only in the nonpooled
Python branch that consumes it. Pooled reads and the separate jobctl branch avoid
building that unused seven-field object. The Python branch retains the same
fields, defaults, limit and payload. This removes an actual redundant
construction. The whole R26 candidate has now passed the recorded observation
nonregression campaign below; that comparison does not isolate this one change
or establish the cause or correction of R25's C1 regression. R25's
original observation rejection remains preserved in the [R25 report](X230_OPTIMIZATION_20261105_R25.md).

Existing-job cancellation still tries ordinary direct admission first and can
select the finite reserve only before submitting a child. Ordinary direct limits
are 16 admitted requests, 8 active children and 2 children per target; the reserve
allows 8 admitted cancellations and 1 active child. Mixed direct traffic is
bounded by 24 admitted requests, 9 active children and 3 children to one target.
These bounds apply to the direct transport, not the separate observation pool.
The reserve uses the original child custody, caller-drop, freeze, reap and
quarantine paths. It introduces no post-submission fallback or effect replay.
Cancellation availability under direct saturation remains unproved because the
normal lifecycle gate rejected this candidate before saturation was submitted.

The [complete patch](../tools/x230/20261105/r26/qualified-candidate-01.patch)
contains five files relative to the accepted, formatted R24 source:

| File | Change |
|---|---|
| `src/mcp/runtime/jobs.rs` | Cancellation routing and deferred Python read-request construction |
| `src/mcp/runtime/ssh.rs` | Internal ordinary/cancellation direct-admission dispatch |
| `src/mcp/runtime/ssh_direct.rs` | Bounded cancellation reserve sharing existing child custody |
| `src/mcp/runtime/ssh_direct_cancellation_tests.rs` | Eight cancellation-reserve regression cases |
| `src/mcp/runtime/ssh_direct_tests.rs` | Sibling test wiring and matching test support |

The qualified map contains 221 compiler inputs. Its SHA-256 is
`7099d5752076faab911394eb06246c6d2da86c0f9a8bf79faa3ab8403b85a50c`.
The accepted R24 `src` tree is `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`;
the qualified R26 `src` tree is `96c529bacbf2248df5765392f920984c90936159`.
The publication comparison uses corrected source index03. Index02 had compared
one pre-format R24 test file; the actual accepted pool-test bytes already match
R26 and are excluded from the patch. This correction happened locally before
any R26 source publication.

## Original qualification

Native job `1a1ab4cb0fc-fc05-4c3c` completed with `succeeded`, exit 0, complete
and durable original output. Qualification ran from 10:41:57 to 11:05:57 UTC on
2026-11-05. Format, format check, harness tests, Clippy, test build, isolated
tests, independent isolated-test audit and release build all returned zero.

The retained result is **1,653 passed, 0 failed, 34 ignored, 1,687 selected,
0 retries**. Preparation records no formatter changes, unchanged qualified
parent inputs and `candidate_adopted=false`. The
[original report](../tools/x230/20261105/r26/reviews/qualification-report-01.json)
is 83,737 bytes, SHA-256
`2ee6d3b65a04a883acf6200d2802f89f5c934b7f8ed9a3ffc5bfc805cf6fc69b`.
Its recorded runtime binary SHA-256 is
`75affab3a1e073b36563dcbdac9d727a54ef220eb2b086b45855572b16f6e467`.
Binary bodies are not included in this draft.

## Exact external Rust CI

Original native job `1a1ab7ecb60-fc05-4e4e` completed with `succeeded`, exit 0,
complete durable output and no automatic retry. It ran the exact workflow
commands against the same qualified source:

```sh
cargo check --locked --all-targets --all-features
cargo nextest run --locked --all-targets --all-features --test-threads 1 --retries 0 --no-fail-fast
```

A separate `cargo nextest list --locked --all-targets --all-features --message-format json`
recorded the complete inventory without changing either run command. The inventory
covers five targets, including the zero-case example, and 1,687 selected cases.
The independent output audit records **1,653 plain `PASS`, 34 ignored, 0 failed,
0 retries**. Its case-inventory SHA-256 is
`874de054557c19edef3c0cb291fb6dd75cde32706e5670b851808db0bf1f8cff`.

The [original CI report](../tools/x230/20261105/r26/reviews/rust-ci-report-01.json)
is 14,129 bytes, SHA-256
`2f3cdff70d1183f9316b95a8ec81ef165df5d094b5fa0b5e6ebe7a007ab410e6`.
It records unchanged source inputs, original child cleanup and no service changes.
This external run used Rust 1.95.0, pinned private nextest 0.9.137, offline Cargo
and the private qualified target directory. Those environment differences from
a clean hosted runner are retained. The independently observed hosted results
below bind a different, already published source commit.
R26 Python CI has not been run, and historical R25 Python results are not counted
as a new R26 execution.

## Original hosted CI: the earlier published head passed

The saved GitHub API observation at **2026-11-05 13:38:32 UTC** reports both
original runs completed with `conclusion=success`, each on attempt 1:

| Run | Event | Relevant completed jobs | Run updated at UTC |
|---|---|---|---|
| [42000460525](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42000460525) | Push | Exact-source job `127154057472` succeeded; the PR-only merge job was skipped | 13:30:37 |
| [42000474593](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/42000474593) | Pull request | Exact-source job `127154102946` and prospective-merge job `127154102660` succeeded | 13:20:14 |

Both runs identify head `bfa0d6113d675bb9f597baa474f913c3a12df37a` on
`perf/x230-r11-20261103`. The published head retains R24 production `src` tree
`b71cac25e2c2138837f27f3c74f6a2dc5c56b565`; it adds rejected R25 evidence.
The saved prospective-merge tree binding records the same complete tree for
merge object `46e7547d0e636e497819b0e0a7fa7f817bc4eb38`.

This closes the previously observed queue blocker for that original head.
The API supplies no cause for the scheduling delay, so none is assigned. The
[raw API responses and refresh summary](../tools/x230/20261105/r26/reviews/github-bfa-success/refresh-summary-02.json)
are preserved alongside the earlier tree/publication records, whose historical
queued fields remain unchanged. The successful run identities do not transfer
to the rejected R26 patch, an R28 proposal, or a later evidence commit.

## Original observation campaign

Native Mac holder job `1a1ab9c71ee-fc05-4f01` completed once with `succeeded`,
exit 0, lossless original native output and closed holder cleanup. The
[original parent report](../tools/x230/20261105/r26/reviews/observation-01/report.json)
and [summary](../tools/x230/20261105/r26/reviews/observation-01/summary.json)
record `passed=true`, `measurement_attribution_valid=true` and
`observation_gate_passed=true` with no rejection reasons. The comparison is
accepted R24 versus the same qualified R26 binary, using all frozen ABBA cells.

| Concurrency | Successful RPC/s, R24 → R26 | Throughput change | p95 ms, R24 → R26 | Controller CPU ms/call, R24 → R26 |
|---|---:|---:|---:|---:|
| 1 | 7.82070 → 7.88867 | +0.869% | 183.848 → 184.498 | 31.06771 → 31.51042 |
| 8 | 55.06966 → 54.49389 | −1.046% | 193.541 → 198.972 | 19.29688 → 19.24479 |
| 16 | 51.73525 → 55.42111 | +7.124% | 392.629 → 347.103 | 20.31250 → 20.00000 |

All three concurrency levels passed their separate throughput, p95 and CPU
nonregression thresholds. C16 p95 changed by −11.595%. These are results from
one finite campaign, with no confidence or general throughput-improvement claim.
The primary C8 throughput was slightly lower within the frozen nonregression
bound; no pooling with historical attempts changes that result.

Maximum sampled controller RSS was 18,760 KiB for R24 and 18,892 KiB for R26:
**+132 KiB**, below the combined 19,272 KiB ceiling. The 1 Hz compiler monitor's
independent audit passed 298 samples, with 297 required scheduled samples,
zero missed samples and no observed compiler. Its recorded cost was
**0.66993% of one CPU core**. Sampling does not rule out activity between samples;
controller RSS is a sampled process peak, and controller CPU excludes the Python
harness and remote processes. See the
[original monitor audit](../tools/x230/20261105/r26/reviews/observation-01/compiler-monitor.audit.json)
and [root verification](../tools/x230/20261105/r26/reviews/observation-01/root-independent-verification-01.json).

The original observation correctness canary and boundary drain/recovery also
passed. They do not substitute for the separately required lifecycle ABBA or
cancellation-reserve saturation proof.

## Original lifecycle attempt01: stopped before fixtures

Native holder job `1a1ababc175-fc05-4f94` completed with **`failed`, exit 1**.
Its [unchanged parent report](../tools/x230/20261105/r26/reviews/lifecycle-failed-01/report.json)
records an initial compiler-monitor failure, `stages=[]`,
`candidate_binary_sha256=null`, `passed=false`,
`measurement_attribution_valid=false` and `adoption_passed=false`. The report's
other false fields remain untouched. No lifecycle fixture or saturation workload
was submitted in that attempt.

The native stdout/stderr and original Mac holder report were retained, and the
holder's owned cleanup closed. The initial sample observed live compiler
processes whose ownership was not established by this evidence; this report
does not assign them to the candidate or to another actor. No process was killed
by this evidence handling. The
[root failure receipt](../tools/x230/20261105/r26/reviews/lifecycle-failed-01/root-failure-receipt-01.json)
binds the failed original operation.

## Natural quiet wait before lifecycle02

The separate original native job `1a1abb2b75b-fc05-4fde` completed with
`succeeded`, exit 0. Its [original report](../tools/x230/20261105/r26/reviews/lifecycle02-quiet-01/report.json)
and [independent cadence audit](../tools/x230/20261105/r26/reviews/lifecycle02-quiet-01/independent-cadence-audit.json)
retain 162 samples. Samples 143 through 161 cover a final quiet interval of
90.145574535 seconds. This was a natural wait, with no termination of unowned
compiler processes. It proves the recorded admission condition only and does
not turn either lifecycle outcome into a pass.

## Original lifecycle attempt02: performance rejection

Native Mac holder job `1a1abcac847-fc05-509a` completed with **`failed`, exit 1**.
The [unchanged parent report](../tools/x230/20261105/r26/reviews/lifecycle-attempt02-01/report.json)
is 76,823 bytes, SHA-256
`50b745129004ba2e8f85e179bf41930c84588f8bbbf015f3cbc03479b20dcb79`.
It retains `passed=false`, `adoption_passed=false` and
`measurement_attribution_valid=true`. The formal 90-second quiescence completed;
all 14 lifecycle-tool tests passed with zero skips; then the normal lifecycle
ABBA stage returned 1 because its performance gate rejected the candidate.

All four rounds completed their functional canary and independent audit. The
original [summary](../tools/x230/20261105/r26/reviews/lifecycle-attempt02-01/summary.json)
and [gate report](../tools/x230/20261105/r26/reviews/lifecycle-attempt02-01/gates.json)
retain 24 new starts, 48 cancellation calls and 48 same-key lookups across the
campaign, with zero automatic retries. Each arm contributes 60 measured RPCs,
including 12 launch and 12 live-cancellation calls, at concurrency six.

| Required group | RPC/s, R24 → R26 | Throughput change | p95 ms, R24 → R26 | p95 change | Frozen gate result |
|---|---:|---:|---:|---:|---|
| All operations | 7.22267 → 7.27292 | +0.696% | 920.387 → 905.717 | −1.594% | Passed |
| Launch | 5.35970 → 7.06214 | +31.764% | 1,316.645 → 869.105 | −33.991% | Passed |
| Concurrent cancellation | 6.49615 → 5.54128 | **−14.699%** | 923.105 → 1,128.037 | **+22.200%** | **Failed throughput and p95** |

The frozen policy requires R26/R24 throughput at least 0.95 and p95 at most
1.10 for each required group. Concurrent cancellation produced ratios
**0.8530095758** and **1.2220032067**, respectively. Better launch or aggregate
results do not offset this failed required group. The controller CPU checks
passed within the declared one-tick-per-phase-per-round tolerance:

| Required group | R24 controller CPU, seconds | R26 controller CPU, seconds | Frozen R26 ceiling, seconds |
|---|---:|---:|---:|
| All operations | 0.36 | 0.39 | 0.46 |
| Launch | 0.10 | 0.12 | 0.12 |
| Concurrent cancellation | 0.06 | 0.07 | 0.08 |

The original gate retains the unrounded floating-point values and comparisons.
Its [frozen policy](../tools/x230/20261105/r26/reviews/lifecycle-attempt02-01/lifecycle-gate-policy.json)
adds one raw clock tick per phase window: 0.10 seconds over the ten all-operation
windows, and 0.02 seconds over the two launch or cancellation windows. Maximum
sampled controller RSS was 17,508 KiB for R24 and 17,744 KiB for R26, **+236 KiB**,
within the combined 18,020 KiB ceiling.

The other phase comparisons remain descriptive in the original gate report.
This finite ABBA does not establish statistical significance or isolate a causal
source change; with 12 live-cancellation calls per arm, nearest-rank p95 is the
largest observed latency. The recorded rejection is sufficient to decline
adoption under the policy, without a causal claim or a changed threshold.

The [compiler-monitor audit](../tools/x230/20261105/r26/reviews/lifecycle-attempt02-01/compiler-monitor.audit.json)
passed all 150 recorded samples. The
[root closed-rejected verification](../tools/x230/20261105/r26/reviews/lifecycle-attempt02-01/root-closed-rejected-01.json)
records `waited_and_reaped=true`, process absence, and original process-group
absence for both outer stages and all ten ABBA child stages, including the
gate process that returned 1. The Mac holder's owned agent cleanup also closed.
These are successful cleanup results for a failed original campaign. The complete
raw lifecycle archive is now locally verified, including the four original
independent round summaries. This update verifies original bytes and their
report bindings; it does not execute a new workload or rerun the performance gates. The cancellation
saturation stage was not submitted after the rejection, so there is no
saturation result to infer.

## Private phase03: instrumentation disturbance rejected

The separate private diagnostic holder job `1a1abddc5a0-fc05-5108` completed
with **`failed`, exit 1**. This experiment compares the qualified but unadopted
R25 baseline with its private instrumented build. It is separate from the R24
versus R26 adoption comparison. Its original parent, wrapper and bootstrap keep
their false result and attribution fields.

The native observation command returned zero. The original analyzer retained
0 failed, 2,304 measured, 288 warmup and 72 preflight/restart calls, totaling
2,664. Both instrumented-round analyzers returned zero, and the parent verified
six measured cells with 12,096 events and zero crossing events each. It also
verified eight complete stderr identities. These original integrity checks do
not authorize performance attribution after the disturbance gate fails.

| Concurrency | Instrumented/baseline throughput | p95 ratio | Controller CPU/call ratio | Disturbance result |
|---|---:|---:|---:|---|
| 1 | **0.949023740664614** | 1.0049965332 | 1.0457685665 | **Throughput failed** |
| 8 | 1.0569434988 | 0.8995376878 | 0.9986824769 | Passed |
| 16 | 0.9831597196 | 1.0446467485 | 0.9987163030 | Passed |

This diagnostic's frozen limits are throughput at least 0.95, p95 at most 1.10,
controller CPU/call at most 1.05, and sampled RSS growth at most 4,096 KiB. C1
throughput is 5.0976% lower and misses its cutoff by 0.000976259335386. The
1,648 KiB RSS increase and all other disturbance checks passed. The original
decision remains **capacity attribution prohibited**; the cutoff was not
rounded down or relaxed, and no unchanged-binary repeat is proposed.

The independent monitor recomputation passed 267 samples with no compiler
observed and recorded 0.720244% of one CPU core. This retains the one-Hz sampling
limitation. The wrapper retained its original streams; its owned socket
directory was verified empty, removed with the held identity, and its descriptor
closed. The original Mac agent was reaped and its owned paths were absent.
See the [parent report](../tools/x230/20261105/r26/reviews/phase03-diagnostic/parent-report.json),
[root closed-rejected proof](../tools/x230/20261105/r26/reviews/phase03-diagnostic/root-closed-rejected-01.json)
and [independent diagnostic audit](../tools/x230/20261105/r26/reviews/phase03-diagnostic/capacity-phase03-rejection-audit-01.json).

The independent audit also identifies a descriptive wrapper field,
`original_parent_unchanged`, that was initialized false and never reassigned.
Its original false value is preserved; the separate source-identity comparisons
and absence of a postcheck error are recorded explicitly. This annotation
changes no performance or attribution gate. The full 3,567,097-byte native
report and controller stderr bodies are now included in the completely verified
private07 archive. The unchanged full consumer checks original member bytes,
monitor proofs and preserved outcomes; it does not rerun the phase workload or
perform a new phase-trace performance analysis. No phase-timing explanation for R26's lifecycle rejection follows
from this rejected diagnostic.

## Archive-tool failures are retained

Two original export operations failed after the measured workloads had ended:

| Operation | Original native job | Actual outcome and recorded cause |
|---|---|---|
| R26 full export attempt01, tool revision03 | `1a1abf3aa03-fc05-5169` | Failed, exit 1; the text marker scan reached `qualification-01/hepta-runtime` before the ELF identity-only omission classification; zero archives completed |
| Private diagnostic export06 | `1a1ac07b969-fc05-51bc` | Failed, exit 1; `FileNotFoundError` for the absent `mechanism-diagnostic-03/target-build` directory; `export_completed=false` |

Both originals have complete durable native output, zero automatic retries and
`no_workload_executed=true`. Their
[R26 failed report](../tools/x230/20261105/r26/reviews/exporter-failures/r26-export01/report.json)
and [private failed report](../tools/x230/20261105/r26/reviews/exporter-failures/private-export06/report.json),
exact terminal/read DTOs, decoded native streams and failed exporter sources
are included. The prepared repair deltas retain those failures, correct the
specific export handling, and use fresh output paths. The original failures remain intact after the later archive verification.
These failures affect evidence capture; they do not
alter any original qualification, functional, performance or cleanup result.

## Actual complete archive verification and Mac custody

The later original captures succeeded without replacing earlier failures:
R26 export02 was job `1a1ac1643b4-fc05-5220`, private export07 was
`1a1ac1a134e-fc05-5238`, and five-holder Mac capture01 was
`1a1ac2093c8-fc05-526c`. Their original native results remain distinct from
workload and adoption outcomes. The Mac capture's complete original native
stream is 660 stdout bytes and zero stderr bytes.

The [unchanged R26 full consumer result](../tools/x230/20261105/r26/reviews/archive-QA-final-01/r26-four-archive-verification.json)
now verifies all four downloaded archives and **9,581 regular members**.
Its original first local invocation rejected a relative archive argument before
scanning; its second invocation used absolute paths and exited zero. Both
[original operation records](../tools/x230/20261105/r26/reviews/archive-QA-final-01/r26-operations/consumer-main-01.json)
and [the successful invocation](../tools/x230/20261105/r26/reviews/archive-QA-final-01/r26-operations/consumer-main-02.json)
are retained. No consumer source, archive data or performance gate changed,
and no native workload was repeated.

The [Mac full consumer](../tools/x230/20261105/r26/reviews/archive-QA-final-01/mac-independent-verification.json)
completed once with exit zero. Its proof has SHA-256
`d77ff03153267a2f1cf7504cc05f14b51897b5a2efe9708c6347d90887f3c380`.
The two archives contain **145 regular members**, including the exact 22 original
files for each of five holders: 110 holder files and 105 original logs. The
[separate result review](../tools/x230/20261105/r26/reviews/archive-QA-final-01/mac-operations/independent-result-review-01.json)
checks complete gzip framing, member bytes, native streams, retained source,
foreground output, original agent reaping and owned-path absence. This is the
original holder closure plus the collector's metadata witness; no new live-host
cleanup probe was performed during local verification.

| Archive | Bytes | Current local verification |
|---|---:|---|
| [R26 qualification](../tools/x230/20261105/r26/evidence/qualification-01.tar.gz) | 3,339,674 | Complete original bytes and member/outcome audit passed |
| [R26 CI](../tools/x230/20261105/r26/evidence/ci-01.tar.gz) | 307,232 | Complete original bytes and member/outcome audit passed |
| [R26 observation](../tools/x230/20261105/r26/evidence/observation-01.tar.gz) | 3,465,581 | Complete original bytes and member/outcome audit passed |
| [R26 lifecycle, both original attempts](../tools/x230/20261105/r26/evidence/lifecycle-01.tar.gz) | 2,002,792 | Complete original bytes and member/outcome audit passed |
| [Mac formal holders](../tools/x230/20261105/r26/evidence/formal-holders-01.tar.gz) | 101,165 | 86 regular members; three original formal holders verified |
| [Mac diagnostic holders](../tools/x230/20261105/r26/evidence/diagnostic-holders-01.tar.gz) | 42,124 | 59 regular members; two original failed diagnostic holders verified |
| [Private diagnostic full history](../tools/x230/20261105/r25/evidence/private-diagnostic-full-07.tar.gz) | 7,150,445 | Complete original bytes; 4,136 regular members and preserved failures verified |

The formal Mac archive SHA-256 is
`78e41d26607392ddf596202fe7d2242939c52114961c5ce2f571c345f05afb87`;
the diagnostic Mac archive SHA-256 is
`b2b4f9f23bb8203146804ef6a51cc1747a385859adae66cfd96755d32e06f975`.
Full source/archive/verification identities are listed in the
[current closure ledger](../tools/x230/20261105/r26/reviews/evidence-closure-final-01.json).

| Original Mac holder | Original native result retained |
|---|---|
| observation01 — `1a1ab9c71ee-fc05-4f01` | Succeeded, exit 0 |
| lifecycle01 — `1a1ababc175-fc05-4f94` | Failed, exit 1 |
| lifecycle02 — `1a1abcac847-fc05-509a` | Failed, exit 1 |
| phase02 — `1a1ab6ef44c-fc05-4dd3` | Failed, exit 1 |
| phase03 — `1a1abddc5a0-fc05-5108` | Failed, exit 1 |

The [formal cross-package proof](../tools/x230/20261105/r26/reviews/archive-QA-final-01/cross-package/formal-cross-package-proof-01.json)
also binds the three formal holders to the actual X230 archives: retained and
staged Mac scripts equal installed X230 source, original native terminal bytes
match exactly, the forwarded footer identifies the actual parent report and
retains its original flags, and the parent's input matches the archived input.
The [private phase02/03 cross-package proof](../tools/x230/20261105/r26/reviews/archive-QA-final-01/private-cross-package/private-cross-package-proof-01.json)
now binds both diagnostic holders to the complete private07 archive. Their
staged and retained Mac bootstrap bytes match installed X230 source; all three
forwarded source/wrapper/final records match the archived reports, and the
wrapper binds the original parent source and streams. Phase03 also contains
the identical original native terminal text inside the archived export input.
Phase02 native custody remains covered by its original Mac/native records;
no duplicate X230 terminal member is invented. Both original failures remain
failed. Complete native-operation custody is now verified below; the repository
publication step still requires its own fresh branch lease and readback.
Capture and archive-verification success do not adopt R26 or authorize capacity
attribution from the rejected private phase03 diagnostic.

## Exact archive Git objects

All seven locally verified archive bodies now have immutable Git blob objects.
The [original create responses and input identities](../tools/x230/20261105/r26/reviews/git-blob-publication-final-01/publication-proof-01.json)
record six sequential create calls with zero retries. Each returned SHA matches
SHA-1 of the exact Git blob header, including byte count, followed by the complete
locally verified archive body. This prepares content objects; it does not update
a repository tree, commit, branch or PR. The [private07 Git proof](../tools/x230/20261105/r26/reviews/private07-git-blob-publication-final-01/publication-proof-01.json)
retains its initial `ReadTimeout` and one explicitly authorized reconciliation
with exactly the same content, encoding and repository. That second call
returned `999018f49c6290942805db6243555529f1a24257`, the independently computed
content address. It was a Git object reconciliation and did not repeat a
workload.

The current connector rejected binary readback through both the Git DATA JSON
URL and `fetch_blob`. Both original errors are preserved. This proof therefore
claims matching create-returned content identities and complete local QA; it
does not claim a successful server binary-byte fetch. Native custody is
delivered through the separately verified contiguous parts described below.

## Complete original native-operation custody

The [native-custody manifest](../tools/x230/20261105/r26/reviews/native-custody-final-01/manifest.json)
and [independent verification](../tools/x230/20261105/r26/reviews/native-custody-final-01/independent-verification-01.json)
bind **1,012 regular members**, including **1,004 original files**. The archive
is 18,895,848 bytes, SHA-256
`0eb6a3ad7c0e6dd9f0fdc06dd07640ba2509723cee3b2df82befc56bc8bf6774`.
It retains the original 401-file inventory, all 38 private07 successful transfer
batches and the preserved failed read attempts, actual request/start/status/read
records, the seven companion-archive proofs and their Git responses. The first
private07 Git timeout and its exact-content reconciliation are included.

[Original native coverage](../tools/x230/20261105/r26/reviews/native-custody-final-01/native-coverage-02.json)
accounts for **36 observed operations: 35 with strong terminal records and
complete original stdout/stderr, plus one preserved `launch_unknown`
installation, `1a1abaf7904-fc05-4fba`**. That installation retains its original
unknown classification and has no inferred terminal. A separate read-only probe
or subsequent successful installation does not replace its original record.
Request source objects are matched by host, executable, arguments, idempotency
key and working directory; their original native request digests are retained.
The custody checker does not claim to independently recompute those digests.

The [original snapshot, coverage, build and verifier operations](../tools/x230/20261105/r26/reviews/native-custody-final-01/publication-handoff-01.json)
all completed once with exit 0 and empty stderr. The independent verifier checks
all member bytes and USTAR metadata, the exact XZ end and checksum, the original
source identities, and all seven companion links. The sealed bundle is unchanged.
Its own packaging/verifier logs and later Git upload responses remain outside
the archive to avoid self-reference. The previous [R25 transfer-custody archive](../tools/x230/20261105/r25/evidence/archive-transfer-custody-02.tar.xz),
Git blob `effcf7defa03a9b3b7e5c494fecc5409279341b3`, is reused without duplicating its body.
R28 work is outside this package.

### Exact three-part delivery

The whole-archive create request received an explicit
[HTTP 400 size rejection](../tools/x230/20261105/r26/reviews/native-custody-whole-blob-rejection-01/explicit-size-rejection-01.json):
its 25,194,464 base64 characters exceeded the connector's 16 MiB MCP request
limit. The original archive was then divided into three contiguous byte ranges,
without recompression or member changes. The
[fixed reconstruction manifest](../tools/x230/20261105/r26/evidence/native-operations-custody-01.tar.xz.parts/reconstruction-manifest.json)
and [reconstruction script](../tools/x230/20261105/r26/evidence/native-operations-custody-01.tar.xz.parts/reconstruct.py)
identify the actual repository files:

| Part | Offset | Bytes | Actual Git blob SHA |
|---|---:|---:|---|
| [part-000.bin](../tools/x230/20261105/r26/evidence/native-operations-custody-01.tar.xz.parts/part-000.bin) | 0 | 6,500,000 | `aa410849f790d9ae0bf7b0d1d91a36328ab16935` |
| [part-001.bin](../tools/x230/20261105/r26/evidence/native-operations-custody-01.tar.xz.parts/part-001.bin) | 6,500,000 | 6,500,000 | `5e6fd47e6ec79dd16204165008f335067677ac4e` |
| [part-002.bin](../tools/x230/20261105/r26/evidence/native-operations-custody-01.tar.xz.parts/part-002.bin) | 13,000,000 | 5,895,848 | `43547c56651acdd8dbd2465dcf53c5d76d74b5c0` |

All three original create calls returned the expected content address on their
first attempt; [the complete part publication proof](../tools/x230/20261105/r26/reviews/native-custody-part-blobs-01/publication-proof-01.json)
preserves their responses. One actual local reconstruction exited 0 and was
compared byte for byte with the original complete archive; its
[verification receipt](../tools/x230/20261105/r26/reviews/native-custody-part-blobs-01/local-reconstruction-verification-01.json)
retains the exact result. From a checkout, choose a fresh output path:

```sh
python3 -I -B tools/x230/20261105/r26/evidence/native-operations-custody-01.tar.xz.parts/reconstruct.py --output native-operations-custody-01.tar.xz
```

The script checks the fixed manifest, order, sizes, per-part hashes and full
archive identity, creates the output exclusively, and executes no archive
contents. The whole-file Git SHA `a4e3b1db060e3b816acc13743abe9f5693ec4b4a`
is a local content identity only: no successful creation of that whole blob is
claimed. The published objects are the three actual part blobs above.

## Rejection and evidence custody

R26 remains rejected even though qualification, external CI, observation,
lifecycle functionality, monitoring and cleanup passed. Both original failed
lifecycle attempts remain unchanged. No unchanged-candidate retry, lifecycle
attempt03 or acceptance-threshold relaxation is planned. The qualified source
patch is retained as an auditable rejected proposal; accepted R24 stays active.

The original qualification/CI receipts, passed observation receipts, failed
lifecycle-attempt01 receipts, successful quiet-wait receipts and rejected
lifecycle-attempt02 receipts are included without re-encoding. This revision
also retains the rejected phase03 diagnostic, actual hosted-CI API outcomes and
both original export failures, followed by the successful capture receipts above.
All seven archives now have complete local verification, covering 13,862
regular members. The [private07 full verifier result](../tools/x230/20261105/r26/reviews/archive-QA-final-01/private07/full-archive-verification-01.json)
and both original local [assembly](../tools/x230/20261105/r26/reviews/archive-QA-final-01/private07/operations/assembly.json)
and [full-verifier invocations](../tools/x230/20261105/r26/reviews/archive-QA-final-01/private07/operations/full_QA.json)
record one successful execution each, without code/data changes or retries.
All five holder cross-package bindings and complete original native-operation
custody are verified. The
[current receipt index](../tools/x230/20261105/r26/reviews/receipt-reference-index-final-01.json)
distinguishes locally present bodies from remote-only identities, and the
[current evidence bindings](../tools/x230/20261105/r26/reviews/evidence-closure-final-01.json)
record completed evidence custody while leaving the fresh publication lease
and final repository readback to the root publication step.

The [historical native custody set](../tools/x230/20261105/r26/reviews/native-custody-required-04.json)
is preserved alongside the complete final inventory and actual coverage above.
A complete decoded stdout does not replace its original API pages. The root
publication process must recheck the branch lease, construct and verify the
intended evidence-only tree with accepted R24 source unchanged, and retain the
actual commit/ref readback. The seven verified archive
blob objects and three native-custody part objects have been created without
changing any tree, commit, reference or production source.

R28 is a separately prepared cache-only proposal. No R28 qualification,
measurement or adoption result is established here. Accepted R24 remains active,
and no claim is made that all optimization blockers are closed.

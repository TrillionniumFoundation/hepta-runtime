# X230 R4: bounded known-identity refresh and independent SSH maintenance

## Status and source boundary

This iteration continues [PR #77](https://github.com/TrillionniumFoundation/hepta-runtime/pull/77)
at exact source commit `f0f1c1da4e62404fc800df0f186db5948b4ad38d` (R3).
The [R3 integration report](X230_OPTIMIZATION_20261028.md), qualification receipts
and measurements remain historical evidence for that source. They are not reused
as R4 test or performance results.

R4a and R4b are retained rejected performance candidates. R4b passed its complete
correctness qualification, but its subsequent release MCP comparison lost 18.624%
of cold C4 throughput. R4c completed an early release comparison after removing
waiting by requests outside the active scan's frozen target set. R4d then tested
earlier bounded registration, but its cold controller CPU cost remained near the
baseline; that extra registration path was not adopted.

**R4e is accepted for this iteration**, based on R4c with a bounded queue of recently
validated identities used to choose scan targets. It does not include R4d's early
registration. Its release MCP ABBA comparison completed all 5,184 calls and
showed the targeted concurrent throughput and CPU gains, with the regressions
recorded below. **R4e has completed all eight exact-source qualification gates:**
1,522 Rust tests passed, 0 failed and 25 were explicitly ignored; all 57 Python
harness tests passed. The final isolated Rust comparison also completed. The
qualified source map and release ELF match the measured diagnostic artifact.
Native validation has also completed all eight stages once, including six-host
controller-crash recovery and its configured 120-second file soak. The separate
360-second extended soak also completed once, with 7,104 successful measured
calls and no failures. These results support an empirical stopping point for
this implementation round, with the costs and remaining work recorded below.
The original evidence package has been exported and every retained file hash
verified. Publication uses the existing
[`perf/x230-concurrency-recovery-20261028` branch](https://github.com/TrillionniumFoundation/hepta-runtime/tree/perf/x230-concurrency-recovery-20261028)
and [PR #77](https://github.com/TrillionniumFoundation/hepta-runtime/pull/77).
The hosting commit identifies this report's published bytes; current remote-head
verification and GitHub CI outcomes are recorded on the PR.

R4 changes two production paths:

1. Concurrent refreshes of previously verified strict identities can share a
   complete registry scan for a bounded set frozen before the first receipt.
   R4e chooses that set from admitted workers and recent strict identities; only
   actual admitted workers may receive a result. First observations and absent
   keys retain their original parallel worker paths.
2. SSH observation-pool maintenance retains the original cleanup owner without
   blocking the actor from admitting work for other hosts during a slow retirement.

There is no new persistent job index, queue, effect-owner authority or output
ledger. The original durable receipts, start lanes, admission fences and
terminal-publication barriers remain in use. This document records a source
candidate and isolated X230 validation; it does not announce service installation
or production ownership transfer.

The R3 runtime used as the reference is a **retained qualified artifact on X230**,
not an asserted running production service. The initial X230 inspection did not
establish a standalone resident Hepta Runtime server unit. An operator job is not
evidence of such a deployment.

| Identity | Value / evidence status |
| --- | --- |
| Parent source | `f0f1c1da4e62404fc800df0f186db5948b4ad38d` |
| Retained R3 runtime SHA-256 | `5e670e58d1c8067df594fcc256a2b88bd52cb60a443cadb36e2a7dc0f49effa7` |
| R3 reference source path | `/home/qian/hepta-runtime-optimization-20261028/source-r3` |
| Historical R4b compiler-input map | 192 compiler inputs, retained as [source-map-r4b.json](../tools/x230/20261028/evidence/r4/source-map-r4b.json). SHA-256 `764a406e4eb08ad380996f793315cebbe275bab5b00a8bc23af4a9c2b3deaac5`. These inputs are frozen as R4b and do not qualify R4e. |
| Historical qualified R4b release SHA-256 | `5cadde76ecfa7f5de5be9450668a249968cce5d81b810df672e5f38a9c1bae5e` |
| R3-control libtest source / executable | `source-r4-control`; SHA-256 `73e538f910786b4675975305ec25188eadf6b23a5a1cc14725bfe8d3efdea3fe`. Test-only source changes are described below. The original control report and source-difference receipt are retained as `control-r4/report.json` and `control-r4/control-source-diff.json` in the [original evidence archive](../tools/x230/20261028/evidence/r4/evidence-package.tar.gz). |
| Rejected R4a libtest source / executable | Retained `source-r4a`; SHA-256 `09e987f2c2a8f5f456578b409befb83a6b10aed6399bf4a75bb6d13a006da1da`. |
| R4b diagnostic libtest source / executable | `source-r4`; SHA-256 `c9069ee70d10f72a36660a6f87c0039da38eeb194356e2da1e2fa009f0c62a07`. This is a test executable, not the qualified release artifact. |
| Historical R4b qualification result | All eight gates passed: 1,513 Rust cases passed, 0 failed, 25 ignored; 57 Python harness tests passed. Qualification report SHA-256 `431af6273220311b8e7bd9c4542bc0daf4db291c21e6525ec252e6ed4da0aa8b`. Subsequent performance rejection does not change this correctness result. |
| Historical R4c diagnostic source | `/home/qian/hepta-runtime-optimization-20261028/source-r4c`. The release comparison completed; its source map, runtime and report identities are recorded below. It did not receive complete qualification. |
| Historical R4d diagnostic source | `/home/qian/hepta-runtime-optimization-20261028/source-r4d`. Its completed release comparison and exact identities are recorded below. Early registration was not adopted; complete qualification was not started. |
| Qualified R4e source | `/home/qian/hepta-runtime-optimization-20261028/source-r4e`. Its own eight qualification gates passed. The 192-input source map and final runtime match the completed release MCP comparison; the qualified libtest executable was used for the final Rust comparison. Exact bindings are recorded below. |
| GitHub publication | The commit containing this report on `perf/x230-concurrency-recovery-20261028`, continuing [PR #77](https://github.com/TrillionniumFoundation/hepta-runtime/pull/77). The [publication boundary](../tools/x230/20261028/evidence/r4/publication-boundary.json) binds the 14 intended code changes to the exact qualified source and R3 parent. |

The R3-control, R4a and R4b diagnostic source directories are beneath
`/home/qian/hepta-runtime-optimization-20261028/`. The benchmark runner retained
their compiler-input maps and checked source and executable hashes before,
between and after its processes. R4b's formal qualification was a separate
completed run. R4e has its own completed qualification and artifact identities;
the historical R4b receipts remain separate.

## Cold registry lookup design

R3 already moves registry work off the async executor and retains a semaphore
permit until its actual blocking worker finishes. At most four such workers may
run. A caller cancelled while waiting for a permit submits no work; cancelling a
caller after admission does not erase the running worker's ownership.

The remaining repeated work occurs when different keys miss the positive cache
at the same time. Each lookup previously decoded the complete history even when
another admitted worker was already checking the same registry generation.
R4 adds an in-process coordination object to the existing reuse cache. The
following receipt-validation rules are retained in R4e. The R4c waiting policy
and R4e's additional target selection are specified separately below:

- Only a reliable content watch, a missing positive hit and retained strict
  original ownership permit registration. Warm hits, first observations and new
  keys do not register or wait for the cold gate. Registration is bounded by the
  four-worker limit and a per-demand byte limit.
- Registration precedes the worker's required strict receipt read. Other admitted
  refreshes may join during this existing I/O; there is no batching sleep, delay
  or additional queue. The worker must still pass its own original strict read
  before acquiring the gate or consuming a shared hint.
- A cold-scan gate permits one leader at a time to perform a shared scan.
  Independent full scans can still run within the original worker limit. Warm
  hits return through the original path before this gate.
- The leader freezes other registered target keys and selected recent strict
  identities before reading the first receipt. A later demand may join only if
  its identity was already covered; it cannot expand that frozen target set.
- Every JSON receipt still receives the original guarded open, bounded read,
  complete decode, filename/identity check and final metadata checks. The leader
  tracks uniqueness for each frozen target while performing this same scan.
- Only a unique, existing `launched` record can produce a hint. A hint contains
  its original ID, complete decoded-record digest and the successful scan epoch;
  it is not a complete retained record or an authorization to launch.
- A waiting worker verifies a reliable matching content-watch generation,
  strictly rereads its original receipt, checks the digest and identity, and
  verifies the epoch again. It then passes through the existing ownership and
  positive-cache publication checks.

Hints are limited by a separate 16 KiB byte budget and live only while an admitted
worker for their key remains registered. RAII cleanup drops the demand and its
hint when the last corresponding worker exits, including error and unwind paths.
Speculative candidates do not fill or evict the retained in-process `known`
ownership map. A matching positive hit still requires retained refusal evidence.

### Preserved refusal and fallback behavior

| Condition | R4 behavior |
| --- | --- |
| Unknown key | No shared negative cache; complete original lookup remains required. |
| Pending, unknown or failed launch | No launched hint; retain original scan/reconciliation path. |
| Duplicate owner for a frozen target | That target receives no hint. Its duplicate marker cannot be resurrected by a third record. A healthy different target is not newly rejected solely for that duplicate. |
| Unrelated malformed or unsafe JSON | The complete scan fails; no partial cohort result is published. |
| Content generation changes during scanning | Preserve the original maximum of three scan attempts; discard candidates from each failed attempt. Only the successful attempt's epoch can label a hint. |
| Root path, inode, device, ownership or mode changes | Preserve the existing refusal; do not reset history to make the new root acceptable. |
| Missing, lost or re-armed content watch | Old hints cannot be reused; the original double complete scan/fingerprint fallback remains. |
| Legacy readable 0644 or 1–4 MiB receipt | A failed optional strict hint read falls back to the original compatibility scan. It does not invent strict ownership. |
| Previously strict ownership | Later permission widening, missing/rebound identity or failed strict verification remains a refusal. |
| Caller cancellation | The original worker retains the permit, registered demand and actual work lifetime; no replacement effect is authorized. |

The first R4a candidate allowed every cold lookup to enter the gate. Its X230
ABBA comparison found absent-key throughput regressions of 51.3% at C4 and 53.4%
at C8. That policy was rejected, and its exact source, executable and raw results
were retained. R4b limits sharing to refreshes of known strict identities, so
unknown/new keys retain the original independent workers. Previously known
refreshes without a usable hint can still require their own complete scan.
No claim that all O(N) lookup work has been removed follows from this design.

### R4c: wait only for a target covered by the frozen scan

R4c changes the waiting policy in [the registry lookup](../src/mcp/runtime/jobs.rs).
At C4, the release MCP workload submits six original keys through four client slots;
completion of an earlier request can admit another key after a leader has frozen
its targets. That late key cannot safely use a partially observed history. R4b
nevertheless made it wait for the gate before performing its own complete scan.
R4c lets such a key use the original independent full scan, with the same actual
worker permit and registry read fence. No batching sleep, yield or artificial
admission window is introduced.

After the worker passes its original strict receipt read, routing is:

1. Try an existing hint using the original complete digest, identity and epoch
   checks. Check gate poison before and after that attempt so an already poisoned
   gate cannot be bypassed by a previously valid hint.
2. If no hint is usable, try to acquire the gate without waiting. A worker that
   acquires it rechecks for a hint published in the intervening interval. If a
   scan is still necessary, it becomes the leader.
3. The leader takes one state snapshot that produces both the actual scan targets
   and active membership. Membership contains only those other target identities,
   excludes the leader's own key, and is bounded by the existing admitted-demand
   limit. A later registration cannot join this already frozen set.
4. If the gate is busy, a worker waits only when its identity appears in the
   published active target set. A nonmember, including a worker that observes
   the short interval before the leader has published membership, performs the
   original complete scan with an empty shared cohort. Missing membership permits
   extra independent work; it never creates authority to use a partial scan.
5. A member that acquires the gate tries the completed hint and releases the gate.
   If the hint is absent or no longer passes validation, its original complete
   scan starts only after that release. It does not become another serial scan
   leader merely because it waited for the previous one.

Only a leader publishes cohort hints, and only after the existing full-scan and
final ownership checks succeed. Active membership is a scheduling fact, not a
receipt-verification result. It cannot authorize a return value, absence or new
effect. Independent fallbacks retain strict rereads, complete history decoding,
duplicate detection, root/epoch validation and the final `known` ownership checks.

The leader's RAII guard owns the original gate for the scan's lifetime. It clears
active membership before unlocking, including on error and panic; cleanup can
recover the state lock to remove the membership without clearing its poison or
treating a failed worker as successful. Gate acquisition still refuses poison.
Cancelling the async caller does not drop this guard, its demand or its semaphore
permit while the actual blocking worker is running.

Mutex admission is not FIFO. A previously admitted member can encounter a later
leader that acquires the gate first; R4c does not promise that it waits for only
its original leader. Whatever the scheduling order, it must independently
validate any hint, and a failed hint leads to an unlocked complete scan. The
completed R4c diagnostic is reported below; the R4b microbenchmark savings are
not R4c results. R4e retains this routing while extending the identities that a
leader may cover from the start of its scan.

### R4e: predict a bounded set of recent strict identities

R4e starts from R4c, without the first-epoch-probe registration added in R4d.
Demand registration still requires the original reliable watch, missing positive
hit and retained strict ownership. The new queue predicts which other identities
an already necessary complete scan should cover. It contains only `(host, key)`
pairs, with no receipt ID, digest, epoch, result or effect authority, and is never
persisted. Controller restart reconstructs it empty.

The queue changes only inside the existing successful cold positive-hit commit
block: original ownership must be retained with the same ID, strict verification
must succeed, the final epoch must match, the content watch must be reliable and
the original record must be launched. A commit removes an existing copy and moves
the identity to the newest position, evicting only prediction entries as needed.
Warm fast returns do not update the queue. Neither queue eviction nor prediction
can evict `known`, invent refusal evidence or bypass the original cache-capacity
conditions. Legacy, missing, pending and failed lookups do not populate it.

After acquiring the gate, a leader briefly locks the reuse cache and checks at
most eight recent identities with individual `known.get` calls. It checks the
registry root and strict status, copies the eligible keys newest first, and
releases that lock before taking the cold-state lock. It never walks the full
ownership map. In one state-lock snapshot, all distinct actual other demands are
selected first; recent identities fill the remaining capacity. The leader's own
identity and duplicates are excluded. Prediction strings are moved into targets,
and unused snapshot entries are dropped before active membership is cloned.

| Structure | Independent bound and meaning |
| --- | --- |
| Recent identity queue | At most 8 entries and 2 KiB total host/key bytes; each identity is at most 1 KiB. Contains scheduling keys only. |
| Temporary recent snapshot | At most the same 8 entries and 2 KiB of key payload; no full-map traversal. |
| Other scan targets | At most 7 identities, so at most 8 including the leader; at most 3 KiB total target-key bytes. Actual demands have priority over predictions. |
| Active membership | Exactly the actual frozen target identities, with the same 7-entry and 3 KiB key-payload bounds. |
| Published hints | Original separate 16 KiB budget; IDs, complete digests and epochs exist only for live admitted demands. |

These are separate container-payload limits, not a combined RSS limit. Demand
guards, the ownership map, callers and temporary values retain other allocations.
With four actual workers, the leader has at most three distinct other demands,
each at most 1 KiB, so all actual demands fit before predictions are considered.
A full prediction budget merely reduces predicted coverage; it cannot reject an
otherwise valid lookup.

The leader freezes these targets before the first receipt. A covered identity
can therefore arrive even after its record was scanned and still join safely:
its complete target history was observed from the beginning. An uncovered late
identity keeps R4c's independent full-scan path. Complete JSON decoding, target
duplicate tombstones and all original refusal checks remain. Hint candidates use
the existing strict reader's valid-name constraint to bound retained IDs to 128
bytes; an unhintable ID still counts as seen and follows the original full-scan
behavior. This does not add receipt I/O, but a single leader may perform up to
seven additional target comparisons per receipt and bounded candidate digests.
Whether that cost is repaid by shared scans is an empirical question for R4e.

Successful publication closes `active` under the same state lock that publishes
hints. A predicted key without a live actual demand receives no hint; registering
after publication cannot wait on stale membership. The leader RAII guard still
clears membership on error or unwind before releasing the gate. Last-demand
cleanup still removes its hint, even though an identity-only prediction may
remain in the queue. Member hint misses release the gate before fallback scanning,
and gate poison remains a refusal even when an earlier hint would otherwise match.
There is no sleep, yield, additional worker or artificial admission window.

## SSH maintenance and original cleanup ownership

The SSH observation actor previously performed maintenance work in its own
dispatch loop. A slow original master retirement could delay unrelated host
admission. R4 runs at most one maintenance task under the same actor owner while
continuing to process bounded request admission and completion.

Maintenance snapshots the bounded master table, preserving each entry's
generation and readiness-channel identity, then releases the table lock before
waiting on any original child. Before closing a generation to new leases, it
rechecks that the table still contains that exact entry and refreshes the active
and idle conditions. After cleanup it removes an entry only when the same
generation/channel is still present and the original permit/active conditions
allow removal. A stale maintenance snapshot cannot delete a newer generation.

Each original master owns one retained retirement result. Maintenance and renewal
join that same result instead of independently stopping, releasing or unlinking
the original child/socket. A cleanup failure remains a failure and freezes
admission; it is not silently retried as successful cleanup for another owner.

The maintenance task is included in shutdown joining. Task failure or unwind
closes admission, and the actor waits for its original maintenance and request
tasks before completing shutdown. This change does not increase the established
host/global request limits or turn a lost acknowledgement into execution success.
Existing output, exit-record and exact-byte-witness durability barriers are not
weakened or replaced.

## Validation method

### Formal candidate qualification

**R4e completed all eight qualification gates.** The
[qualified bindings](../tools/x230/20261028/evidence/r4/qualification-bindings.json)
are tied to the original qualification report and independent exact-case audit,
not to dependency prewarming or an earlier candidate's receipts.

| Qualification check | R4e result |
| --- | --- |
| Gates | `format`, `fmt-check`, `harness-tests`, `clippy`, `test-build`, `isolated-tests`, `audit-isolated-tests` and `release` all returned 0. |
| Rust inventory | 1,547 selected cases across 5 test executables. |
| Rust execution | 1,522 executed and passed; 0 failed; 25 explicitly ignored and not counted as executed passes. |
| Python harness tests | 57 passed. |
| Registry coalescing | All 21 cases executed and passed on their first recorded attempt, including the six R4e prediction cases. |
| SSH maintenance | The isolated maintenance parent case executed and passed; its separately listed helper remained explicitly ignored in the inventory. |
| Compiler and harness inputs | 192 compiler inputs and 19 harness files bound to the completed qualification. |
| Release identity | Qualified runtime SHA equals the measured R4e diagnostic runtime SHA. |

| Retained identity | SHA-256 |
| --- | --- |
| Qualification report | `3d5d618eae594f2aa1b7e5902230d4600e32b1b163c2e759914c61bddda7997b` |
| Independent isolated-test audit | `69123251e571b140683e90dceb49c0746e07b91ca86ff7bd00d3f67c974eaf16` |
| Qualified binding JSON | `e04b2109f062c70bad4861ba866fd4644000930a722718a27738c1b9cc375dab` |
| Qualified runtime | `8469fe7afdf560f4c501e5162cd7926957fade695118e9b9b72f1594ed861248` |
| Qualified libtest executable | `0ed9d036f073c8ef4f476ab7dbc9a0307c3e996f874aaa55c17662f2046d9926` |

The [current source map](../tools/x230/20261028/evidence/r4/source-map.json) has
SHA-256 `7b5903e0e11666b926ff8dbdba28e3009c2ab4382f8e579d0c54bea1f4410c25`.
The [R4e publication boundary](../tools/x230/20261028/evidence/r4/publication-boundary.json),
SHA-256 `43a16e5105b7fc32875ed04e9fbfabc2d6e5ff85fcf0d142f68a245b055a17b8`,
passes the byte comparisons for all 192 qualified compiler inputs and all 19
qualified harness files. It permits 14 selected code changes: 6 Rust files and
8 Python files, with the other 11 harness files matching R3. The staged tree keeps
the original R3 example and excludes six PR76-only source files. This check uses
the R3 parent tree plus selected changes, not the whole older local checkout.
Documentation and retained evidence are additional deliberate publication entries.

R4b's original map and boundary remain in `source-map-r4b.json` and
[publication-boundary-r4b.json](../tools/x230/20261028/evidence/r4/publication-boundary-r4b.json).
They are historical receipts and have not been relabeled as R4e qualification.
The separately bound eight-stage native run and one-stage extended soak have both
completed. Their results retain separate schemas, reports and workload scopes.

One earlier R4b diagnostic attempt failed during evidence preflight, before any
Rust case ran: its temporary Cargo-record file retained `compiler-artifact`
messages but omitted the original `build-finished` message. The preflight
therefore refused to accept that file as a complete successful build stream and
reported zero executed cases. The corrected `r02` evidence preparation retained
the complete original successful Cargo stream and the same libtest ELF. Registry
and maintenance diagnostics then passed. This was a correction to evidence
packaging, not a Rust source fix, replacement executable, retry of a failed Rust
case or full qualification. The failed preflight evidence is retained separately;
it must not be overwritten or counted as a passing diagnostic.

The [R4e source-handoff preflight](../tools/x230/20261028/evidence/r4/diagnostics/r4e-source-handoff-preflight.json)
also stopped a local transfer when its expected test-file hash was stale, before
any working-tree write, host request, Rust case or performance call. The final two
fixture edits were independently re-reviewed and their exact hash accepted before
upload; this was a source-identity guard rejection, not a Rust test failure.

The registry tests exercise concurrent different-key reuse, duplicate-target
tombstones, complete-history corruption refusal, changed generation/digest,
no-watch fallback, legacy receipt compatibility, bounded demand lifetime,
cancelled worker ownership and hot-hit independence. SSH cases exercise slow
retirement alongside other-host work, concurrent renewal, persistent cleanup
failure and maintenance panic/shutdown custody. The completed counts above come
from the source-bound qualification; the coverage descriptions below explain
those tests.

#### Deterministic R4c routing coverage

The [registry coalescing tests](../src/mcp/runtime/jobs_registry_coalescing_tests.rs)
added three cases for the R4c admission policy. They remain part of R4e's original
15 cases. All three executed and passed in the completed R4e qualification; the
table below explains the deterministic conditions behind those recorded passes.

| New test | Deterministic condition and assertion |
| --- | --- |
| `late_known_refresh_bypasses_an_active_frozen_cohort` | Pause a leader at `ON_SCAN`, after its target set is frozen. Register a different already strict known key afterwards and require that key's complete scan to finish while the leader remains paused. Both lookups return their original IDs. |
| `cohort_member_without_a_hint_releases_gate_before_full_scan` | Register the member before freezing and observe its actual cohort-wait path. Finish the leader without a usable hint; the member's scan hook must be able to acquire the gate, proving the fallback does not hold it. |
| `poisoned_leader_clears_active_and_refuses_an_existing_valid_hint` | First establish a usable complete hint, then panic a worker holding the actual leader RAII guard. Require cleared active membership and a poison refusal before any new full scan or successful hint return. |

Existing fixtures also make the intended scheduling explicit. The four-host
single-scan test registers all participants, lets one leader freeze its targets,
then releases the other workers. The cancellation fixture registers the waiter
before the leader freezes, verifies its active membership, and observes
`ON_COHORT_WAIT` before cancelling both async callers; both actual workers must
retain their permits until completion. The gate-held/active-absent fixture now
includes a previously strict known identity alongside fresh and absent keys,
covering the acquisition-to-membership publication interval. These synchronization
points are test-only hooks, not production batching delays.

#### Deterministic R4e prediction coverage

R4e adds six cases to those 15, for **21 coalescing tests**. All 21 executed and
passed in the completed exact-source qualification, each with recorded attempt 1.
These executed outcomes supplement the earlier independent static review.

| New test | Deterministic condition and assertion |
| --- | --- |
| `predicted_late_identity_joins_after_its_complete_scan` | Pause after the complete history scan and before publication. Verify the predicted identity is in `active` but has no actual demand or hint; then register its worker and observe `ON_COHORT_WAIT`. The leader scans once and the late worker zero times, returning the original IDs. |
| `recent_predictions_follow_strict_cold_commits_not_warm_or_legacy_reads` | A cold strict refresh deduplicates and moves the identity to the newest position; warm, legacy, pending and absent lookups leave the queue unchanged. |
| `recent_prediction_budget_and_full_ownership_map_do_not_evict_known` | Exercise the 8-entry and 2 KiB limits, oversized-key skipping and newest-first selection. With all 4,096 known slots occupied, another successful lookup cannot evict refusal evidence or populate a prediction without satisfying the original retention gate. |
| `frozen_prediction_budget_prioritizes_distinct_live_demands` | Give actual distinct demands first choice, deduplicate shared identities, enforce 7 other targets and 3 KiB, and preserve a duplicate tombstone after an unhintable record ID. |
| `predicted_key_without_live_demand_is_not_published_and_closes_membership` | Produce a real candidate without a live target demand, publish while retaining the leader guard, and assert no hint and `active == None`; later registration cannot recover a speculative result. |
| `predicted_duplicates_and_corruption_retain_original_refusals` | Duplicate predictions remain tombstoned without newly rejecting a healthy different target; malformed predicted JSON still fails the complete scan, with no hint or membership leak. |

The earlier uncovered-late fixture now explicitly removes its test prediction
entries while retaining strict ownership, so it still proves the independent
bypass path. The poison fixture asserts actual waiter membership before the
leader panics, preserving a non-vacuous cleanup assertion after publication began
closing membership earlier. Production scheduling has no test-hook delay.

### R3-control versus R4 isolated Rust comparison

The ignored `jobs_registry_concurrency_bench.rs` module is added byte-for-byte to
both source variants. **R3-control differs from R3 only by test-only benchmark
modules and their `cfg(test)` declarations; no R4 production optimization may be
backported into the control.** Record the complete source diff and both test
executable hashes before comparing them.

Both arms are Rust 1.95.0 **libtest builds**, with all features enabled and
`CARGO_PROFILE_DEV_DEBUG=0`, `CARGO_PROFILE_TEST_DEBUG=0`, and
`CARGO_INCREMENTAL=0`. The retained original Cargo receipts for the final R3-control
and R4e executables record **`opt_level=1`, `debuginfo=0`, debug assertions enabled
and overflow checks enabled** in both arms. The libtest profile must be read from
those receipts rather than inferred from the absence of `--release`. These
measurements do not use release binaries. The runner removes inherited `HEPTA_`, `SSH_` and `RUST_TEST_` variables, fixes
`RUST_TEST_THREADS=1` and `TOKIO_WORKER_THREADS=2`, and runs only the exact ignored
case
`mcp::runtime::jobs::registry_concurrency_bench::cold_positive_and_absent_concurrency_benchmark`.
It checks that the benchmark source module is identical in both arms and rejects
equal executable hashes. Those checks establish the measured input identities;
they do not replace compiler provenance or formal qualification.

Each benchmark process creates 6,000 private receipts, a two-worker Tokio runtime
and the existing four-permit registry worker limit. Four repetitions cover C1,
C4 and C8 for three categories:

| Category | State before the timed wave |
| --- | --- |
| `fresh_positive` | Empty `ReuseHitCache`; each key already has one launched original receipt. |
| `absent` | Empty cache; distinct keys have no receipt. |
| `known_invalidated` | Serial lookups prime the original keys outside timing, then a unique non-JSON marker invalidates positive hits while retaining known ownership. |

Category and concurrency order reverse on alternating repetitions. The complete
process has 36 waves and 156 timed lookup calls. Each completed wave is emitted
and flushed immediately, preserving earlier observations if a later wave fails;
the entire failed process remains failed. The outer runner must retain every
planned ABBA process and its original stdout/stderr without retry or substitution.

Timing covers the main barrier wait through joins of all original workers.
Receipt fixture creation and pre-wave priming are outside that timing; worker
startup/queueing and all synchronous lookup work remain within the measured wave.
CPU is a `getrusage(RUSAGE_SELF)` delta. Raw per-call latencies are retained.
`ru_maxrss` is a process-lifetime maximum, not a per-wave memory peak. C1/C4/C8
wave p95 is simply that wave's largest observation.

This test isolates the actual bounded lookup path. It does not execute start
lanes, owner admission, durable new-intent publication, audit, SSH or external
effects. C8 uses eight distinct lookup keys; it is not the same workload as the
six-original MCP test below.

Throughput in the results below is total completed lookup calls divided by the
sum of the measured wave durations for that category and concurrency. It is not
an arithmetic average of wave throughput or the number of calls divided by the
whole runner duration. CPU per call uses summed user plus system CPU deltas.
Latency percentiles use the pooled original call samples and nearest-rank
selection. Changes are `(candidate / control - 1) * 100` within each experiment.

### Direct retained R3 runtime versus R4 MCP ABBA

`tools/x230/20261028/run_registry_cohort_abba.py` accepts explicit baseline and
candidate binary paths/hashes plus separate compiler-input manifests and source
roots. It rejects identical binary hashes and checks both sources and artifacts
before, between and after the rounds. These checks bind the comparison inputs;
they do not independently prove compilation provenance or grant qualification.

The harness reuses the pinned original `load_originals`, `make_controller` and
`phase` helpers. It does not call the old A62 comparison entry point or rewrite
old experiment records. Six original launched identities and request bytes are
validated from an immutable successful recovery report. Every SSH status attempt
is intercepted by a local wrapper that exits before exec; only exact original
request keys are submitted.

Default plan:

- Fixed ABBA order, with a fresh controller and copied private registry for each
  round; two configured Tokio workers in each arm.
- C1, C4 and C8, with eight invalidation cycles per concurrency per round.
- Each cycle creates a new non-JSON marker outside measured calls, executes one
  six-original cold wave, then 48 additional warm reuse calls.
- Total planned tool calls: 5,184. C8 still has only six distinct original keys
  in its cold wave and at most six simultaneous distinct requests.

`cold_initial` means the first invalidated wave for a concurrency in that
controller round; `cold_steady` means its later seven invalidated waves. Neither
means a cold operating-system page cache. The same controller spans concurrency
levels, so even `cold_initial` is not a claim that the process has never observed
the original keys. `cold_all` and `warm` are reported separately as well.

Original event journals retain all executed calls and failed attempts, with
20 ms ping observations. The original 100 ms resource sampler is extended with
one raw sample record per pass, without changing its cadence or identity checks.
Raw fields retain missing data and non-atomic process-tree observations. Samples
crossing a phase boundary are retained but excluded from phase-specific peaks.
Resource-log finalization stays on the sampler worker; a blocked fsync cannot
turn the bounded stop caller into an unbounded filesystem worker.

At each round's end, the harness verifies exact denied-status receipt counts,
unchanged original and synthetic job JSON, the absence of newly allocated jobs,
original-child shutdown and complete journal retention. A failure stops the
remaining work without retry. Planned but unexecuted phases remain in the report.
Any global evidence failure revokes all comparison eligibility and ratios,
including ratios for otherwise complete subsets.

### Native recovery and maintenance validation

**R4e completed all eight native stages once**, with no automatic retries and a
successful final input-integrity check. The completed stage results, original job
IDs, lease custody and file observations are recorded below. This adds actual
six-host controller-crash recovery and read-only file exercise to the isolated
maintenance tests; it does not establish physical-power-loss or target-reboot
acceptance. The independently configured 360-second extended run also completed;
it has its own report and is not counted as another native stage.

## Results from completed evidence

### Experiment identities and completion

The completed Rust comparisons use A for the R3-control test executable and B
for the indicated candidate test executable. R4a, R4b and the qualified R4e
comparison are separate experiments with their own interleaved control
measurements. Their absolute control rates must not be combined to construct
a larger claimed gain.

| Experiment | Serial process order | Completed processes / timed waves / timed calls | Lookup failures | Whole runner elapsed time | Original report SHA-256 |
| --- | --- | --- | ---: | ---: | --- |
| Rejected R4a | `ABBA` | 4 / 144 / 624 | 0 | 74.501 s | `41b23384b05166bd34c1db4f0503795ee4fb8b8e6048443fc14a21f2d742ea8c` |
| R4b | `ABBAABBA` | 8 / 288 / 1,248 | 0 | 122.522 s | `51e68dba0e81f539005451b8ea85c127628206e365630d416e182be1ffcd842c` |
| Qualified R4e | `ABBAABBA` | 8 / 288 / 1,248 | 0 | 119.028683 s | `27265e12a3f71acca9dd5d3a961d6f196368731df0a6a5d13f841b6b85e9bf99` |

All three comparison reports passed the runner's fixed inventory, original wave,
completion and input-stability checks. There were no benchmark retries or
replacement samples. Each process contributes four waves for every category and
concurrency. R4a therefore has eight waves per arm/category/concurrency; R4b and
R4e each have sixteen. Whole runner elapsed time includes fixture preparation and is shown for
reproducibility, not used as the throughput denominator.

The retained original reports, source maps, command journals and raw stdout/stderr
are included in the [original evidence archive](../tools/x230/20261028/evidence/r4/evidence-package.tar.gz).
Its [manifest](../tools/x230/20261028/evidence/r4/evidence-manifest.json) records each
member's original path, identity, length and SHA-256. The report hashes above
identify the completed measurements; the tables do not substitute for those
original files.

### R4a: rejected because the broad cold gate serialized absent lookups

The first candidate admitted fresh and absent keys to the same cold gate.
Although some CPU-per-call measurements fell, absent lookup throughput fell by
51.258% at C4 and 53.363% at C8. Fresh-positive throughput also fell by 4.352% and
8.901% at those widths. That behavior did not meet the optimization objective,
and R4a was rejected.

| Category | C | Calls per arm | Control calls/s | Candidate calls/s | Change | Control CPU ms/call | Candidate CPU ms/call | CPU change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `fresh_positive` | 1 | 8 | 8.213 | 8.413 | +2.431% | 121.670 | 118.854 | -2.315% |
| `fresh_positive` | 4 | 32 | 17.260 | 16.509 | -4.352% | 185.240 | 60.747 | -67.206% |
| `fresh_positive` | 8 | 64 | 17.846 | 16.258 | -8.901% | 185.119 | 61.460 | -66.800% |
| `absent` | 1 | 8 | 9.011 | 8.532 | -5.312% | 110.904 | 117.108 | +5.593% |
| `absent` | 4 | 32 | 17.438 | 8.499 | -51.258% | 182.470 | 117.758 | -35.464% |
| `absent` | 8 | 64 | 18.314 | 8.541 | -53.363% | 182.834 | 117.119 | -35.942% |
| `known_invalidated` | 1 | 8 | 8.857 | 8.751 | -1.191% | 112.903 | 114.256 | +1.198% |
| `known_invalidated` | 4 | 32 | 16.745 | 16.829 | +0.502% | 184.785 | 59.591 | -67.751% |
| `known_invalidated` | 8 | 64 | 18.235 | 17.253 | -5.387% | 186.290 | 58.106 | -68.809% |

The absent-key latency evidence is consistent with that rejection: C4 p99 rose
from 269.461 to 514.900 ms, and C8 p99 from 512.781 to 1,060.458 ms. Lower CPU use
alone is not an acceptable outcome when the same lookup workload loses that much
throughput. The rejected executable, source snapshot and report remain evidence
of the failed design, rather than being relabeled as R4b results.

### R4b: sharing only retained strict identities after invalidation

R4b registers a demand only when the content watch is usable, retained ownership
is strict and no positive cache ID is available. Registration occurs before the
already required strict receipt read, allowing the admitted workers to overlap
that read without adding a batching delay. Every worker must still pass its own
strict read before using the shared scan. Warm hits, first observations and
absent keys bypass the gate.

| Category | C | Calls per arm | Control calls/s | Candidate calls/s | Change | Control CPU ms/call | Candidate CPU ms/call | CPU change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `fresh_positive` | 1 | 16 | 8.951 | 8.894 | -0.644% | 111.602 | 112.361 | +0.680% |
| `fresh_positive` | 4 | 64 | 20.522 | 20.901 | +1.844% | 185.267 | 186.296 | +0.556% |
| `fresh_positive` | 8 | 128 | 19.990 | 20.448 | +2.292% | 185.591 | 185.924 | +0.179% |
| `absent` | 1 | 16 | 9.355 | 9.340 | -0.164% | 106.692 | 106.981 | +0.271% |
| `absent` | 4 | 64 | 20.329 | 20.444 | +0.564% | 184.206 | 185.134 | +0.504% |
| `absent` | 8 | 128 | 20.530 | 20.833 | +1.480% | 185.181 | 185.574 | +0.212% |
| `known_invalidated` | 1 | 16 | 9.337 | 9.146 | -2.045% | 106.913 | 109.236 | +2.173% |
| `known_invalidated` | 4 | 64 | 19.608 | 20.654 | +5.334% | 185.425 | 48.591 | -73.795% |
| `known_invalidated` | 8 | 128 | 20.177 | 22.273 | +10.393% | 185.566 | 45.056 | -75.720% |

For the targeted `known_invalidated` workload, observed throughput increased by
5.334% at C4 and 10.393% at C8, while CPU per call fell by 73.795% and 75.720%.
C1 retained a cost: throughput fell by 2.045%, with CPU per call up 2.173%.
Fresh-positive throughput changed by -0.644%, +1.844% and +2.292% at C1/C4/C8;
absent throughput changed by -0.164%, +0.564% and +1.480%. These measurements
supported proceeding to formal and runtime validation. The later release MCP
comparison below rejected R4b despite these favorable isolated concurrent results.
They do not establish a statistically guaranteed improvement or an improvement
for every request shape.

Pooled original call latencies show the remaining tradeoffs:

| Category | C | p50 ms, control / R4b | p95 ms, control / R4b | p99 ms, control / R4b | Maximum ms, control / R4b |
| --- | ---: | ---: | ---: | ---: | ---: |
| `fresh_positive` | 1 | 105.337 / 107.223 | 132.278 / 131.491 | 132.278 / 131.491 | 132.278 / 131.491 |
| `fresh_positive` | 4 | 188.184 / 187.387 | 206.440 / 205.763 | 226.377 / 232.011 | 226.377 / 232.011 |
| `fresh_positive` | 8 | 319.353 / 231.149 | 443.013 / 394.605 | 476.423 / 425.149 | 494.310 / 461.064 |
| `absent` | 1 | 105.070 / 106.031 | 117.475 / 120.618 | 117.475 / 120.618 | 117.475 / 120.618 |
| `absent` | 4 | 187.169 / 188.318 | 217.027 / 207.267 | 264.605 / 270.033 | 264.605 / 270.033 |
| `absent` | 8 | 276.136 / 261.235 | 388.691 / 387.430 | 448.454 / 413.832 | 504.223 / 434.023 |
| `known_invalidated` | 1 | 105.431 / 106.868 | 126.523 / 125.896 | 126.523 / 125.896 | 126.523 / 125.896 |
| `known_invalidated` | 4 | 188.216 / 107.314 | 235.230 / 239.144 | 285.700 / 243.845 | 285.700 / 243.845 |
| `known_invalidated` | 8 | 359.005 / 212.240 | 420.649 / 367.816 | 448.916 / 401.360 | 506.306 / 471.329 |

In particular, known-invalidated C4 p95 increased from 235.230 to 239.144 ms even
though its pooled throughput and median improved. C1 has only 16 calls per arm
and category, so p95 and p99 both select the maximum; at C4, p99 selects the
maximum of 64 calls. C8 has 128 calls per arm/category. These small repeated
cohorts are useful diagnostic evidence, not estimates of production tail latency.
The ABBA order helps expose order effects on this X230 but does not make samples
independent or provide a confidence interval. No significance test or confidence
claim is made here.

The large concurrent CPU reduction is measured in the lookup test process. This
experiment does not independently measure disk I/O bytes, cache-miss rates,
release-runtime throughput, SSH capacity or completed new jobs. Memory remains a
process-lifetime maxRSS observation in the raw waves; no per-wave RSS or FD
improvement is inferred from these CPU results.

### R4b release MCP: correctness complete, performance rejected

The direct retained-R3 versus qualified-R4b release comparison completed its four
ABBA controller rounds and all 5,184 planned calls, with zero failed calls and no
new remote effects. Its original report SHA-256 is
`5c29c46c721448ad8d3f5f41ca35d7c907c28684f66ea2e0929aef01fffbd71f`.
The runner's `passed` result establishes the fixed experiment's completion and
correctness; it is not an automatic performance acceptance decision.

| C | Phase group | Throughput change | Controller CPU per call change | Call p95 change |
| --- | --- | ---: | ---: | ---: |
| 1 | Cold, all waves | +0.855% | -1.024% | -0.421% |
| 1 | Cold, initial wave | -0.526% | 0.000% | +0.292% |
| 1 | Cold, later waves | +1.059% | -1.172% | -1.053% |
| 1 | Warm | -0.837% | +0.172% | +0.193% |
| 4 | Cold, all waves | **-18.624%** | -49.198% | +1.830% |
| 4 | Cold, initial wave | -22.888% | -48.404% | +13.266% |
| 4 | Cold, later waves | -18.023% | -49.307% | +1.830% |
| 4 | Warm | -0.115% | +0.225% | +0.318% |
| 8 | Cold, all waves | +7.264% | -63.299% | -14.221% |
| 8 | Cold, initial wave | +2.274% | -62.626% | -4.285% |
| 8 | Cold, later waves | +7.955% | -63.391% | -14.221% |
| 8 | Warm | +0.486% | -0.210% | +0.723% |

Both candidate C4 rounds showed the same lower cold-wave rate. CPU savings and
the C8 improvement did not compensate for that C4 regression, so R4b was rejected
as a performance candidate. The six-request, four-client workload can
admit later refreshes after the first shared scan freezes its target set. R4b
made those later workers wait for that scan even though it could not supply their
hints, then scan independently. This is the scheduling hypothesis addressed by
R4c; the hypothesis requires a new complete comparison rather than relabeling
R4b's measurements.

### R4c early release diagnostic: throughput recovered, CPU reduction limited

The complete ABBA plan again passed all 5,184 calls, with 1,296 locally denied
SSH attempts per round and no remote effects. Report SHA-256:
`809dbe7ce144979c7b7b547d6a1b2bbde7f6e8dc15351306b5e840e48959862f`.
The diagnostic runtime SHA-256 is
`2547c6c975f5086600cea43de6516746d379840fc17863d7f96c8b45bc9d4e2f`,
and its 192-input source-map SHA-256 is
`70ae3e2ef57541d4e2e33b933cbfe1743f134938a77c7d062b770174dfb4610c`.
This build used `--release --all-features --bin hepta-runtime` for an early
performance diagnosis. It did not execute the full qualification, whose release
stage also builds all binaries and examples. Its results do not qualify a future
R4d or R4e artifact or establish the identity of either artifact.

| C | Phase group | Throughput change | Controller CPU per call change | Call p95 change |
| --- | --- | ---: | ---: | ---: |
| 1 | Cold, all waves | +0.574% | +0.796% | +1.126% |
| 1 | Cold, initial wave | +1.398% | -2.778% | -2.906% |
| 1 | Cold, later waves | +0.456% | +1.318% | +3.331% |
| 1 | Warm | -0.032% | +0.175% | +0.263% |
| 4 | Cold, all waves | +6.052% | -2.621% | -16.278% |
| 4 | Cold, initial wave | +5.797% | -3.590% | -1.421% |
| 4 | Cold, later waves | +6.088% | -2.484% | -16.278% |
| 4 | Warm | -1.366% | -1.345% | +6.033% |
| 8 | Cold, all waves | +2.614% | -1.048% | -0.978% |
| 8 | Cold, initial wave | +3.893% | -0.995% | -4.098% |
| 8 | Cold, later waves | +2.437% | -1.056% | -0.978% |
| 8 | Warm | +0.839% | -0.837% | -1.622% |

The C4 cold-throughput regression seen in R4b was absent in this comparison.
However, controller CPU per cold call fell by only 2.621% at C4 and 1.048% at C8.
This is consistent with few workers sharing a scan in this arrival pattern;
it is an inference from the measured CPU cost, not an instrumented share count.
Warm C4 throughput fell by 1.366%, and its p99 rose by 21.434%; the complete raw
samples remain included. These observations are not a universal improvement
claim or a reason to discard unfavorable tail samples.

R4c remains a completed diagnostic iteration. Work continued with R4d to test
whether registration before the already-required first epoch probe increases
natural overlap without adding a batch wait. No R4c result is relabeled as an
R4d result or as a complete correctness qualification.

### R4d release diagnostic: early registration not adopted

R4d moved eligible known-key demand registration before the first required epoch
probe, aiming to expose more naturally overlapping workers without adding a
delay. Early registration errors were deferred until the original checks actually
made the request eligible; hot and no-watch paths retained their original error
behavior. The completed diagnostic nevertheless did not show the targeted
concurrent CPU reduction, so R4e returns to the R4c registration point.

The four ABBA rounds completed all 5,184 planned calls with zero failed calls and
1,296 locally denied SSH attempts per round. Original report SHA-256:
`cd335fc1eecf67787ab4b6a9e7d92d179a319b31c5b8570b1c2cff6370eafc71`.
The [retained R4d compact summary](../tools/x230/20261028/evidence/r4/cohort-r4d-diagnostic-compact.json)
contains each arm, comparison group and round completion status. The diagnostic
runtime SHA-256 is
`416284f84a3b8a4aa85816afb3550d3bbd7db2aefdb71e06a52e65b8d06eb112`,
and its 192-input source-map SHA-256 is
`8e5b3cf63716d18ab718ce3bf7eeba9328588dd0908ac076ef7cfd60c676cb8c`.
The release diagnostic used `--release --all-features --bins --examples`, matching
the release target scope planned for qualification. It was still a diagnostic
build and comparison; full qualification was not started for R4d.

| C | Phase group | Throughput change | Controller CPU per call change | Call p95 change | Call p99 change |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Cold, all waves | +3.597% | -5.250% | -4.191% | -6.408% |
| 1 | Cold, initial wave | -2.954% | +3.497% | +4.647% | +4.647% |
| 1 | Cold, later waves | +4.600% | -6.477% | -5.450% | -7.633% |
| 1 | Warm | +0.014% | -0.345% | +0.346% | +1.069% |
| 4 | Cold, all waves | +0.909% | -1.036% | +16.616% | -5.716% |
| 4 | Cold, initial wave | +0.544% | 0.000% | -3.707% | -3.707% |
| 4 | Cold, later waves | +0.960% | -1.183% | +16.616% | -5.716% |
| 4 | Warm | +3.545% | -1.778% | -9.304% | -8.602% |
| 8 | Cold, all waves | +0.712% | -0.983% | +0.482% | +13.182% |
| 8 | Cold, initial wave | -0.987% | -2.404% | +6.166% | +6.166% |
| 8 | Cold, later waves | +0.967% | -0.775% | +0.888% | +13.182% |
| 8 | Warm | +2.563% | -0.210% | -0.397% | -2.217% |

Cold controller CPU per call changed from 160.833 to 159.167 ms at C4 and from
169.583 to 167.917 ms at C8, reductions of only 1.036% and 0.983%. C4 cold p95
increased from 277.288 to 323.362 ms, while C8 cold p99 increased from 439.412 to
497.334 ms. C1's pooled cold result improved, but its initial-wave throughput
fell by 2.954% and CPU per call increased by 3.497%; those observations are retained
alongside later waves and warm calls. Each arm has 96 cold and 768 warm calls per
concurrency, with only 12 calls in each cold-initial subset, so these tails remain
diagnostic observations rather than production tail estimates.

The concurrent CPU changes are consistent with little effective scan sharing,
but no instrumented sharing count was collected. R4d's additional early
registration was not adopted because this experiment did not demonstrate the
intended reduction in concurrent scan cost. All percentages above compare R4d to
its own interleaved R3 measurements; no R4b, R4c or R4e measurements are substituted
to construct a gain. The separate R4e comparison below tests predicted target
coverage with its own interleaved control measurements.

### Qualified R4e isolated Rust comparison

The final isolated comparison used the actual qualified libtest executable at
`/home/qian/hepta-runtime-optimization-20261028/qualification-r4e/test-binaries/hepta_runtime-67430d7e3fa4f507`,
SHA-256 `0ed9d036f073c8ef4f476ab7dbc9a0307c3e996f874aaa55c17662f2046d9926`.
Its control was the retained R3-control libtest ELF
`73e538f910786b4675975305ec25188eadf6b23a5a1cc14725bfe8d3efdea3fe`.
Original Cargo receipts verify `opt_level=1`, `debuginfo=0`, debug assertions and
overflow checks enabled for both executables. This is the libtest measurement
profile, distinct from the release MCP comparison.

The [R4e Rust compact summary](../tools/x230/20261028/evidence/r4/rust-r4e-compact.json)
has SHA-256 `6e992de2cdf792a225e42af5de2c8a97123b621036ffa89f31ae7d53ad44d9b9`;
the original report is
`27265e12a3f71acca9dd5d3a961d6f196368731df0a6a5d13f841b6b85e9bf99`.
All 8 processes in the planned `ABBAABBA` order completed, retaining 288 timed
waves and 1,248 calls with no lookup failures. Whole-run elapsed time was
119.028683 seconds, including preparation; throughput below uses the sum of the
measured wave durations for each category and concurrency. Each arm contributes
16 waves per category/concurrency, with 16, 64 or 128 calls at C1, C4 or C8.

| Category | C | Calls per arm | Control calls/s | R4e calls/s | Change | Control CPU ms/call | R4e CPU ms/call | CPU change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `fresh_positive` | 1 | 16 | 9.157 | 8.988 | -1.841% | 109.187 | 110.974 | +1.637% |
| `fresh_positive` | 4 | 64 | 20.318 | 20.240 | -0.381% | 184.005 | 184.566 | +0.305% |
| `fresh_positive` | 8 | 128 | 20.682 | 20.384 | -1.442% | 184.201 | 184.645 | +0.241% |
| `absent` | 1 | 16 | 9.388 | 9.460 | +0.770% | 106.276 | 105.480 | -0.749% |
| `absent` | 4 | 64 | 20.508 | 20.626 | +0.571% | 182.917 | 183.166 | +0.136% |
| `absent` | 8 | 128 | 20.814 | 21.255 | +2.116% | 183.691 | 184.160 | +0.255% |
| `known_invalidated` | 1 | 16 | 9.453 | 9.516 | +0.666% | 105.778 | 104.746 | -0.976% |
| `known_invalidated` | 4 | 64 | 20.318 | 35.695 | +75.679% | 183.054 | 35.531 | -80.590% |
| `known_invalidated` | 8 | 128 | 20.541 | 30.631 | +49.117% | 184.199 | 67.849 | -63.165% |

The targeted known-invalidated workload gained 75.679% throughput at C4 and
49.117% at C8, while CPU per call fell by 80.590% and 63.165%. C1 changed by
+0.666% in throughput and -0.976% in CPU per call. These results measure reuse of
known strict identities after invalidation; they do not imply a corresponding
gain for first observations or absent keys.

Fresh-positive throughput fell at all three widths: 1.841% at C1, 0.381% at C4
and 1.442% at C8. Its CPU per call rose by 1.637%, 0.305% and 0.241%. Absent-key
throughput rose by 0.770%, 0.571% and 2.116%, but C4/C8 CPU per call also rose
slightly. These observations remain part of the comparison; they are not erased
by the larger known-refresh gains.

| Category | C | p50 ms, control / R4e | p95 ms, control / R4e | p99 ms, control / R4e | Maximum ms, control / R4e |
| --- | ---: | ---: | ---: | ---: | ---: |
| `fresh_positive` | 1 | 103.961 / 105.239 | 122.098 / 138.120 | 122.098 / 138.120 | 122.098 / 138.120 |
| `fresh_positive` | 4 | 186.513 / 186.756 | 201.109 / 228.351 | 289.318 / 238.761 | 289.318 / 238.761 |
| `fresh_positive` | 8 | 251.753 / 347.841 | 388.428 / 411.823 | 401.112 / 457.193 | 410.328 / 490.745 |
| `absent` | 1 | 104.026 / 103.474 | 122.698 / 124.887 | 122.698 / 124.887 | 122.698 / 124.887 |
| `absent` | 4 | 185.422 / 185.908 | 211.130 / 213.335 | 239.136 / 234.920 | 239.136 / 234.920 |
| `absent` | 8 | 265.935 / 205.973 | 392.937 / 376.717 | 452.901 / 383.201 | 456.580 / 386.802 |
| `known_invalidated` | 1 | 104.974 / 104.010 | 119.026 / 117.551 | 119.026 / 117.551 | 119.026 / 117.551 |
| `known_invalidated` | 4 | 186.163 / 107.107 | 213.662 / 125.292 | 232.125 / 125.740 | 232.125 / 125.740 |
| `known_invalidated` | 8 | 274.057 / 215.350 | 388.996 / 293.465 | 489.306 / 324.672 | 500.228 / 325.650 |

The fresh-positive tails show costs beyond its small throughput changes. C1 p95
and p99 rose 13.123%, and C4 p95 rose 13.546% even though its p99 decreased. At C8,
fresh-positive median latency rose 38.167%, p95 rose 6.023%, p99 rose 13.981% and
the maximum rose 19.598%. Absent C1 p95/p99 rose 1.785%, and absent C4 p95 rose
1.045%. The original samples are retained; no favorable subset replaces them.

C1 p95/p99 both select the maximum among 16 calls, and C4 p99 selects the maximum
among 64 calls. The finite repeated waves and fixed process order do not establish
statistical significance, confidence intervals or a production tail-latency SLA.
CPU is the test process's user-plus-system delta, not controller-tree CPU, disk
traffic or an RSS improvement. This eight-distinct-key C8 microbenchmark and the
six-original release MCP workload keep separate denominators and claims. Their
throughput or CPU percentages must not be pooled into a larger gain.

### R4e release MCP: concurrent gains bound to the qualified release

The retained R3 runtime and R4e diagnostic runtime completed the full four-round
ABBA plan: all 5,184 planned calls succeeded, with zero failed calls and 1,296
locally denied SSH attempts per round. Every phase/concurrency comparison was
eligible. This is the existing six-original, denied-SSH workload, not a measurement
of new remote launches or file-transfer capacity. Its successful execution and
measured gains motivated the subsequently completed qualification. The binding
checks below connect this measurement to that qualified release. The completed
native validation is recorded separately and uses its own workload and baseline.

The [retained R4e compact summary](../tools/x230/20261028/evidence/r4/cohort-r4e-compact.json)
contains both arms, all phase groups and all four round outcomes. The measured
identities are:

| Identity | SHA-256 |
| --- | --- |
| Original release MCP report | `7a099f3863151faac2e50eb93a0d29d19e49ac839f3c872ad0de5b28aaa967a9` |
| Plain compact JSON linked above | `330aa33e4e93f90ac137afbdef9e79b265d938fa2208986b40cdada14d35f04e` |
| Retained MCP evidence archive | `0abdb848e3fad40b69cc8a2bc2600367a02589460bae50f0c1474f8770a3dbea` |
| R4e diagnostic runtime | `8469fe7afdf560f4c501e5162cd7926957fade695118e9b9b72f1594ed861248` |
| R4e 192-input compiler map | `7b5903e0e11666b926ff8dbdba28e3009c2ab4382f8e579d0c54bea1f4410c25` |
| R4e release diagnostic report | `7ebe74069ed4733c3d308205458979a4cbef11c1823d18fbd0484fac185310e9` |

The diagnostic release used `--release --all-features --bins --examples`. The
subsequently completed qualification has the same compiler-input map and the
same runtime SHA-256 shown above. The qualified bindings and publication boundary
record these successful comparisons, so this MCP measurement is bound to the
qualified release. The binding follows the verified bytes, not merely matching
build-target flags.

All changes below are relative to this experiment's own interleaved R3 arm.
Earlier candidates' control values are not substituted or pooled with these.
Each arm has 96 cold and 768 warm calls per concurrency; cold-initial contains 12
of those cold calls and cold-steady the other 84. Neither label denotes an empty
operating-system page cache. Percentiles use the original executed call samples.

| C | Phase group | Throughput change | Controller CPU per call change | Call p95 change | Call p99 change |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Cold, all waves | +1.344% | -0.890% | -2.366% | -3.075% |
| 1 | Cold, initial wave | +4.067% | -4.930% | -18.716% | -18.716% |
| 1 | Cold, later waves | +0.963% | -0.305% | -2.154% | -3.075% |
| 1 | Warm | -0.107% | -3.339% | +0.304% | -0.400% |
| 4 | Cold, all waves | +34.803% | -75.277% | -41.760% | -44.112% |
| 4 | Cold, initial wave | +48.064% | -76.733% | -51.886% | -51.886% |
| 4 | Cold, later waves | +32.876% | -75.056% | -38.689% | -36.958% |
| 4 | Warm | +0.332% | +0.903% | -1.624% | -11.127% |
| 8 | Cold, all waves | +30.073% | -63.214% | -22.318% | -26.111% |
| 8 | Cold, initial wave | +27.424% | -60.513% | -21.005% | -21.005% |
| 8 | Cold, later waves | +30.451% | -63.591% | -22.318% | -26.111% |
| 8 | Warm | +0.468% | 0.000% | -3.755% | -3.477% |

For `cold_all`, the absolute rates and controller CPU costs are:

| C | R3 cold calls/s | R4e cold calls/s | R3 controller CPU ms/call | R4e controller CPU ms/call |
| --- | ---: | ---: | ---: | ---: |
| 1 | 6.471 | 6.558 | 117.083 | 116.042 |
| 4 | 14.258 | 19.221 | 160.104 | 39.583 |
| 8 | 15.071 | 19.604 | 165.938 | 61.042 |

C4 cold throughput increased by 34.803% while controller CPU per call fell by
75.277%; C8 increased by 30.073% with CPU per call down 63.214%. Initial and later
cold waves both showed the targeted concurrent gains. C4 cold p95/p99 fell from
295.538/352.151 to 172.121/196.811 ms; C8 fell from 399.908/431.808 to
310.657/319.057 ms. These observations support the bounded predicted-coverage
change in this workload. They do not establish an exact number of scans shared,
which this release experiment did not instrument, or improvements for every key
arrival pattern.

The smaller changes and regressions remain part of the result. C1 cold throughput
rose 1.344% and CPU per call fell 0.890%, while its median call latency rose
1.035%. Warm C1 throughput fell 0.107%, its p95 rose 0.304%, and its maximum call
latency rose from 61.113 to 63.669 ms. Warm C4 CPU per call rose 0.903%; C8 warm
CPU per call was unchanged at the displayed precision. The repeated samples and
ABBA order provide a controlled diagnostic comparison, not statistical guarantees
or production tail-latency estimates.

#### R4e ping observations and resource limits

The ping observer retained the following p99 values and executed sample counts;
all recorded pings in these groups succeeded. Initial/steady rows are subsets
of cold-all, so their counts must not be added to cold-all again.

| C | Phase group | Ping p99 ms, R3 / R4e | Change | Executed ping samples, R3 / R4e |
| --- | --- | ---: | ---: | ---: |
| 1 | Cold, all waves | 1.168018 / 2.011546 | +72.219% | 728 / 716 |
| 1 | Cold, initial wave | 0.780044 / 1.042430 | +33.637% | 92 / 88 |
| 1 | Cold, later waves | 1.263987 / 2.023315 | +60.074% | 636 / 628 |
| 1 | Warm | 2.085896 / 1.863878 | -10.644% | 1600 / 1602 |
| 4 | Cold, all waves | 9.398161 / 6.186499 | -34.173% | 317 / 243 |
| 4 | Cold, initial wave | 7.470275 / 7.764895 | +3.944% | 43 / 30 |
| 4 | Cold, later waves | 10.052938 / 6.158714 | -38.737% | 274 / 213 |
| 4 | Warm | 14.143874 / 9.054311 | -35.984% | 564 / 564 |
| 8 | Cold, all waves | 9.503634 / 9.422882 | -0.850% | 296 / 235 |
| 8 | Cold, initial wave | 7.754691 / 7.989989 | +3.034% | 36 / 29 |
| 8 | Cold, later waves | 9.503634 / 9.422882 | -0.850% | 260 / 206 |
| 8 | Warm | 17.107472 / 16.965850 | -0.828% | 515 / 509 |

In particular, C1 cold ping p99 increased 72.219%, from 1.168018 to 2.011546 ms.
C4 and C8 initial-wave ping p99 also rose 3.944% and 3.034%, despite the improvements
in the corresponding tool-call tails. Cold-all C4 ping p99 improved, while C8 was
close to its control. Shorter measured phases produce fewer ping observations,
and the 20 ms observer does not turn these small subsets into an SLA estimate.
A gain in tool-call throughput is therefore not a claim of uniformly better
responsiveness.

The resource comparison below takes the maximum of the retained phase-specific
observations across C1/C4/C8 cold-all and warm groups. Initial and steady subsets
are not counted again. These are non-atomic 100 ms observations, not simultaneous
whole-tree peaks or independently isolated allocation measurements.

| Metric: maximum within selected phases | R3 | R4e |
| --- | ---: | ---: |
| Controller RSS, KiB | 17,536 | 17,844 |
| Controller observed HWM, KiB | 17,536 | 17,844 |
| Controller FDs | 67 | 65 |
| Process-tree RSS, KiB | 113,084 | 105,128 |
| Process-tree FDs | 146 | 144 |
| Observed descendants | 8 | 7 |

Observed controller RSS was higher in every retained cold-all/warm group; its
overall phase maximum increased by 308 KiB, from 17,536 to 17,844 KiB (+1.756%).
Some observed FD, descendant and process-tree peaks were lower, but these samples
can miss short-lived processes and depend on the duration and alignment of the
measured phases. They do not establish a general resource-use improvement or
attribute the RSS difference solely to the new prediction containers.
The HWM field is a process-lifetime high-water value observed during these samples,
not an independent allocation peak for each phase.

Across the nonoverlapping cold-all and warm groups, R3 retained 780 resource
samples wholly within measured phases and R4e 753. Each of the six resource fields
has that many readable retained observations. The summaries also report 279 and
318 sampler errors respectively; these are accumulated error counts, not counts
of failed passes, and they must not be erased because summary fields were readable.
The summed group counts for samples excluded from phase peaks at boundaries are
5 and 4; a boundary pass may contribute to both adjacent groups. Raw boundary
observations and errors remain in the evidence, and missing
fields or unreadable processes do not mean zero resource use.

R4e has now completed exact-source qualification and the separate isolated Rust
comparison while retaining these regressions. The diagnostic and qualified
release ELF identities match, and both the native run and extended six-host soak
have completed. Publication follows the qualified source boundary recorded above.
The adoption decision below is
bounded by these measurements and does not establish that all optimization is
exhausted.

### R4e native validation: eight completed stages and original-job recovery

The [native compact report](../tools/x230/20261028/evidence/r4/native-r4-compact.json)
records `passed=true`, `complete=true`, all eight stages executed once and passed,
zero automatic retries, no unexecuted stage and a passed final input-integrity
check. Each original stage helper returned 0 without timeout and was reaped while
its cleanup owner retained custody. The native cohort ran from
2026-10-29 04:11:48.730595 to 04:18:40.776784 UTC. These are cohort timestamps;
throughput uses the measured call-cell times below, not the full cohort interval.

| Native evidence identity | Value |
| --- | --- |
| Original native report SHA-256 | `711970e679e04cfcac60daa86d859c70f1fd2e6a1078c20dcf8414377542b09d` |
| Compact JSON SHA-256 | `5b68fea2db1e8ab4d834d849a570765f04b4a0c34c2142c4e8f61fc1b507d729` |
| Native cohort nonce | `6ba8382fa4028afa6fa0c4b3` |
| Main orchestration job | `1a185db5843-96a-390f`; authoritative completion exit 0. |
| Main lease report SHA-256 | `de200a42a67efc2850fc94a016c50a1e9e81d8970758ba6f79d12751a0550a85` |
| Remote lease report SHA-256 | `41daf6af9c9de3d33d3c2b0de5795fa36d5f5b69486f5aa51c082d341e170a9e` |
| Forwarded lease nonce | `b8e9574bdb393d153d35603c31a66058` |

The native cohort nonce and forwarded lease nonce have different namespaces.
The [main lease receipt](../tools/x230/20261028/evidence/r4/leases/native-main-report.json)
binds its completion to the SHA of the
[remote lease receipt](../tools/x230/20261028/evidence/r4/leases/native-remote-report.json),
which binds the original native report SHA above. Both leases passed with one
launch, no automatic retry, return code 0 and original direct-child reaping.
The main SSH child and remote runner child each retained custody until their
actual reap. This records completion of those owned children; it does not claim
that unrelated processes were stopped or that production service ownership changed.

The native report directly names qualification report
`3d5d618eae594f2aa1b7e5902230d4600e32b1b163c2e759914c61bddda7997b`,
audit `69123251e571b140683e90dceb49c0746e07b91ca86ff7bd00d3f67c974eaf16`,
and runtime `8469fe7afdf560f4c501e5162cd7926957fade695118e9b9b72f1594ed861248`.
All three match the qualified R4e bindings. Its pinned protocol, stage helpers,
source and harness inputs remained subject to the original validation and final
integrity checks; an earlier candidate's native result is not reused here.

| Stage, in original order | Recorded result and scope |
| --- | --- |
| `small-archive-abba` | Passed once: 4,096 measured calls and 4,424 total tool calls; 64 records per round at C1. This is the native stdio hot small-archive guard, not a large-history or concurrent-throughput result. |
| `inherited-pipes` | Passed once: seven original cases, listed below, including one fixture cancellation. |
| `six-running-recovery` | Passed once: six original host/job identities, controlled controller SIGKILL, original-key recovery, 42 successful native calls and 30 successful SSH calls. |
| `file-abba-0-baseline` | Passed once: A62, 288 measured calls across C1/C4/C8, plus 24 auxiliary calls. |
| `file-abba-1-candidate` | Passed once: R4e, 288 measured calls across C1/C4/C8, plus 24 auxiliary calls. |
| `file-abba-2-candidate` | Passed once: R4e, 288 measured calls across C1/C4/C8, plus 24 auxiliary calls. |
| `file-abba-3-baseline` | Passed once: A62, 288 measured calls across C1/C4/C8, plus 24 auxiliary calls. |
| `candidate-c8-soak-120s` | Passed once: configured 120 seconds, 27 measured C8 cells and 2,592 successful measured calls; this remains separate from the completed extended run. |

#### Inherited pipes and six original recovery identities

The seven pipe cases were `natural`, `staggered` and `timeout` on both X230 and
Mac, plus one X230 `cancel` case. Exact original IDs, fixture-only effects,
shutdown and the single fixture cancellation all passed the original validator.
These exercise inherited pipes and process-lifecycle handling on those two
hosts; they do not constitute a power-loss or target-reboot experiment.

The running-job recovery stage launched exactly six controlled canary originals
and later performed exactly six same-key lookups. It retained these IDs:

| Host | Original recovery job ID |
| --- | --- |
| `ai395` | `1a185dc83f0-4e26e-4` |
| `mac` | `1a185dc83ea-4e26e-1` |
| `main` | `1a185dc83f1-4e26e-5` |
| `pocket4` | `1a185dc83ee-4e26e-2` |
| `rog` | `1a185dc83f1-4e26e-6` |
| `x230` | `1a185dc83ee-4e26e-3` |

The first owned controller exited with the intentional SIGKILL status `-9`.
The recovered controller subsequently shut down through stdin EOF with exit 0.
Both completion observations reported no descendant survivors, no reader error
and zero unmatched responses. All 42 native calls and 30 SSH observations were
recorded as okay. Source originals, runtime binary, forwarded agent and original
controller records remained unchanged where required, with no final record errors.
Automatic RPC retries, remote cleanup operations and production service mutations
were all zero.

“No observed survivors” is the recorded observation, not an exhaustive claim
about every process between samples. The crash observation retained one resource
sampling permission error; missing process data is not zero resource use. These
cases establish controlled controller-process recovery and original identity
retention. They do not establish disk durability through physical power loss or
recovery after a target-machine reboot.

#### Read-only file ABBA against A62

The file comparison uses the retained **A62 jobctl-start-durability baseline**,
release SHA-256 `fbc9cb15fb425e0d17ce570b52b9ba3e70d689c7c5d1ec68b99ac742d4879dde`,
with baseline qualification report
`8a97541d019f4b92f21f1073d4849b98f4e9db8c3a27ff536fc267e09d3ee651`.
Its denominator therefore differs from the R3 registry comparisons above.
Both arms used the pool-on file helper with tracing disabled, reading six
immutable synthetic outputs of 44–48 bytes through `file_info` and `binary_read`.
This measures small metadata and range-read operations rather than bulk bandwidth.

The four ABBA helper runs retained **1,152 measured calls plus 96 auxiliary calls**.
Those auxiliary calls were 48 warmups and 48 expected negative checks; each helper
required the `stale_version` and `outside_root` refusals for every host. A negative
call returning its required refusal is a passed check, not a measured-call failure.
All measured cells had exactly 96 successful calls with the original balanced
host/tool mapping. Every original call journal, unchanged input and owned shutdown
check passed; no file-write operation was part of this workload.

| C | Calls per arm | A62 calls/s | R4e calls/s | R4e change |
| --- | ---: | ---: | ---: | ---: |
| 1 | 192 | 3.920674 | 3.919355 | -0.0336% |
| 4 | 192 | 15.527799 | 15.408041 | -0.7713% |
| 8 | 192 | 22.050161 | 21.611085 | -1.9913% |

Rates divide all measured calls for an arm/concurrency by the sum of its original
cell wall times. All four ABBA runs remain included. Throughput was slightly lower
for R4e at each width, so **no file-throughput improvement is claimed**. This is one
short block over tiny immutable files, with local host-load observations every two
seconds and uncontrolled remote/background load; it does not establish statistical
significance, a production SLA or a broad multi-host capacity limit.

#### Completed native 120-second C8 soak

The original native stage configured 120 seconds and completed 27 consecutive
96-call C8 cells. All **2,592 measured calls succeeded**. Their measured cell times
sum to **121.33508366975002 seconds**, giving **21.362329 calls/second**. Setup,
12 warmups and 12 expected negative checks are outside that measured-call count.
These observed cell durations are distinct from helper startup, cleanup and the
full native-run timestamps. The original stage's `helper_elapsed_seconds` is
**128.93093385896645 seconds**. The compact report retained a null generic
`elapsed_seconds` field; the helper duration is taken from the full original
native report, as recorded in the [publication preparation receipt](../tools/x230/20261028/evidence/r4/publication-preparation.json).

Across the 27 cells, cell p95 ranged from 433.973 to 913.323 ms and cell p99 from
452.462 to 961.132 ms. These are ranges of per-cell percentiles, not a pooled
percentile for all 2,592 calls; the slower cells remain in the evidence.
The sampled controller RSS/HWM maximum was **18,584 KiB** and controller FD maximum
**88**. Observed local process-tree RSS/HWM reached 122,036 KiB and tree FDs 172.
The original sampler retained **27 resource-observation errors**. CPU/resource
scope covers the original controller and observed local descendants, excludes
remote CPU, and can miss short-lived peaks; these are not exhaustive limits or a
claim of general resource improvement.

The file stages did not expose a master-generation total:
`observed_master_generations_total` is null. Generation count remains **unknown**,
and neither the configured duration nor the cell count proves per-host master
rotation. File ABBA and soak owned-shutdown validation reported exit 0 and no
observed descendants remaining. Native local load gates and all 193 periodic
load samples were clear, but the two-second sampling interval does not guarantee
remote-host quietness or absence of unrelated work between samples.

The independent six-host C8 extended soak also completed, as recorded next. Its
successful outcome comes from its own original helper, call journal and lease
receipts, independently of the completed 120-second native stage.

### R4e extended six-host C8 soak: completed independently

The [extended compact report](../tools/x230/20261028/evidence/r4/extended-r4-compact.json)
uses schema `hepta-x230-extended-file-soak/v1`. It records `passed=true`,
`complete=true`, one executed controller/helper stage, return code 0, no timeout,
zero automatic retries and successful final input integrity. The original helper
was reaped while custody was retained. This is a separate completed run from the
eight-stage native protocol and its 120-second soak.

| Extended evidence identity | Value |
| --- | --- |
| Original report SHA-256 | `5442ddb8fc8e94da94a35a033153e81b3933ea90155288224b76ad52b178a729` |
| Compact JSON SHA-256 | `2d91ade0e8f20e6b6ff44fe1b4eada407fb407c4a05fa1bc45905cd7dc1cd173` |
| Raw call-journal SHA-256 | `8f3175066375a8bb715643072990242ec393744f57cf3f23603a3ce8dab039bf` |
| Main orchestration job | `1a185e81236-96a-3944`; authoritative completion exit 0. |
| Main lease report SHA-256 | `c0179f8de0ed19905b30b08dc3cfff6225743f6236d4eace6278bb596e6c85e4` |
| Remote lease report SHA-256 | `a1edac8cf763bc447670b19c8ce3de4f3da38e70e6c0e2445e408cc011283419` |
| Forwarded lease nonce | `b67406794c2aac7ce917e056ea6064ad` |

The extended report supplies no native-style cohort nonce; the nonce above
belongs only to its forwarded lease. The
[main lease](../tools/x230/20261028/evidence/r4/leases/extended-main-report.json)
binds the [remote lease](../tools/x230/20261028/evidence/r4/leases/extended-remote-report.json),
which binds the original extended-report SHA. Both receipts have
`report_kind=extended-soak`, one launch, no retry, return code 0 and actual original
child reaping with retained custody. The report's qualification, audit and runtime
identities match the same qualified R4e source and ELF used by the completed native
run. No new code change was introduced for this extension.

| Duration or call measure | Recorded value |
| --- | --- |
| Configured helper duration | 360 seconds. |
| Original helper lifetime | 373.1708621750586 seconds, including setup and completion work. |
| Sum of measured cell durations | 364.67598693142645 seconds; setup and gaps are outside this sum. |
| Measured cells | 74 consecutive C8 cells, 96 calls each, under one controller. |
| Measured calls | 7,104 successes, 0 failures. |
| Retained raw calls | 7,128: 7,104 measured + 12 warmups + 12 expected negative checks. |
| Measured rate | 19.4803065 successful calls/second, using measured cell time. |

The reused native structure validator retains its historical 120-second minimum.
The extended layer separately validated the actual 360-second helper configuration,
helper lifetime, all raw samples, summed cell time and six-host distribution. The
nested structural minimum is not the duration configured for this run. Every
original cell and call remains in the report and journal.

| Host | Measured successes / calls | Warmup checks passed | Expected-refusal checks passed | Failed checks |
| --- | ---: | ---: | ---: | ---: |
| `ai395` | 1184 / 1184 | 2 | 2 | 0 |
| `mac` | 1184 / 1184 | 2 | 2 | 0 |
| `main` | 1184 / 1184 | 2 | 2 | 0 |
| `pocket4` | 1184 / 1184 | 2 | 2 | 0 |
| `rog` | 1184 / 1184 | 2 | 2 | 0 |
| `x230` | 1184 / 1184 | 2 | 2 | 0 |

Expected negative checks succeeded by returning their required refusals; they
are not failed measured reads. The workload used the pinned pool-on file helper
to read the same six immutable 44–48 byte synthetic outputs through `file_info`
and `binary_read`, with no remote writes or new remote execution effect. Its
single-controller completion and balanced coverage do not measure bulk transfer
bandwidth or a sustained new-job launch rate.

This longer run has no interleaved control arm. Its 19.4803065 calls/second is a
completion-run observation, not a cross-version gain, and is not pooled with the
120-second stage or file ABBA. Per-cell p95 ranged from 428.704 to 1,028.913 ms,
and per-cell p99 from 460.123 to 1,344.053 ms. The slower cells are retained; these
ranges are not percentiles pooled across all 7,104 calls.

Sampled controller RSS/HWM reached **18,428 KiB**, controller FDs **92**, and
observed local process-tree RSS/HWM **128,376 KiB** with tree FDs 198. The original
resource sampler retained **65 observation errors**. These observations cover the
controller and sampled local descendants, exclude remote CPU and can miss short
process lifetimes. They do not establish a general memory improvement or exhaust
all possible resource peaks.

The before/after local load gates and all 184 periodic load samples were clear;
the latter had no sampling errors or unclear observations. These two-second
local checks do not establish remote-host quietness between samples. The original
owned-shutdown checks passed, including no observed surviving descendants.
Master-generation evidence remains **unknown** because the helper did not supply
that field. The elapsed duration does not prove either a total generation count
or per-host master rotation.

### Adoption and empirical stopping point for this iteration

**Adopt R4e for this iteration and stop further implementation changes to this
qualified source.** The decision rests on the completed exact-source qualification,
the real release MCP comparison, the separate Rust comparison, all eight native
stages and the independently completed extended soak. The qualified runtime and
measured release ELF are identical, and the publication boundary matches the
qualified compiler and harness inputs.

The targeted result is lower repeated validation cost for concurrent refreshes
of existing strict identities. In release MCP, cold C4 throughput rose 34.803%
while controller CPU per call fell 75.277%; C8 rose 30.073% with CPU per call down
63.214%. The independent Rust known-invalidated results support the same limited
mechanism without being combined with the release percentages. R4b's rejection
shows why the release admission pattern mattered; R4c and R4d did not deliver the
intended concurrent CPU reduction. R4e covers predicted identities from the start
of each complete scan while retaining uncovered-worker bypass and all original
validation fences.

The acceptance includes the measured costs. Fresh-positive Rust throughput fell
by 1.841%, 0.381% and 1.442% at C1/C4/C8, with larger C8 median and tail-latency
regressions recorded above. Release C1 cold ping p99 rose 72.219% to about 2.012 ms,
and the observed controller RSS phase maximum increased by 308 KiB. Read-only
file ABBA against A62 showed small throughput declines at every width. The longer
soak completed without failed checks but retained slow cells, sampler errors and
unknown master-generation coverage. These are explicit boundaries of the result,
not omitted failures or claims of uniformly better performance.

This is a practical stopping point supported by the tested X230 workloads and
retained receipts. It does not demonstrate a theoretical optimum or prove that
no further optimization exists. New identities, absent keys and required fallback
paths still perform O(N) complete-history validation. Strict receipt reads,
content-watch/epoch fencing and original ownership checks continue to cost work;
R4e reduces repeated scans for a bounded positive cohort without removing those
obligations.

A future persistent index would need a separately designed and tested atomic
publication and crash-recovery protocol: its updates must remain consistent with
durable receipts and ownership fences, its rebuild/reconciliation rules must
handle interrupted writes, and it must preserve the current duplicate and
corruption refusals. The current evidence does not validate such an index.
Changing worker limits, admission policy or the remaining complete-scan path
also needs its own concrete hypothesis and controlled comparison. This iteration
therefore preserves the qualified R4e bytes for publication with the completed
evidence package and its verified source boundary.

An [initial evidence export](../tools/x230/20261028/evidence/r4/diagnostics/evidence-export-r01.json)
failed during the collector's self-screen because its own source contained the
literal PuTTY marker used by the credential scanner. Splitting that source literal
into adjacent byte strings preserved the AST, compiled regex bytes and flags;
evidence contents and exclusion policy were unchanged. The corrected `export-r4-r02`
completed successfully. This was a packaging failure, with no Rust/runtime
failure and no test or external-effect replay.

### Original evidence package and byte verification

The [package index](../tools/x230/20261028/evidence/r4/package-index.json) binds the
archive, manifest and publication receipts. The archive retains the rejected
iterations and their original failures alongside final R4e qualification,
comparisons, recovery and soak artifacts. It contains no executable artifacts,
live job state, trust material, private keys or environment dumps.

| Artifact | Exact size / integrity |
| --- | --- |
| [Original evidence archive](../tools/x230/20261028/evidence/r4/evidence-package.tar.gz) | 26,023,585 bytes; SHA-256 `a9d799c7b1e719c5da6424c26fc37cef7860c85538ac5aed5f1418ea40d2517d` |
| Original file payloads | 6,789 files; 131,321,244 bytes before compression. The additional `metadata.json` member is the manifest. |
| [Original manifest](../tools/x230/20261028/evidence/r4/evidence-manifest.json) | 7,362,748 bytes; SHA-256 `eb89e12c98a96040f98cc89620f0b73dd03dc4bd9ad12417270e58bfd2d7c29a` |
| [Publication preparation](../tools/x230/20261028/evidence/r4/publication-preparation.json) | Archive size/hash, all 6,789 individual payload hashes, exact member set, safe regular member types and the 14 qualified code files verified after transfer. |
| [Archive/lease joins](../tools/x230/20261028/evidence/r4/archive-lease-joins.json) | Both main completion receipts join to the original remote lease, original report and remote heartbeat/runner logs by full recorded identity, size and hash. Original source references remain bound by separate qualification/publication maps. |

Main-host lease reports and their original heartbeat/SSH logs are retained
separately under [leases/](../tools/x230/20261028/evidence/r4/leases/).
The [independent local lease review](../tools/x230/20261028/evidence/r4/leases/independent-local-review.json)
records its narrower local-only scope; the later archive/lease join above closes
its original-archive verification gap. Native and extended leases retain 42 and
39 main heartbeats respectively, one launch each, zero retries, the actual child
wait identities and custody through reap. These joins do not replay any workload.

### R4e evidence status and publication boundary

| Evidence category | R4e result / historical evidence boundary |
| --- | --- |
| R4e exact-source qualification | Completed: 8 gates passed, 1,522 Rust cases executed and passed, 0 failed, 25 ignored, 57 Python cases passed; all 21 coalescing cases passed. The independent audit, source/harness maps and runtime identity are bound above. |
| Direct Rust ABBA, fresh positive C1/C4/C8 | Completed on the qualified R4e libtest ELF: throughput changed -1.841% / -0.381% / -1.442%; CPU and latency regressions remain in the full tables. |
| Direct Rust ABBA, absent C1/C4/C8 | Completed: throughput changed +0.770% / +0.571% / +2.116%, with C1/C4 p95 regressions retained. |
| Direct Rust ABBA, known-invalidated C1/C4/C8 | Completed: throughput changed +0.666% / +75.679% / +49.117%; CPU per call changed -0.976% / -80.590% / -63.165%. |
| R4e direct runtime MCP cold-initial / cold-steady / warm | Completed: 4 rounds in ABBA order, 5,184 successful calls, 0 failed. All 12 groups are reported above, and the measured source map/runtime SHA match the completed qualification. |
| R4e ping and resource observations | Completed for this diagnostic: C1 cold ping p99 rose 72.219% to 2.012 ms, and observed controller RSS rose 308 KiB. Scope, sampling errors and coverage are reported above; there is no general resource-improvement claim. |
| R4e native recovery / SSH maintenance cases | Completed: all 8 stages passed once, zero retries, final input integrity passed. Six original recovery IDs were retained through the controlled crash; the completed native report and both lease receipts are bound above. |
| Additional continuous six-host C8 soak | Completed once: 360 seconds configured, 364.67598693142645 measured seconds, 74 cells, 7,104 successful measured calls and 7,128 total raw calls. All six hosts have zero failed checks; sampler errors and unknown generation evidence remain explicit. |
| Candidate adoption / stopping decision | Accepted for this iteration on completed qualification, both registry comparisons, eight native stages and the separate extended soak. The practical stopping boundary and retained costs are stated above; this is not a theoretical-optimality claim. |
| Publication identity | The commit hosting this report, with parent `f0f1c1da4e62404fc800df0f186db5948b4ad38d`. [PR #77](https://github.com/TrillionniumFoundation/hepta-runtime/pull/77) records the pushed SHA and the checks for that SHA; historical R3 CI results are not R4e CI evidence. |

## Limits and interpretation

Sharing is restricted to existing launched positive identities in one cooperating
registry owner process. No negative result becomes new-effect authority. The
unchanged persistent registry remains the recovery source after controller exit;
the ephemeral coordination object is reconstructed empty. The current content
watch trust boundary, including the existing limitations around arbitrary
same-UID mutation and mmap writes, is unchanged.

Cold-positive throughput, absent-key throughput, CPU per call, memory observations
and ping responsiveness can move in different directions. Report each separately.
The isolated lookup benchmark and the denied-SSH MCP benchmark are complementary
workloads and must not be pooled into a single throughput claim. Neither measures
bulk transfer bandwidth, remote launch capacity or a production latency SLA.

RSS/FD and process-tree CPU samples can miss short-lived descendants and cannot
form an atomic whole-process snapshot. Missing fields and permission errors are
unknown observations, not zero use. Phase sample peaks, process-lifetime maxRSS
and the controller's own CPU delta are different metrics.

Source correctness, final release qualification, native recovery outcomes,
measured performance and deployment state remain separate assertions. A pushed
commit makes the work reviewable; it does not by itself merge the candidate,
transfer a production owner or establish that further optimization is impossible.

The R4b rejection also limits what can be inferred from isolated lookup results:
favorable CPU and throughput measurements did not predict the release workload's
response-driven admission of later keys. The adoption and stopping decision above
therefore uses the exact R4e runtime evidence. First observations, absent
keys and fallbacks still pay for complete historical validation; larger changes
to indexing, invalidation or worker limits require their own semantic review and
direct experiments. No theoretical-optimality or exhausted-optimization claim is
made for this candidate.

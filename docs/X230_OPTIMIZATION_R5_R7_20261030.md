# X230 R5–R7: persistence, cold lookup and bounded resource work

## Status and comparison boundaries

This work continues [PR #77](https://github.com/TrillionniumFoundation/hepta-runtime/pull/77)
on the existing
[`perf/x230-concurrency-recovery-20261028` branch](https://github.com/TrillionniumFoundation/hepta-runtime/tree/perf/x230-concurrency-recovery-20261028).
The [R4 report](X230_OPTIMIZATION_R4_20261028.md) remains evidence for its own
qualified source and measurements.

**R5b completed its X230 correctness qualification, isolated receipt/idle
comparison, two release MCP ABBA blocks, and eight-stage native validation.**
The isolated receipt work became substantially cheaper for large records, and an
empty SSH observation actor stopped waking periodically. The release MCP
comparison showed approximately unchanged throughput and a **14.400% increase
in pooled cold-C8 p99**. Those results do not support a general runtime speedup.

**R6a has completed all eight X230 qualification gates:** 1,557 Rust tests
passed, zero failed, 28 were ignored, and 57 Python harness tests passed. Its
two planned release MCP ABBA blocks also completed successfully. Against newly
measured R5b controls, pooled cold-C8 throughput increased **57.950%**, controller
CPU per successful call fell **64.821%**, and p99 fell **39.555%**. Warm-C4
throughput fell **3.221%** and p99 rose **9.429%**, with the same regression
direction in both blocks. The results establish a gain for the measured cold
reuse workload and retain the warm-path cost; they do not establish a uniform
runtime improvement.

**R6a also completed its own eight-stage native validation successfully.**
Later complete-chain revalidation stopped because a retained historical A62
test executable was missing. That revalidation remains blocked; no detailed
native aggregates are newly claimed from it.
A separate isolated R6b candidate has completed all eight qualification gates:
1,560 Rust tests passed, zero failed, 28 were ignored, and 57 Python harness
tests passed. Its exact ignored diagnostic and both planned release ABBA blocks
also completed. **R6b was rejected for adoption before native validation:** its
pooled cold-C4 p99 rose 15.479% and warm-C4 p99 rose 9.615% against newly measured
R6a controls, with mixed directions between blocks. Those unexplained outcomes
did not satisfy R6b's predeclared performance gate. This is not a correctness
test failure or a native-test failure; R6b's planned native suite was not run.
R6a supplies the accepted comparison baseline for the resource-focused follow-up.

**R7b completed its own eight-gate X230 qualification on R6a: 1,573 Rust tests
passed, zero failed, 28 were explicitly ignored, and 1,601 were selected across
five retained test executables.** It bounds actual owner-fence acquisition workers and avoids
retaining private record payloads throughout an unpaginated inventory request.
Its 200-input tested and post-qualification maps match. Both direct release
ABBA blocks and the fixed inventory RSS series have completed. The inventory's
whole-child median peak fell **81.628%**, passing both predeclared resource
gates, while release **cold-C8 throughput fell 1.811% and p99 rose 12.112%**
with adverse directions in both blocks. Its own paired native suite and the
complete evidence/custody checks also passed. **R7b is accepted for publication
as an explicit resource-versus-latency tradeoff**, retaining the measured
cold-C8 cost and making no general speedup claim. Separately, its two measurement-harness
regression suites passed on X230: 16 RSS and 19 paired-native Python tests. These 35 supplemental cases do not replace the original
qualification's Python gate or qualify any Rust/runtime behavior. The prepared
R7a variant on R6b was never executed. No R6b atomic-claim change is carried into R7b.
Publication identity and live exact-head / prospective-merge CI acceptance are
recorded on [PR #77's current head](https://github.com/TrillionniumFoundation/hepta-runtime/pull/77).
Each candidate's qualification and measurements retain their own source boundary.

| Work | Source and result boundary |
| --- | --- |
| R5a | Rejected qualification: 1,535 Rust tests passed, one failed, 27 ignored. The failing maintenance-startup fixture assumed that one poll was sufficient to observe startup. No R5a performance result is used. |
| R5b | The fixture uses an explicit startup handshake. A fresh full qualification passed: 1,542 Rust tests, zero failures, 27 ignored. All R5b measurements below use its retained, identified artifacts. |
| R5b receipt/idle comparison | R4e control versus R5b libtest executables. These measurements isolate receipt reads and an empty observation actor. |
| R5b release MCP comparison | Retained R4e release versus qualified R5b release, two complete ABBA blocks. All eight controllers are included. |
| R5b native validation | Qualified R5b release; the historical comparison arm is A62, not R4e. This suite establishes the tested native behavior and recovery outcomes. |
| R6 baseline diagnostic | R5b production code with a test-only probe overlay. One exact ignored test executed once and passed. No candidate performance claim follows from this run. |
| R6a qualification | All eight gates succeeded for its own frozen 198-file input map: 1,557 Rust cases passed, zero failed, 28 ignored; 57 Python harness tests passed. |
| R6a candidate diagnostic | One exact ignored test executed once and passed, separately from qualification. It covers 192 calls and compares lookup-only scan counts and timings with the R5b production baseline. |
| R6a release MCP comparison | Both planned R5b/R6a ABBA blocks passed; all eight controllers and all 10,368 measured reuse calls are included. The warm-C4 regression is retained. |
| R6a native validation | All eight original stages completed once with the qualified R6a artifact against A62. Later complete-chain revalidation is blocked by a missing retained A62 test executable; further aggregate extraction stopped. |
| R6b qualification | All eight gates succeeded for its own 199-file tested map: 1,560 Rust cases passed, zero failed, 28 ignored; 57 Python harness tests passed. |
| R6b candidate diagnostic | One exact ignored diagnostic passed once: 192 calls, one complete scan in every cold wave and zero in warm waves. Lower scan counts did not uniformly lower elapsed time. |
| R6b release MCP comparison | Both planned R6a/R6b ABBA blocks completed; all eight controllers and 10,368 reuse calls are included. Cold-C4 and warm-C4 pooled p99 increased, with mixed per-block directions. |
| R6b adoption/native | Rejected for adoption under its original performance gate. Its native suite was left unexecuted; no native failure or acceptance is claimed. |
| R7a | Resource combination prepared on R6b, never qualified or measured; superseded without using its artifacts as evidence. |
| R7b qualification | All eight gates passed for its own 200-input tested map: 1,573 Rust cases passed, zero failed, 28 ignored, 1,601 selected across five retained executables. All 16 new resource regressions and 15 specified existing contracts are proven in the original complete audit. |
| R7b measurement-harness regressions | Separate X230 runs passed 16 RSS and 19 paired-native Python cases; the latter uses synthetic binding fixtures and launches no runtime, native helper or SSH operation. |
| R7b release comparison | Both fixed R6a/R7b ABBA blocks completed: 23,781 successful RPCs, zero failed/missing; cold-C8 throughput/p99 regressed in both blocks and 1,111 resource-sampling errors remain visible. |
| R7b inventory resources | All eight original processes completed; median whole-child peak RSS fell 81.628% and every candidate peak was below every control peak. These are fixed-fixture results, not steady service-RAM bounds. |
| R7b native/adoption | Own eight-stage paired R6a/R7b suite and full evidence/custody checks passed. Accepted under the predeclared resource-versus-latency rule, retaining all adverse release/native results. |
| Publication | Use PR #77's current source head and prospective-merge checks for final publication and CI acceptance. Historical successful runs do not qualify a later head. |

All completed builds, Rust tests and measurements described here ran on X230. They use
isolated fixtures and retained executables. No production service installation
or ownership transfer is claimed. Original run records remain retained with
their hashes; this report contains code-level explanations and aggregate
measurements rather than operational configuration or execution payloads.

## R5b implementation

The relevant production changes are in
[`jobs.rs`](../src/mcp/runtime/jobs.rs),
[`effect_owner_fence.rs`](../src/mcp/runtime/effect_owner_fence.rs), and
[`ssh_observation_pool.rs`](../src/mcp/runtime/ssh_observation_pool.rs).

| Change | Intended effect | Boundary retained |
| --- | --- | --- |
| Compare already decoded `JobRecord` values directly at two same-stage verification sites | Avoid serializing and hashing both copies of a large record | Equality covers all 17 decoded fields. Cross-stage cohort binding still uses the full record digest. |
| Size the strict-read buffer from the verified length plus one byte | Avoid repeatedly growing the buffer while reading a large receipt | Existing strict 1 MiB limit, compatibility 4 MiB limit, guarded open, file identity checks and change detection remain. |
| Suspend the maintenance timer while the SSH observation actor is empty | Remove periodic idle wakeups | Work arrival notifies and rearms maintenance. Retirement and failure cleanup retain their original owner. |
| Run start persistence work in bounded blocking workers | Keep synchronous durable filesystem work off the async executor | Four start-I/O workers; the actual worker retains its permit, same-key lane and effect-owner guard. |
| Reserve launch-outcome publication capacity before remote submission | Keep ownership of an acknowledged or uncertain result across caller cancellation | Eight bounded outcome publications; the result writer is submitted before the first cancellable wait after acknowledgement. |
| Give cancellation its own bounded publication capacity | Keep cancellation of an existing job available when start capacity is saturated | Eight cancellation publications independent of start lanes; retain the original job identity and the distinction between a stop request and observed termination. |

The cache still represents verified existing identities. It does not authorize
a replacement execution when the original receipt is missing, unsafe, changed
or uncertain. No persistent index, new remote scheduler or ownership protocol
is introduced by these changes.

### Persistence and cancellation ordering

A start still durably records intent and its recoverable pending identity before
submitting the remote operation. The filesystem durability sequence remains in
place: write and synchronize, atomic publication, and directory synchronization
where required. Per-event audit `sync_data` is retained. The optimization changes
where this work runs and who holds its capacity, not the required durability
ordering.

After a remote acknowledgement, the already reserved outcome-publication slot
and the original identity move to the real writer before the caller can suspend
at the next cancellation point. Cancelling the async waiter does not release
that writer's lane or permit while it still owns the work. A local publication
error does not relabel a remote acknowledgement as a successful local durable
publication; uncertainty and publication failure remain visible.

Cancellation follows the original job's existing authority. It does not require
admission for a new effect. Its independent capacity prevents saturated launch
publication slots from blocking this continuation. `stop_requested` remains a
request acknowledgement, and an unknown remote outcome remains unknown until
reconciled.

| Failure or interruption | Required behavior |
| --- | --- |
| Caller cancelled before worker admission | Submit no new persistence worker or remote operation from that waiting caller. |
| Caller cancelled while a persistence worker runs | The actual worker retains its permit and owned state until it finishes. |
| Intent or pending-identity publication fails | Do not submit the corresponding remote effect. |
| Acknowledgement received, caller cancelled before local publication completes | Preserve the already submitted outcome writer and original identity. |
| Outcome publication or audit fails | Preserve the remote result or uncertainty and report the local publication failure truthfully. |
| Runtime process is killed | In-memory `Arc` ownership provides no process-crash durability. Recovery relies on the original durable identity and reconciliation path. |

Focused regression coverage is in
[`jobs_start_io_tests.rs`](../src/mcp/runtime/jobs_start_io_tests.rs),
[`jobs_cancel_io_tests.rs`](../src/mcp/runtime/jobs_cancel_io_tests.rs),
[`jobs_record_comparison_tests.rs`](../src/mcp/runtime/jobs_record_comparison_tests.rs),
and the SSH observation maintenance tests. The complete qualification also runs
the existing registry, ownership, cancellation and recovery regressions.

## R5b qualification

The eight gates were format, format check, Python qualification-harness tests,
all-target/all-feature Clippy with warnings denied, test build, isolated exact
Rust cases, independent audit of those cases, and release build. Each gate ran
once for R5b; no automatic test retries were used. The auditor binds the original
test output, selected cases, retained executables and tested source map.

| Item | R5b result |
| --- | --- |
| Rust cases across five test executables | 1,542 passed; zero failed; 27 explicitly ignored; 1,569 selected |
| Qualification-harness Python tests | 57 passed |
| Additional receipt/idle parser tests | Six passed separately |
| Compiler-input map | 196 files; tested and post-qualification source maps match |
| Rust toolchain | 1.95.0 |
| Retained libtest profile | Optimization level 1, debug information disabled |
| Retained release profile | Optimization level 3, LTO, one codegen unit |

R5a's failed original qualification remains a rejected result. R5b fixed the
fixture's startup observation with an explicit synchronous factory handshake
and then received a fresh full qualification. The rejected run is not counted
as a successful retry or included in performance aggregates.

Both exact-head and prospective-merge GitHub CI jobs now discover the six
receipt/idle parser regressions in `tools/x230/20261029`, in addition to the
existing `tools/x230/20261028` suite. This report does not reuse an earlier
commit's GitHub CI status as evidence for a later source head.

## Isolated receipt and idle measurements

The receipt comparison used retained R4e and R5b libtest executables in ABBA
order: 144 measured waves, 9,216 successful calls, 4,608 per arm, and 512 per
record-size/mode cell in each arm. The table reports CPU time per call and the
measured call-throughput ratio. These are lookup-only test measurements; they
exclude the complete MCP, audit, SSH and remote job-start path.

| Mode | Record size | R4e CPU µs/call | R5b CPU µs/call | R5b/R4e call throughput |
| --- | ---: | ---: | ---: | ---: |
| Strict read | 1 KiB | 18.406 | 18.383 | 1.001× |
| Strict read | 64 KiB | 49.441 | 47.586 | 1.040× |
| Strict read | 768 KiB | 380.201 | 363.652 | 1.051× |
| Strict rescan | 1 KiB | 70.113 | 47.053 | 1.490× |
| Strict rescan | 64 KiB | 946.090 | 109.609 | 8.634× |
| Strict rescan | 768 KiB | 10,434.473 | 890.236 | 11.724× |
| Fresh lookup | 1 KiB | 77.484 | 52.707 | 1.470× |
| Fresh lookup | 64 KiB | 912.064 | 115.687 | 7.887× |
| Fresh lookup | 768 KiB | 10,399.861 | 903.256 | 11.519× |

For the 768 KiB strict-rescan cell, CPU cost fell by 91.468%. The small gain in
strict read alone and the larger gains in paths that previously reserialized
records are consistent with the intended reduction in repeated serialization
work. These results do not establish an 11.724× improvement in process starts
or overall runtime throughput.

The empty-actor comparison used two approximately ten-second observations per
arm. CPU percentages below are rates relative to one CPU core.

| Empty observation actor | R4e | R5b |
| --- | ---: | ---: |
| Total observed wall time | 20.002596 s | 20.002097 s |
| Total CPU time | 53.268 ms | 0.910 ms |
| CPU rate, one core | 0.266305% | 0.004550% |
| Maintenance passes | 200 | 0 |
| Voluntary context switches | 399 | 6 |

The CPU rate fell by 98.292%, an absolute reduction of 0.261756 percentage
points of one core. This is an empty actor's resource cost. It is not a
whole-runtime CPU or memory claim, nor a measurement of a busy SSH pool.

The reusable runner and its parser regressions are
[`run_record_idle_abba.py`](../tools/x230/20261029/run_record_idle_abba.py) and
[`run_record_idle_abba_tests.py`](../tools/x230/20261029/run_record_idle_abba_tests.py).

## Release MCP comparison: R4e versus R5b

Two complete ABBA blocks ran the original registry-cohort harness with eight
waves, 48 warm calls per wave and 6,000 synthetic historical records. The
second block ran while this optimization task paused its other X230 activity;
that does not establish exclusive ownership of the entire host. All eight
controllers are included. No third block was selected to replace an
unfavorable result.

Each cold wave contains **six original identities**. Thus “C8” is the configured
concurrency limit; cold waves can have at most six simultaneous calls. Warm
waves contain enough calls to fill eight slots. The benchmark reuses the
original identities through a local denial wrapper; it does not submit real
SSH operations, allocate new keys or launch remote effects.

The pooled result contains 10,368 successful reuse calls and 15,604 successful
pings, or 25,972 successful RPCs, with zero failed or missing RPCs. Rates and CPU
costs are derived from summed counts and times. Quantiles are recomputed from
original per-call attempts rather than averaged from per-controller quantiles.

| Workload / limit | R4e calls/s | R5b calls/s | Throughput change | R4e CPU ms/call | R5b CPU ms/call | R4e p99 ms | R5b p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Cold C1 | 6.348855 | 6.206011 | −2.250% | 120.677083 | 126.197917 | 203.526333 | 200.365934 |
| Cold C4 | 18.636612 | 18.664437 | +0.149% | 41.302083 | 41.562500 | 206.494486 | 207.931934 |
| Cold C8 | 19.286861 | 19.197964 | −0.461% | 62.135417 | 61.510417 | 345.833092 | 395.631512 |
| Warm C1 | 23.462823 | 23.311517 | −0.645% | 7.428385 | 7.584635 | 50.493541 | 52.733302 |
| Warm C4 | 61.939168 | 61.367254 | −0.923% | 5.813802 | 5.891927 | 93.827071 | 96.166301 |
| Warm C8 | 62.665139 | 63.788466 | +1.793% | 6.263021 | 6.295573 | 213.878400 | 202.675846 |

Cold-C8 p99 rose **14.400% pooled**, with increases in both individual blocks
(21.222% and 9.892%). Warm-C8 p99 fell 5.238%. Each cold cell has only 96 calls
per arm per block: its nearest-rank p99 is its maximum. The pooled 192-call p99
is its second-largest observation. These tail estimates are sensitive to a
small number of calls and are reported with their actual sample sizes.

The sampled controller RSS peaks were 17,892 KiB for R4e and 17,812 KiB for R5b;
sampled descriptor peaks were 66 for both. The 80 KiB RSS difference is
essentially flat in this experiment. There were 1,085 resource-observation
errors. Successful RPC accounting does not remove those sampling limitations,
and no general memory reduction is claimed.

### Inspection of the original slow waves

Independent analysis checked the hashes of all eight original compressed event
journals and reproduced all 48 call/ping groups' counts and nearest-rank
p50/p95/p99/max values. Only four of the 192 R5b cold-C8 calls exceeded 350 ms,
and they occurred in two waves:

| Block / R5b wave | Two slow calls | Controller CPU for the wave | Wave wall time |
| --- | ---: | ---: | ---: |
| First block, wave 7 | 399.658 / 395.632 ms | 510 ms | 401.774 ms |
| Quiet block, wave 4 | 381.048 / 378.570 ms | 490 ms | 384.817 ms |

The other 188 R5b calls had a maximum of 321.004 ms; the R4e maximum was
346.748 ms. Among all 64 cold-C8 waves, 13 used 240–280 ms controller CPU, 49
used 370–430 ms, and these two used 490–510 ms. Additional CPU work is
compatible with an extra full-history scan, but these CPU bands do not directly
count scans or establish causation.

The same two slow waves had maximum ping delays of 9.054 and 7.121 ms. They do
not show an 80–100 ms stall of the entire MCP executor. Sparse resource
observations also do not establish the absence of brief allocation, scheduling,
page-fault or frequency effects. In particular, a resource sample in one of
the slow waves failed.

## R6a qualification and bounded peer-hit prefill

### Qualified candidate

R6a completed the same eight-gate qualification sequence described above, using
its own frozen source and retained release artifact. The tested and
post-qualification source maps match. Its result is independent of R5b's
historical qualification and does not reuse R5b test output as candidate
evidence.

| Item | R6a result |
| --- | --- |
| Rust cases across five test executables | 1,557 passed; zero failed; 28 explicitly ignored; 1,585 selected |
| Qualification-harness Python tests | 57 passed |
| Compiler-input map | 198 files; tested and post-qualification maps match |
| Qualification gates | All eight succeeded |
| Separately executed ignored diagnostic | One exact test passed; zero failed; 1,527 tests filtered out; one execution |

The 15 additional non-ignored regressions in
[`jobs_registry_prefill_tests.rs`](../src/mcp/runtime/jobs_registry_prefill_tests.rs)
cover the leader-to-peer hit path, strict original ownership, every changed
persisted record field, equivalent JSON, missing/unsafe/corrupt peers,
duplicates and pending records, failed complete scans, leader refusal,
watch/epoch and cache-root changes, full budgets, concurrent capacity fill,
auxiliary-verification panic and cache poison. They are part of the complete
qualification above. The ignored timing probe was executed separately and is
not added to the 1,557 qualification passes.

### Baseline and candidate lookup-only probe

The test-only
[`jobs_cohort_tail_probe.rs`](../src/mcp/runtime/jobs_cohort_tail_probe.rs)
uses the real `run_registry_lookup` admission path, four lookup slots, two Tokio
workers, six known strict original identities and 6,000 unqueried synthetic
records. Initial identity priming and blocking-thread startup occur outside
the measured waves. A marker invalidates the cache before each cold wave.

The R5b production baseline's exact test executed once and passed. The R6a
candidate's exact test also executed once and passed. Each execution produced
32 six-call waves, or 192 successful calls. Each of two patterns contains eight
cold and eight warm waves. The original baseline scan counts are:

| Pattern | Full scans in the eight cold waves | Cold scan total | Full scans in warm waves | Peak actual lookup workers |
| --- | --- | ---: | ---: | ---: |
| Natural six-call submission | 3, 4, 3, 3, 4, 3, 3, 3 | 26 | 0 | 4 |
| First four complete before final two are submitted | 4, 3, 2, 2, 2, 3, 4, 4 | 24 | 0 | 4 |

R6a produced the following candidate scan counts using the same probe:

| Pattern | Full scans in the eight cold waves | Cold scan total | Full scans in warm waves | Peak actual lookup workers |
| --- | --- | ---: | ---: | ---: |
| Natural six-call submission | 1, 1, 1, 1, 2, 2, 2, 1 | 11 | 0 | 4 |
| First four complete before final two are submitted | 1, 2, 3, 1, 1, 1, 1, 1 | 11 | 0 | 4 |

The comparison below sums worker CPU and wave wall time over the eight cold
waves of each pattern. Maximum lookup latency is a single observed call, not
a percentile. Each pattern has 48 cold calls per source.

| Cold pattern / metric | R5b baseline | R6a | Change |
| --- | ---: | ---: | ---: |
| Natural: complete scans | 26 | 11 | −57.692% |
| Natural: summed worker CPU | 3,264.912600 ms | 1,302.490143 ms | −60.106% |
| Natural: total wave wall time | 1,800.016003 ms | 947.722356 ms | −47.349% |
| Natural: maximum lookup latency | 239.189125 ms | 152.828706 ms | Decreased |
| Staged: complete scans | 24 | 11 | −54.167% |
| Staged: summed worker CPU | 2,908.226794 ms | 1,542.225017 ms | −46.970% |
| Staged: total wave wall time | 1,917.708685 ms | 1,060.313450 ms | −44.709% |
| Staged: maximum lookup latency | 170.081496 ms | 183.548974 ms | **Increased** |

All 16 warm waves in each execution performed zero complete scans, and both
executions retained the four-worker limit. Per-call inspection of R6a's staged
cold waves found zero scans in each wave's final two calls. Its additional
scans occurred among the first four calls. The probe does not directly record
each internal routing decision, so these observations do not establish which
branch caused each remaining scan.

The natural pattern contains no registration or scan barrier, sleep or
artificial wait inside the measured admission path. The second pattern is a
deliberately staged diagnostic and is labelled as such. Both preserve all six
original IDs, the four-worker cap, and final demand/hint/active-state cleanup.

This probe directly confirms repeated full scans in the R5b production lookup
path and fewer scans in R6a under this fixture. It excludes start audit, SSH and
the RPC envelope, and runs in retained optimization-level-1 libtest executables.
It is one baseline/candidate diagnostic execution per source, not a release
ABBA experiment. Its scan counts and timings cannot be relabelled as release
MCP throughput or proof that R6a has fixed the historical p99 regression. The
increased staged maximum also prevents a claim that every measured tail
improved. `submit_to_worker_ms` combines async
scheduling, semaphore admission and blocking-pool dispatch. The recorded
cohort-wait-to-lookup-end interval includes final verification and is an upper
bound on gate wait.

The first diagnostic driver stopped before compilation because its source-map
check found a transfer-generated lock sidecar in the isolated source copy. The
next driver compiled the probe and ran the exact test successfully. Its report
parser then rejected the output because libtest printed the test name and the
JSON marker on the same line. Independent parsing recovered and checked the
single original successful result. Both driver outcomes and the original
stdout are retained; the probe was not rerun to obtain a preferred sample.

### Bounded prefill implementation

Only workers that already hold one of the four lookup permits register cold
demand. A leader's bounded frozen cohort can include recently verified strict
identities, but its hint publication keeps results only for identities with a
live admitted demand. The last two callers in a six-call wave can therefore
arrive after publication and miss a scan result that already covered their
identity.

R6a populates the **existing positive-hit cache** for a
bounded set of those already known strict peers after a successful complete
scan. Its eligibility and publication rules are:

1. Use only a unique `launched` candidate from the frozen cohort, with a valid
   original ID and an already retained matching strict ownership binding.
2. Strictly reread that original receipt, verify its ID, host, key and launch
   state, and compare its complete cross-stage binding digest with the scan.
3. Require the initial lookup epoch, successful scan epoch, and before/after
   verification epochs to match and have a reliable content watch.
4. Perform file reads, decoding, hashing and epoch probes outside cache/state
   mutexes. Stage the bounded eligible IDs before a single final cache update.
5. Recheck root, cache epoch, original strict binding and available capacity
   under the cache lock. Insert only the original ID into existing `hits`.

The implementation does not create `known` ownership, upgrade a compatibility
record to strict, cache absence or errors, evict refusal evidence, grow the
prediction budget, or extend hint lifetimes. Optional peer-verification failure
skips that peer without rejecting an unrelated healthy leader. A
corrupt complete scan or a failed original leader check publishes no auxiliary
hits. Staging before insertion prevents a later peer-read panic from leaving
partially published peer hits.

The existing wait boundary remains relevant: a late identity outside the frozen
cohort, or a busy gate with no active cohort, retains its original independent
scan path. R6a does not change that branch into an
unconditional wait and does not increase the four-worker limit.

### Release MCP comparison: R5b versus R6a

Both planned ABBA blocks completed successfully with the qualified R6a release
and retained R5b release. Each block used the same eight-wave, 48-warm-call,
6,000-record plan as the historical cohort comparison. All eight controllers
are included. These are newly measured R5b controls; the earlier R4e/R5b
observations are not pooled into this comparison.

The collector verified both original report hashes, the pinned helpers and
original inputs, all original event and resource journals, complete event and
phase inventories, and unchanged source and executable identities. Each block's
summary was reproduced from its raw journals before pooling. The resource error
logs were also checked by hash and complete row count. No new keys, real SSH
executions or remote effects occurred.

The two blocks contain **10,368 successful reuse calls and 14,437 successful
pings: 24,805 successful measured RPCs, zero failed or missing calls**. The
pooled rates and CPU costs use summed counts and times; p99 is recomputed from
all original attempts. Each pooled cold cell contains 192 calls per arm and
each warm cell 1,536. Cold-C8 still means a configured limit of eight with only
six original callers available in a cold wave.

| Workload / limit | R5b calls/s | R6a calls/s | Throughput change | R5b CPU ms/call | R6a CPU ms/call | R5b p99 ms | R6a p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Cold C1 | 6.183555 | 13.608958 | +120.083% | 125.416667 | 38.125000 | 209.445982 | 192.860005 |
| Cold C4 | 18.940308 | 28.452778 | +50.223% | 40.781250 | 23.489583 | 247.696535 | 207.701833 |
| Cold C8 | 19.181791 | 30.297554 | +57.950% | 63.958333 | 22.500000 | 360.910520 | 218.152630 |
| Warm C1 | 23.431665 | 23.755376 | +1.382% | 7.526042 | 7.148438 | 50.651532 | 52.902329 |
| Warm C4 | 61.872649 | 59.879667 | −3.221% | 5.820313 | 5.852865 | 94.779622 | 103.716390 |
| Warm C8 | 63.035586 | 63.652702 | +0.979% | 6.230469 | 6.204427 | 212.442872 | 200.081355 |

The pooled cold-C8 gain includes **64.821% less controller CPU per successful
call** and **39.555% lower p99**. Both individual blocks improved cold-C8
throughput, CPU cost and p99. Cold-C1 and cold-C4 throughput also improved in
both blocks. The per-block directions are retained below; pooling does not
replace the individual observations.

| Workload / limit | Block 1 throughput change | Block 2 throughput change | Block 1 p99 change | Block 2 p99 change |
| --- | ---: | ---: | ---: | ---: |
| Cold C1 | +116.976% | +123.292% | −8.990% | −0.000267% |
| Cold C4 | +48.804% | +51.680% | −18.832% | +0.887% |
| Cold C8 | +57.144% | +58.744% | −33.209% | −41.608% |
| Warm C1 | +0.842% | +1.930% | +3.957% | +3.795% |
| Warm C4 | −1.380% | −5.026% | +1.594% | +14.155% |
| Warm C8 | +1.813% | +0.148% | −1.118% | −13.636% |

**Warm-C4 is a repeat-direction regression:** throughput fell 1.380% and 5.026%
in the two blocks, while p99 rose 1.594% and 14.155%. Pooled throughput fell
3.221%, p99 rose 9.429%, and CPU per call rose 0.559%. Warm-C1 p99 also rose
4.444% pooled despite slightly higher throughput. Cold-C4's pooled p99 fell,
but its second block increased 0.887%; cold-C1's second-block p99 was essentially
unchanged. These results do not justify a claim that every tail improved. As
before, each block's 96-call cold p99 is its maximum, and the pooled 192-call
cold p99 is its second-largest observation.

The collector retained **1,197 resource-sampling errors** across the eight
controller runs. Phase-contained controller RSS observations were near flat:
the cold-C8 maxima were 17,824 KiB for R5b and 17,840 KiB for R6a, and warm-C8
maxima were 18,040 and 17,844 KiB. These are non-atomic, approximately 100 ms
samples wholly inside the selected phases; boundary samples are excluded, and
missing fields remain unknown. They do not establish an overall RSS reduction
or the absence of brief resource peaks.

This release comparison isolates R5b versus R6a for original-key reuse, audit
and locally denied status. It does not measure new-key launch throughput,
normal remote status, network bandwidth or production tail guarantees. A claim
about total improvement over R4e still requires a direct R4e/R6a comparison;
percentages from the historical and current experiments must not be multiplied.

### Completed R6a validation and historical revalidation limit

Focused regressions, full frozen-source qualification, one candidate probe and
both planned release ABBA blocks completed. R6a's original eight-stage native
validation also completed with its own qualified artifact. The later complete
historical-chain revalidation is blocked by a missing retained A62 test
executable, and further aggregate extraction stopped. Its original successful
report remains retained; this report adds no independently revalidated native
counts or soak figures. Accepted R6a supplies the baseline for the separate
R7b candidate. Final candidate selection, branch publication and exact-head /
prospective-merge CI acceptance are tracked against PR #77's current head.

## R6b isolated follow-up qualification

The separate R6b candidate targets the interval between claiming the cold-scan
gate and installing the frozen cohort. It claims the gate with a nonblocking
attempt while holding the cohort-state mutex, then freezes membership in the
same critical section. The state mutex is released before any blocking gate
wait. Guard declaration and drop order also preserve cleanup after a panic;
the leader's cleanup cannot attempt to reacquire a state mutex that its own
unwinding frame still holds. These are implementation and correctness
boundaries, not a measured performance result.

R6b completed a fresh full qualification using its own post-format source map
and retained artifacts. R6a test output is not counted as R6b qualification.

| Item | R6b result |
| --- | --- |
| Rust cases across five test executables | 1,560 passed; zero failed; 28 explicitly ignored; 1,588 selected |
| Qualification-harness Python tests | 57 passed |
| Compiler-input map | 199 files; its own tested post-format map |
| Qualification gates | All eight succeeded |
| Separately executed ignored diagnostic | One exact test passed once; zero failed, 1,530 filtered out; 192 validated calls |

Three additional regressions cover a real contender at gate establishment,
panic before and after cohort freeze with safe cleanup order, and a newly
visible second hint releasing the prospective leader before final checks. The
isolated diagnostic is separate from the 1,560 qualification passes. Both
planned release ABBA blocks completed. The results below remain evidence for
R6b's own source; they did not lead to adoption.

### R6b lookup-only diagnostic

The single exact diagnostic used the same qualified lookup-only fixture as
R6a: 32 six-call waves, 192 validated calls, 6,000 historical records and four
lookup workers. Both submission patterns performed exactly **one complete scan
in each of their eight cold waves**, for eight scans per pattern. All warm waves
performed zero complete scans, the four-worker limit held, and the original
identities and final cleanup were validated.

Compared with R6a's earlier single diagnostic, the cold scan total fell from
11 to eight in both patterns. The worker CPU reduction did not translate into
uniformly lower elapsed time:

| Cold pattern / metric | R6a diagnostic | R6b diagnostic | Change |
| --- | ---: | ---: | ---: |
| Natural: complete scans | 11 | 8 | −27.273% |
| Natural: summed worker CPU | 1,302.490143 ms | 1,046.722898 ms | −19.637% |
| Natural: total wave wall time | 947.722356 ms | 1,044.175246 ms | **+10.177%** |
| Natural: maximum lookup latency | 152.828706 ms | 153.278747 ms | **+0.294%** |
| Staged: complete scans | 11 | 8 | −27.273% |
| Staged: summed worker CPU | 1,542.225017 ms | 1,078.344627 ms | −30.079% |
| Staged: total wave wall time | 1,060.313450 ms | 1,077.503833 ms | **+1.621%** |
| Staged: maximum lookup latency | 183.548974 ms | 153.232969 ms | −16.517% |

These are one diagnostic execution per source in retained libtest executables,
not a release ABBA comparison. One complete scan meets the scan-count lower
bound for this covered, cold, same-epoch fixture under the existing requirement
to validate the complete history. It does not establish minimum latency,
general optimality or uniformly better release behavior.

### Release MCP comparison: R6a versus R6b

Two complete ABBA blocks used newly measured R6a controls and the qualified
R6b release. The unchanged plan used eight waves, 48 warm calls per wave and
6,000 synthetic historical records. All eight controllers are included, with
**10,368 successful reuse calls and 13,360 successful pings: 23,728 successful
measured RPCs, zero failed or missing calls**. These are original-key reuse,
audit and locally denied-status measurements, with six actual callers in each
cold-C8 wave. They do not measure new launches or normal remote status.

The pooled rates and CPU costs use summed original counts and times. Quantiles
are computed from all original attempts. Each pooled cold cell has 192 calls
per arm; each warm cell has 1,536. The new R6a controls are not pooled with
earlier R5b/R6a measurements.

| Workload / limit | R6a calls/s | R6b calls/s | Throughput change | R6a CPU ms/call | R6b CPU ms/call | R6a p99 ms | R6b p99 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Cold C1 | 13.371080 | 13.582284 | +1.580% | 38.958333 | 37.760417 | 196.956986 | 193.139725 |
| Cold C4 | 27.507083 | 28.534771 | +3.736% | 23.906250 | 23.072917 | 210.857732 | 243.496502 |
| Cold C8 | 29.861102 | 30.194267 | +1.116% | 22.760417 | 22.604167 | 230.474215 | 233.977492 |
| Warm C1 | 23.390432 | 23.229673 | −0.687% | 7.558594 | 7.656250 | 51.310780 | 50.941072 |
| Warm C4 | 61.835027 | 60.724718 | −1.796% | 5.885417 | 5.852865 | 90.290118 | 98.971835 |
| Warm C8 | 63.019679 | 63.917045 | +1.424% | 6.276042 | 6.263021 | 198.533383 | 191.061633 |

| Workload / limit | Block 1 throughput change | Block 2 throughput change | Block 1 p99 change | Block 2 p99 change |
| --- | ---: | ---: | ---: | ---: |
| Cold C1 | +1.450% | +1.709% | −5.092% | +2.198% |
| Cold C4 | +3.657% | +3.816% | +17.706% | −7.895% |
| Cold C8 | +1.970% | +0.255% | −6.349% | +7.927% |
| Warm C1 | −1.824% | +0.476% | +0.417% | −2.080% |
| Warm C4 | +0.024% | −3.550% | −3.471% | +16.803% |
| Warm C8 | +0.292% | +2.567% | +2.685% | −14.082% |

Pooled cold-C4 p99 rose **15.479%** despite 3.736% higher throughput and 3.486%
less controller CPU per call. Warm-C4 throughput fell **1.796%**, p95 rose
**8.338%** and p99 rose **9.615%**. Cold-C8 p99 also rose 1.520%. The individual
blocks show mixed tail directions; these data do not establish a stable causal
regression in every run. They also do not resolve the unfavorable pooled tails.
As before, each block's 96-call cold p99 is its maximum and the pooled
192-call p99 is its second-largest observation.

There were **1,263 resource-sampling errors**. Phase-contained controller RSS
peaks were 17,720 versus 17,568 KiB for cold C8, and 17,924 versus 17,696 KiB for
warm C8. These sparse, non-atomic observations do not establish a general
memory reduction. Five of the six pooled ping-p99 ratios increased; cold C4
was the exception. Successful RPC counts do not remove sampling or load
uncertainty.

### R6b adoption decision

R6b was **rejected for adoption before native validation** under its original
predeclared performance gate. The qualification, successful diagnostic and both
complete release blocks are retained. The unexplained pooled cold-C4 and
warm-C4 tail increases were not accepted in exchange for the modest throughput
gains; no favorable subset or extra replacement block was selected.

The planned R6b native suite is **unexecuted**, not failed. The prepared R7a
resource combination based on R6b was also not executed and was superseded by
a separately planned R7b resource candidate based on accepted R6a. That new
candidate subsequently completed its own qualification, release blocks and RSS
experiment, followed by its own complete native suite. R7b was accepted under
its distinct predeclared resource tradeoff, as recorded below. This does not erase
the earlier R5b/R6a warm-C4 regression, and
percentages across these separately measured version pairs must not be
multiplied into a cumulative improvement claim.

## R7b resource changes on accepted R6a

R7b is a separate resource-focused candidate. It starts from the qualified
198-input R6a source, adds two test files, and changes only the corresponding
fence and inventory implementation files. The prepared source contains 200
compiler inputs before and after formatting. Its completed qualification binds
the actual post-format source map and retained executables; the preformat
overlay is not a substitute for those tested identities. R6b's atomic cohort claim and its
three added tests are excluded.

The candidate's primary purpose is to bound retained work and private-payload
memory. Its completed release and RSS measurements are recorded below,
including both the large fixed-fixture peak reduction and the cold-C8 latency
cost. Its own native suite and evidence/custody verification completed, and
R7b was accepted under the explicit resource-versus-latency decision below.

### Completed source-bound qualification

R7b completed all eight original gates once: format, format check, Python
qualification-harness tests, all-target/all-feature Clippy with warnings denied,
test build, isolated Rust cases, independent exact-case audit and release build.
Every original stage returned zero, with no automatic test retry. The final
compiler-input map equals both `source_tested` and `source_after`.

| Item | R7b result |
| --- | --- |
| Isolated Rust cases | 1,573 passed; zero failed; 28 explicitly ignored; 1,601 selected |
| Retained test executables | Five, including the original zero-case executable |
| Qualification-harness Python tests | 57 passed |
| Original qualification gates | All eight succeeded once |
| Tested compiler-input map | 200 files; tested and post-qualification maps match |
| New resource regressions | All five fence and eleven inventory cases passed in the complete audit |
| Specified existing contracts | All 15 selected ownership/cohort contracts passed in the same complete audit |
| Supplemental measurement-harness Python tests | Separately, 16 RSS and 19 paired-native cases passed |

A read-only derivation checked the original audit, test rows, command records
and compressed stdout/stderr proofs for all 31 specified cases, including exact
test names, one original attempt and the full executable inventory. It also
checked all three retained release artifacts, all five retained test
executables and the final source/evidence bindings. It reran no Rust tests.
The 16 new cases and 15 specified existing cases are included in the 1,573
passes, not additional passes to add to that total.

The qualified overlay below differs from accepted R6a in exactly these four
compiler inputs. Formatting changed the two new test files; subsequent
publication and measurement must use these tested bytes, not their preformat
candidate versions.

| Qualified file | Bytes | SHA-256 |
| --- | ---: | --- |
| `effect_owner_fence.rs` | 24,310 | `47863d0bcb2b704857c39a275bbefbe2bbb2a4b3805837e7e0f653e6f8855e56` |
| `effect_owner_fence_acquisition_tests.rs` | 11,926 | `ec6c5f5ecd6f52d594635333dd76d38807059e79c8deddabd8648eb959193142` |
| `jobs.rs` | 170,233 | `628ebfa3a35f89c17c87360e2d87c9760bb1942a147db622c7a41c543258b384` |
| `jobs_inventory_streaming_tests.rs` | 13,502 | `36e08ae9f5d3c1a1ba7f7157a54a1f87d791f9a4a86d906b5d0010f7459176f1` |

### Retain fence acquisition capacity in the actual worker

When owner fencing is configured, a shared admission lock may wait behind an
administrative exclusive owner transition. Submitting every acquisition to
the blocking pool first can retain arbitrarily many real acquisition closures
when callers are cancelled but those closures are still waiting or running.

R7b acquires one of four asynchronous capacity permits before submitting the
blocking acquisition. The permit moves into that closure, so cancelling the
outer future cannot release capacity still owned by real work. Success, error
or unwind releases the acquisition permit only after the original acquisition
and validation have ended. A caller cancelled while awaiting capacity submits
no blocking acquisition from that wait.

The returned `AdmissionPermit` separately owns the shared filesystem lock for
the complete effect lifetime. Releasing acquisition capacity does not release
that effect's ownership guard. The original owner, root, inode, mode, epoch,
predecessor and replay checks remain in the acquisition path, and the unfenced
early return remains unchanged.

This is a bound of **four queued or running acquisition closures per
controller**. It is not a bound on all async waiting callers, the lifetime
count of admitted effects, a cross-controller capacity limit or an ownership
transfer protocol. The registry reuse benchmark does not enable owner fencing
and cannot establish fence throughput gains.

Five new regressions exercise a real exclusive fence with cancelled waiters,
cancellation while real workers remain in the blocking queue, cancellation or
closed capacity before submission, capacity release on success/error/panic,
and a returned shared fence that outlives acquisition capacity. All five passed
inside R7b's complete isolated qualification audit. They establish the tested
resource-ownership behavior, not a measured native throughput gain.

### Retain public inventory rows after complete record validation

The old unpaginated inventory first retained every complete `JobRecord`, then
sorted, filtered and serialized public fields. Large private arguments and
other private strings therefore remained live across the entire scan even
though they never appeared in the public result.

R7b still uses the complete compatibility reader and full `JobRecord` decoder
for every JSON receipt. It reuses the bounded read buffer, validates the full
record before applying the host filter, and retains only the five public fields
for selected rows: ID, host, creation time, execution mode and launch state.
Private fields from the current record are released before reading the next.
The compatibility read limit remains 4 MiB; this path does not impose the
separate strict-cache 1 MiB receipt limit.

All sources must pass before public-row JSON conversion and final wire-budget
validation. An unsafe or corrupt unselected neighbor still refuses the whole
inventory, including when an earlier selected row would be too large to
serialize. Stable timestamp sorting preserves encounter order for ties. Wide
timestamps in unselected records remain inert, while selected-record failures
retain their original ordering after source validation.

The successful response remains byte-compatible with the old unpaginated
result, including all five fields, total and completeness/authority flags.
The enclosing SDK result still has its 1 MiB response budget; an over-budget
result is refused in full, with no silently truncated inventory. This does
not make the whole request constant-space: retained public rows and final
serialization still grow with the selected inventory. It specifically removes
retention of all records' private payloads, while keeping one decoded record
and the bounded reusable read buffer during the scan.

Eleven new regressions compare the former production reader/formatter with
the projection, including exact wire output, filters, timestamp ties, large
private fields, invalid discarded fields, refusal precedence, compatibility
limits, staging files, the exact wire boundary, over-budget neighbors and
nonregular/hardlinked/non-UTF-8 receipts. All eleven passed in the new
candidate's full audit, together with the five fence regressions and every
other executed original case.

### Predeclared resource and performance acceptance

The workload and acceptance criteria were frozen before R7b qualification or
measurement. The fixed sequence is its own eight-gate qualification, two
complete direct R6a/R7b release ABBA blocks, one eight-process inventory RSS
series, and its own eight-stage native suite. No extra diagnostic probe,
favorable replacement block or selective retry is planned.

| Gate | Required evidence | Current status |
| --- | --- | --- |
| Full qualification | Original eight gates, independent complete audit, all 16 new exact regressions, tested source unchanged afterward and retained artifact hashes | Complete: 1,573 passed, zero failed, 28 ignored; 200 tested inputs |
| Direct release comparison | Two complete ABBA blocks over every cold/warm C1/C4/C8 cell, original raw events, failures, ping and resource-observation errors retained | Complete: 23,781 successful RPCs; adverse cold-C8 outcomes retained in the explicit adoption decision |
| Inventory resource comparison | Two ABBA blocks, eight fresh processes, one complete all-host list per process, fixed 2,048-record fixture with 65,536 private argument bytes per record | Complete: all eight attempts; median peak −81.628% and strictly separated arm peaks pass both fixed RSS gates |
| Native collaboration/recovery | Independently qualified R6a/R7b artifacts, exactly eight complete once-only stages and retained process custody through reap | Complete: all eight stages; original forwarding/lease children reaped; full source/evidence derivation succeeded |

The fixed RSS harness's 16 Python regressions and the paired-native harness's
19 Python regressions passed separately on X230. They validate those measurement
and evidence-handling programs, using local synthetic fixtures. The 35
supplemental Python cases are separate from the original 57-case qualification
harness gate, the 16 new Rust resource regressions and actual release/RSS/native
experiments. Passing them does not supply those experiments' outcomes.

The RSS fixture contains 128 MiB of synthetic private argument payloads per
state. All eight attempts must be clean, complete and bound to their own
qualification, audit, source map and retained release artifact. Each response
must contain the exact 2,048 ordered public rows and remain within the enclosing
SDK wire budget. Original protocol streams and process receipts are retained
privately.

The primary RSS gate requires **at least a 50% reduction in pooled median
peak RSS**, and **every candidate peak must be below every baseline peak**:
`max(B) < min(A)` over all four measurements per arm. These thresholds were
fixed before measurement; actual outcomes are recorded below. The measurement
uses Linux `wait4.ru_maxrss` from uniquely reaped fresh controller processes,
covering their complete lifetime and one list request. It does not include the external fixture
producer. Report all eight peaks and per-block/pooled mean, median, minimum and
maximum; four samples per arm do not justify a meaningful p99 claim or a
steady-state memory guarantee.

Release rates use summed counts and times, and quantiles use pooled original
latencies rather than averaged block percentiles. Material throughput or tail
regressions with the same adverse direction in both blocks require explanation
or rejection. Mixed directions remain uncertainty, with adverse pooled values
published. The resource-purpose gate does not require every p99 to improve.
An explicit resource-versus-latency tradeoff can be considered only after the
strict RSS gate and all correctness/native requirements pass; its measured
benefit, bounded costs and adverse results must remain visible. No threshold
may be changed after seeing data, and this plan does not retroactively accept
R6b under a different gate.

### Release MCP comparison: R6a versus R7b

Both predeclared direct R6a/R7b release ABBA blocks completed once. All eight
controllers and original journal events are included: **10,368 successful reuse
calls plus 13,413 successful pings, totaling 23,781 successful RPCs**, with zero
failed or missing calls. There were **1,111 resource-observation errors**; those
remain part of the result and are not converted into zero resource use.

The workload retains 6,000 synthetic historical receipts, cold/warm C1/C4/C8
cells, eight waves per cell and original-key reuse. The cold-C8 label still has
six actual original callers per wave. It covers the local reuse/audit/status
path with SSH deliberately denied; it does not measure new-key launches,
normal remote status, owner-fence contention or general network throughput.

Rates below divide total successful calls by summed measured phase time.
Controller CPU divides summed controller CPU by successful calls. Percentiles
are nearest-rank values recomputed from all original attempts, with no averaging
of block percentiles or selection of favorable controllers.

| Workload | R6a calls/s | R7b calls/s | Rate change | R6a CPU ms/call | R7b CPU ms/call | R6a p99 ms | R7b p99 ms | p99 change |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Cold C1 | 13.271 | 13.304 | +0.249% | 39.531 | 39.115 | 195.813 | 195.544 | −0.137% |
| Cold C4 | 28.375 | 28.209 | −0.584% | 23.125 | 23.125 | 202.887 | 203.348 | +0.227% |
| Cold C8 | 30.376 | 29.826 | −1.811% | 22.552 | 23.021 | 223.551 | 250.628 | +12.112% |
| Warm C1 | 23.313 | 23.156 | −0.675% | 7.643 | 7.695 | 50.749 | 50.959 | +0.414% |
| Warm C4 | 60.826 | 62.050 | +2.012% | 5.872 | 5.879 | 107.476 | 90.588 | −15.713% |
| Warm C8 | 62.493 | 61.723 | −1.232% | 6.309 | 6.243 | 219.657 | 216.975 | −1.221% |

All cold cells have 192 calls per arm pooled and 96 per arm in each block;
therefore their pooled p99 is the second-largest observation and their block
p99 is the maximum. Warm cells have 1,536 calls per arm pooled. These finite
samples do not establish population tail bounds. The complete individual-block
directions are retained below.

| Workload | Block 1 rate change | Block 2 rate change | Block 1 p99 change | Block 2 p99 change |
| --- | ---: | ---: | ---: | ---: |
| Cold C1 | +0.634% | −0.137% | +6.076% | −2.675% |
| Cold C4 | +0.551% | −1.692% | −0.743% | −7.394% |
| Cold C8 | −1.971% | −1.653% | +15.935% | +3.516% |
| Warm C1 | −0.612% | −0.737% | −2.392% | +2.610% |
| Warm C4 | +1.302% | +2.726% | −8.529% | −31.543% |
| Warm C8 | −2.330% | −0.132% | +8.731% | −2.597% |

**Cold C8 regressed in both blocks.** Pooled throughput fell **1.811%** and p99
rose **12.112%**, from **223.551 to 250.628 ms**. The individual blocks lost
1.971% and 1.653% throughput and increased p99 by 15.935% and 3.516%. Pooled CPU
per successful call also increased **2.079%**, and p95 increased **5.003%**.
These consistent adverse directions are not described as a uniform speedup or
dismissed as mixed-block uncertainty. Their cause is not established by this
experiment.

Warm C4 increased pooled throughput by 2.012% and reduced reuse p99 by 15.713%,
with the same improvement directions in both blocks. Its separate **ping p99
increased 21.392%, from 8.350 to 10.137 ms**; the ping directions were mixed
between blocks. That cost is retained alongside the reuse improvement. Other
mixed directions remain uncertainty. Cold C4's pooled p99 rose 0.227% even
though each block's p99 fell; these are different order statistics over
96-call and 192-call samples, not percentiles to average.

The 100 ms resource observations are non-atomic and incomplete. They do not
establish a general memory reduction or an exhaustive resource bound. The
separate inventory experiment below measures a different workload and a
whole-child peak with `wait4`; neither experiment supplies a causal explanation
for the other's changes. Results from R4e/R5b, R5b/R6a, rejected R6a/R6b and
R6a/R7b must not be multiplied into a cumulative gain.

### Inventory RSS experiment: observed results

The single predeclared series completed **all eight original fresh processes**
in two ABBA blocks, with no automatic retry or replacement attempt. Each
process handled one complete all-host list over 2,048 records containing
65,536 bytes of private argument payload per record: 128 MiB of synthetic
private payloads in each fixture. Both qualified arms, their source maps,
audits, retained executables, harness and fixture inventories remained bound
and unchanged before and after the run. Every original child exited zero and
was uniquely reaped; no shutdown signal or capture error was reported.

Every response had the same 2,048 ordered public rows and **311,437 bytes** in
the compact JSON re-encoding of the actual SDK result, below the enclosing
1 MiB budget. This byte count is not the original RPC frame length; original
protocol streams were retained separately. All eight SDK results share
SHA-256 `fc6132e24eff958a5c6e1d1df2d75f5f8b229dd7491fa260dce17f8ef67bdbf7`.

The complete original observations are:

| Block | Position | Arm | Peak RSS KiB | Whole-child CPU ms | List round-trip ms |
| --- | ---: | --- | ---: | ---: | ---: |
| 1 | 1 | R6a | 149,408 | 260.804 | 214.469 |
| 1 | 2 | R7b | 27,432 | 139.065 | 119.753 |
| 1 | 3 | R7b | 27,432 | 168.012 | 130.691 |
| 1 | 4 | R6a | 149,384 | 221.205 | 193.951 |
| 2 | 1 | R6a | 149,244 | 245.673 | 210.999 |
| 2 | 2 | R7b | 27,432 | 138.093 | 116.908 |
| 2 | 3 | R7b | 27,432 | 147.488 | 124.868 |
| 2 | 4 | R6a | 149,132 | 247.063 | 212.526 |

All four candidate peak values were **27,432 KiB**. They are reported as
observed; identical peaks do not establish constant allocation, a precise
allocation floor or why the four values match. The predeclared summary
statistics retain both blocks and all four samples per arm:

| Window | Metric | R6a mean | R6a median | R6a min–max | R7b mean | R7b median | R7b min–max | Median change |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Block 1 | Peak RSS KiB | 149,396 | 149,396 | 149,384–149,408 | 27,432 | 27,432 | 27,432–27,432 | −81.638% |
| Block 1 | Whole-child CPU ms | 241.0045 | 241.0045 | 221.2050–260.8040 | 153.5385 | 153.5385 | 139.0650–168.0120 | −36.292% |
| Block 1 | List round-trip ms | 204.210 | 204.210 | 193.951–214.469 | 125.222 | 125.222 | 119.753–130.691 | −38.680% |
| Block 2 | Peak RSS KiB | 149,188 | 149,188 | 149,132–149,244 | 27,432 | 27,432 | 27,432–27,432 | −81.612% |
| Block 2 | Whole-child CPU ms | 246.3680 | 246.3680 | 245.6730–247.0630 | 142.7905 | 142.7905 | 138.0930–147.4880 | −42.042% |
| Block 2 | List round-trip ms | 211.762 | 211.762 | 210.999–212.526 | 120.888 | 120.888 | 116.908–124.868 | −42.914% |
| Pooled | Peak RSS KiB | 149,292 | 149,314 | 149,132–149,408 | 27,432 | 27,432 | 27,432–27,432 | −81.628% |
| Pooled | Whole-child CPU ms | 243.6862 | 246.3680 | 221.2050–260.8040 | 148.1645 | 143.2765 | 138.0930–168.0120 | −41.845% |
| Pooled | List round-trip ms | 207.986 | 211.762 | 193.951–214.469 | 123.055 | 122.310 | 116.908–130.691 | −42.242% |

**Both predeclared RSS gates passed.** The pooled median peak fell from
**149,314 to 27,432 KiB**, a reduction of **81.628%**, exceeding the frozen 50%
threshold. The largest candidate peak, 27,432 KiB, was strictly below the
smallest control peak, 149,132 KiB. The pooled median whole-child CPU fell
41.845%, and the median list round trip fell 42.242%, for this fixed inventory
fixture. These additional timing observations are not substituted for the
predeclared RSS conditions.

The peak is Linux `wait4.ru_maxrss` for the **original child's whole lifetime**,
including startup and shutdown; it may include a high-water mark established
before `exec`. It is not steady Rust RSS, the complete service's RAM use or a
constant-space guarantee. The fixture-producing process is outside that
resource metric. CPU is `wait4` user plus system time over the same child
lifetime. List latency covers request write through complete response receipt
and JSON-RPC decoding; expected-result validation occurs afterward. It is not
an isolated timing of the inventory function.

With four processes per arm, the complete raw observations and mean/median/range
are more informative than a claimed p99. This experiment demonstrates a large
peak reduction for the deliberately large private-payload inventory, while the
selected public rows and final serialization can still grow. It does not
establish a general service-memory reduction or erase the release cold-C8 and
ping regressions. The separate complete native outcome and explicit
resource-versus-latency adoption decision are recorded below.

### Paired-native protocol and completed acceptance

The original native validator depends on a retained historical A62 test
executable that was verified earlier but was missing during a later independent
revalidation. Scoped read-only searches did not locate the original artifact;
they do not establish its absence everywhere or its disappearance's cause. The
unchanged historical validator's preflight remains blocked. No replacement
binary, removed check or rewritten historical report repairs that evidence.

R7b therefore has a **separately reviewed paired-qualified native protocol**:
accepted R6a is the explicit comparison arm and R7b supplies its own completed
qualification. Both arms require their original full report, audit, tested map,
all retained test and release executables, and original logs. Complete compiler
maps and all pinned artifacts are checked before and after every stage and at
final completion. A missing retained test executable in either arm still
refuses this new protocol.

The eight native stages, original helper assertions, workload sizes, load
observations, original-child/PID-descriptor custody, once-only execution and
forwarding lease remain unchanged. The original historical runner and protocol
library remain unchanged. The new report explicitly identifies
`paired-composed-qualification/v1`, R6a/R7b and both typed composed-source
bundles; it does not claim historical A62 revalidation. The old A62 collector is
not an interchangeable reader for that new comparison.

The paired protocol's 19 regressions passed before the actual
qualification/map/audit/release identities, concrete command and regression
evidence were bound in its final frozen launch manifest. The new run then
completed all eight stages once; both original forwarding children completed
and were reaped. The separate read-only derivation verified all stage originals
and both complete source/artifact bindings. Its actual outcomes are reported
in the R7b native section below.
The historical R6a/A62 result retains its original scope and current
revalidation limit; it is not relabeled as this new experiment or as a failed
native run.

### Adoption decision and stopping boundary

**R7b is accepted as the final source for this cycle.** Its complete
qualification, all 16 new regressions, both fixed release ABBA blocks, all eight
RSS processes, both predeclared RSS conditions and its own eight-stage native
suite passed. Original process custody and source/artifact integrity were
reconciled before this decision.

This is an explicit resource-versus-latency tradeoff under the plan fixed before
measurement. Four actual owner-fence acquisition workers retain their capacity
across outer cancellation. In the fixed private-payload inventory, median peak
RSS fell **81.628%** and median list round trip fell **42.242%**. Those resource
and inventory benefits justify accepting the measured release **cold-C8 p99
increase of 27.077 ms (12.112%)** and **1.811% throughput loss**, with adverse
directions in both blocks. The warm-C4 ping increase, other adverse cells and
the native guard/file costs remain published. Causation and formal statistical
significance are not established; acceptance does not mean uniformly faster
execution or a bound on future production latency.

No threshold was changed after measurement and no unfavorable trial was
replaced. R6b remains rejected under its own original gate; its atomic-claim
changes and tests are excluded. Prepared R7a remains unexecuted. The identified
ownership-capacity and inventory-retention issues have completed their fixed
validation cycle, so this round stops here. Further allocator, descriptor,
status-worker, audit batching, cross-host capacity or launch-lock proposals
need distinct workloads and correctness analysis. This decision does not claim
that further optimization is impossible.

Final source identity and exact-head/prospective-merge GitHub acceptance are
recorded on PR #77. This report does not claim that its own publication commit
already passed CI.

## R5b native collaboration and recovery validation

All eight native stages completed once using the qualified R5b runtime.
Successful recovery retained the original six jobs, request identities and
once-only markers across a controller `SIGKILL`. The original jobs were then
released normally. This is a six-host fixture result, not a production failover
or ownership-transfer claim.

| Native stage | Observed coverage |
| --- | --- |
| Small-archive ABBA | 4,096 measured calls; historical A62 comparison arm |
| Inherited-pipe canary | Original-child/output custody, including one real X230 cancellation while draining inherited pipes |
| Six-running-job recovery | Six hosts retain their original identities and once markers across controller `SIGKILL` and restart |
| Four file-ABBA stages | 288 calls per stage, 1,152 total; six immutable synthetic outputs of 44–48 bytes |
| C8 file soak | Configured 120 seconds; 27 cells, 2,592 calls, 122.251 measured seconds |

The soak's sampled controller RSS peak was 18,572 KiB; the sampled local process
tree peak was 129,064 KiB. There were 20 resource-observation errors. The largest
reported cell p99 was 944.696 ms; it is a per-cell statistic, not a pooled p99.
Remote-host CPU is outside the local process-tree resource scope. Tiny immutable
file reads do not establish bulk-transfer bandwidth.

These checks exercise controller-process failure and recovery of existing
identities. They do not simulate power loss, host reboot, WAN partition or
production ownership transfer. R5b's native result cannot qualify a later R6
production change; that candidate must run its own validation.

## R6a native collaboration and recovery validation

R6a independently completed all eight native stages once using its own
qualified runtime. The original forwarding wrapper completed successfully and
its original children were reaped. This is R6a evidence, separate from the
historical R5b run above.

The completed suite covers small-archive ABBA, inherited-pipe custody and
cancellation, recovery of original running jobs across controller `SIGKILL`,
four sequential file-ABBA stages, and a configured 120-second C8 file soak.
The native comparison arm is retained A62. It is distinct from the release
registry-cohort comparison between R5b and R6a.

This report does not claim newly independently revalidated native call counts,
measured soak duration, sampled RSS or resource-observation errors for R6a.
The later complete historical-chain revalidation is blocked, and aggregate
extraction has stopped. No numeric values from R5b's native run are assigned
to R6a. The first post-run collector
verified the candidate and baseline bindings and the small-archive stage, then
rejected the inherited-pipe validation because Python tuple pairs serialize as
JSON arrays. That derived-report failure is retained. The collector comparison
was corrected to compare every field in canonical JSON form; the original
native suite was not rerun.

The second extraction attempt stopped earlier because the historical A62
qualification's retained test executable could no longer be found. Its missing
artifact refusal is also retained; no source check was waived and no replacement
binary was treated as the original. The complete historical-chain revalidation
and unchanged validator remain blocked; no further extraction is running.
The original R6a native report remains the record of its completed successful
run. Its blocked later revalidation is not a native-test failure.

Successful native validation does not establish physical-power-loss, target
reboot, WAN-partition or production ownership-transfer behavior. Tiny immutable
file reads do not establish bulk bandwidth, sampled RSS is not an exhaustive
resource limit, and the configured soak is not a 600-second endurance test.

## R7b native collaboration and recovery validation

R7b completed its own **eight original native stages once**, using the
separately qualified R6a/R7b protocol. Every stage returned zero without a
timeout. The original forwarding wrapper and remote lease completed
successfully; both original children were reaped with custody retained through
reap, no wrapper shutdown signal and no automatic retry. This is the new
R6a/R7b experiment, not a repair or reuse of the blocked historical A62 chain.

The post-run read-only collector checked the complete native report, every
stage's original report and artifact inventory, both qualification bundles,
all retained test/release executables and current compiler maps. All eight
stages and **12,358 bound inputs** passed this derivation. The collector started
no workload or helper process. Its separate custody summary binds the actual
completed forwarding run; report extraction alone is not evidence of reap.

| Stage | Original measured outcome |
| --- | --- |
| 1. Small-archive ABBA | Four rounds of 1,024 measured calls: 4,096 successes, zero failed or unexecuted; 64 records per round; R6a/R7b/R7b/R6a order |
| 2. Inherited pipes | Seven of seven cases passed: two natural, two staggered, two timeout and one cancellation; seven original starts and one cancellation submitted once |
| 3. Six-running-job recovery | Six original host/job identities recovered; 42 native calls and 30 SSH checks succeeded; deliberate controller `SIGKILL` exit −9 and restarted controller exit zero |
| 4. File ABBA, R6a | 288 measured successes, zero failed, C1/C4/C8 |
| 5. File ABBA, R7b | 288 measured successes, zero failed, C1/C4/C8 |
| 6. File ABBA, R7b | 288 measured successes, zero failed, C1/C4/C8 |
| 7. File ABBA, R6a | 288 measured successes, zero failed, C1/C4/C8 |
| 8. R7b C8 soak | Configured 120 seconds; 27 cells and 2,592 measured successes, zero failed; 121.448468 measured cell seconds |

### Small-archive guard and pipe/recovery canaries

The small-archive guard is a hot C1 metadata workload. Its four original rounds
contained 4,096 measured calls, separate from seed, preflight, warmup and
postflight calls. Every original round and every measured call is included.

| Arm | Measured calls | Calls/s | Controller CPU ms/call | Whole-round waited CPU s | Largest whole-round RSS KiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| R6a | 2,048 | 127.605 | 6.787 | 14.942559 | 34,736 |
| R7b | 2,048 | 123.915 | 6.997 | 15.173265 | 29,820 |

In this single short guard, R7b throughput was **2.892% lower** and measured
controller CPU per call was **3.094% higher**. Its lower largest round RSS does
not establish a general memory improvement. The tool-level observations retain
the archive/history latency increases:

| Tool | Calls per arm | R6a mean ms | R6a p95 ms | R6a p99 ms | R6a max ms | R7b mean ms | R7b p95 ms | R7b p99 ms | R7b max ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `request_archive` | 682 | 10.290 | 11.888 | 13.006 | 16.777 | 10.605 | 11.956 | 13.546 | 18.455 |
| `request_history` | 682 | 4.358 | 4.993 | 5.533 | 6.454 | 4.515 | 5.112 | 5.686 | 7.486 |
| `usage_stats` | 684 | 5.444 | 6.308 | 7.468 | 9.048 | 5.630 | 6.439 | 7.437 | 9.257 |

Controller CPU comes from the original measured process snapshots; waited CPU
and RSS cover complete rounds, including work outside the measured loop. The
four whole-round RSS peaks in ABBA order were **22,048 / 25,128 / 29,820 /
34,736 KiB**. Those peaks are not the inventory experiment's eight-process
metric or a steady service-memory bound. No reader, shutdown or unmatched
response error was reported in these four rounds.

The inherited-pipe canary retained 58 completed ledger entries: 47 native,
one notification, seven SSH inspections, two SSH preparations and one unreaped
probe. The notification is not an extra RPC. All seven cases passed with no
reader, unmatched-response or recorded ledger error. That ledger uses wall-clock
timestamps rather than monotonic performance cells, so it supplies no latency
comparison here.

Recovery retained the original six jobs and their identities across the
intentional controller kill. Six same-key lookups reused them; no replacement
jobs are inferred from the twelve `process_start` API calls. All 42 native
calls and 30 SSH checks succeeded, with zero RPC/SSH failure, reader error,
unmatched response or final controller-record error. No production service
mutation or remote cleanup operation was performed. The mixed recovery timings
below are descriptive canary observations, not a throughput experiment:

| Native recovery operation | Calls | Mean ms | p50 ms | p95 ms | p99 ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `process_read` | 12 | 267.380 | 271.517 | 357.435 | 357.435 | 357.435 |
| `process_start` | 12 | 590.094 | 593.082 | 758.153 | 758.153 | 758.153 |
| `process_status` | 18 | 691.694 | 840.501 | 982.401 | 982.401 | 982.401 |

These small per-tool samples make the displayed p95/p99 equal to the observed
maximum. They do not establish population tail latency or physical-machine
recovery behavior.

### One descriptive native file ABBA block

All four rounds retained six immutable synthetic outputs of **44, 44, 45, 45,
46 and 48 bytes**. Each round had 288 measured calls plus 12 warmup and 12
expected-rejection calls, kept separate from the successful measured count.
The measured total is **1,152 calls**. All original calls are included in these
six arm/concurrency rows; rates use summed cell durations and quantiles use
original call latencies, not averaged cell percentiles.

| Arm | Concurrency | Calls | Calls/s | Recorded controller CPU ms/call | Mean ms | p50 ms | p95 ms | p99 ms | Max ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| R6a | 1 | 192 | 4.040 | 132.031 | 247.249 | 244.895 | 304.139 | 345.987 | 418.868 |
| R6a | 4 | 192 | 15.347 | 76.250 | 255.204 | 253.522 | 321.878 | 390.827 | 394.763 |
| R6a | 8 | 192 | 21.951 | 72.708 | 353.174 | 355.884 | 431.104 | 500.955 | 507.315 |
| R7b | 1 | 192 | 4.040 | 132.083 | 247.205 | 242.793 | 304.859 | 313.532 | 369.342 |
| R7b | 4 | 192 | 15.461 | 75.365 | 254.177 | 250.696 | 329.736 | 421.173 | 424.916 |
| R7b | 8 | 192 | 21.638 | 74.010 | 358.238 | 353.965 | 454.103 | 492.629 | 512.310 |

This **one short ABBA block** is descriptive validation, distinct from the two
registry release blocks and the inventory RSS experiment. The C1 and C4 rates
changed +0.016% and +0.746%, while **C8 rate fell 1.428%**. **C4 p99 increased
7.765%**, p95 increased 2.441% and the maximum increased 7.638%. At C8, recorded
CPU per call increased 1.791%, p95 increased 5.335% and the maximum increased
0.984%, despite the lower p99. No favorable row is selected as evidence of a
general performance improvement.

The file helper retained per-cell controller CPU values; its underlying `/proc`
before/after counters were not persisted. The displayed CPU is therefore the
call-weighted original recorded value, not a new reconstruction of those
counters. Whole-round waited CPU includes controller and reaped local
descendants, warmup, expected refusals and shutdown; sampled local-tree CPU is
a third incomplete observation. Remote-host CPU is outside those local scopes.

### Soak and observed resource limits

The configured **120-second** C8 loop completed 27 cells and 2,592 measured
calls. Summed measured-cell time was **121.448468 seconds**; the complete helper
elapsed **129.079058 seconds**, including setup and cleanup. These durations
have different coverage. The pooled rate was **21.342 calls/s**. Quantiles over
all original measured calls were **p50 361.936 ms, p95 461.104 ms and p99
533.466 ms**, with a **975.308 ms maximum**. The p99 is a pooled call statistic,
not the maximum or average of cell p99 values.

Recorded controller CPU averaged 74.039 ms per measured call. Complete-round
waited local CPU was 223.431092 seconds; sampled local-tree CPU was 199.42
seconds. These CPU scopes must not be added or treated as interchangeable.
The following 100 ms observations retain every stage's resource sampling
errors:

| Observation scope | Samples | Controller RSS peak KiB | Local-tree RSS peak KiB | Controller/local-tree FD peaks | Recorded sampling errors |
| --- | ---: | ---: | ---: | --- | ---: |
| Inherited pipes | 208 | 15,508 | 39,504 | 45 / 63 | 0 |
| Original recovery controller | 31 | 17,208 | 94,736 | 77 / 138 | 0 |
| Restarted recovery controller | 39 | 16,728 | 110,304 | 76 / 134 | 2 |
| File round 1 (R6a) | 375 | 17,960 | 111,348 | 80 / 150 | 1 |
| File round 2 (R7b) | 373 | 17,572 | 96,808 | 73 / 134 | 3 |
| File round 3 (R7b) | 373 | 17,452 | 111,108 | 78 / 144 | 1 |
| File round 4 (R6a) | 371 | 17,716 | 118,880 | 81 / 160 | 2 |
| R7b C8 soak | 1156 | 18,324 | 127,288 | 89 / 188 | 25 |

The soak's controller/tree sampled RSS peaks were **18,324 / 127,288 KiB**,
with **25 sampling errors**. All resource peaks above are incomplete samples,
not exhaustive bounds. Legacy canary error entries are capped at eight; these
runs recorded zero, zero and two respectively, without truncation. File-helper
error counts are uncapped. Repeated cumulative snapshots were not summed.
Small-archive whole-round `wait4` peaks use a different metric, as recorded
separately above.

Two-second local load gates had zero recorded errors or unclear samples in
all eight stages. They do not establish exclusive use of X230 or control
remote/background load. Six tiny immutable files do not establish bulk-transfer
bandwidth. This run validates controller-process failure and identity recovery;
it does **not** simulate target reboot, physical power loss, WAN partition or
production ownership transfer, and it is not a 600-second endurance test.

## Retained artifact and evidence identities

Hashes identify the retained originals. Raw execution records and configuration
are not embedded in this public report. Release and libtest identities are
listed separately so diagnostic measurements cannot be mistaken for release
qualification.

| Retained item | SHA-256 |
| --- | --- |
| R5b qualification report | `0a5a103bb86f8ad0a5996dcf2f54667d623a9db711e289c14f4f06b112e93fec` |
| R5b isolated-case audit | `ea43b16db1137a8fb1f171d167c51f4918520b6bc0426c2ff69da42898cd6251` |
| R5b 196-file compiler-input map | `780cd5679363a2bdbd9d4b09a3e447a1fad8a0ba9d7a0fc466442a44ef0c4843` |
| Qualified R5b runtime release | `da513d01e4dd4b12f1a6365472cbd743c8be31ec5371f01242c2e2735f4a9d16` |
| Retained R4e runtime release | `8469fe7afdf560f4c501e5162cd7926957fade695118e9b9b72f1594ed861248` |
| Qualified R5b libtest | `ade63daddb1ca6dc482c36533ba6077d0fc23224f06e256fea8c8010ca6b0377` |
| R4e control libtest used for receipt/idle comparison | `f97c7a00e222e229277cbfe1faa5b420c9a745cec7bb0fa0f6944fde3f9f7880` |
| R5b receipt/idle original evidence archive | `cf01ef3c2f8c0e85c84c1b1184b6da94a07bc0a75cfb9eec2ce3fa3341a647e8` |
| First R4e/R5b release ABBA report | `2d8103fb8fe891430083e1551c64c2bdf0fd4278b76e666fe3c75ea888e959f8` |
| Quiet R4e/R5b release ABBA report | `93f7955f458643135a23dd508e564646dd6670766446e13419948d9aa74b4a77` |
| Pooled R4e/R5b release result | `ef897ae57d384d353678f7bacad3765c3338667b0af46a56dab28f44c0dd07bd` |
| R5b native validation report | `72b19e8223117931c939093faf103a88630855888b67c1127ec05809e08457cd` |
| R6 baseline diagnostic libtest, R5b production code | `24fba3043f5606103f6697a1ee06b1f05d6a8a869fa4c19b943b5d5101ab8f68` |
| Original successful baseline probe stdout | `7431eadf9c8e7d8e558d1045fb96c998c13144449ea265eaf77d0248ac44a574` |
| R6a qualification report | `fa8ea5292d582c57e483493202c759f780ff42ac79d8e040e0ae4c7b8a231102` |
| R6a isolated-case audit | `e5a6826a07c70b3589c42d6b943934c95771317ff1078212e533081d9daaa753` |
| R6a 198-file compiler-input map | `83c68c34fb85337db5fb1bdac1271fec64f1674fbd9a88fe149c434734b666d6` |
| Qualified R6a runtime release | `c51e1be5012147fa6718c4b2883440ad971c46774151f65211ecde5403b14ce1` |
| R6a exact diagnostic report | `6909a781f6e03668d1de34ad203c5bc01b130dadcbbbe7a0cfcf0f8bff882cca` |
| Original successful R6a probe stdout | `a7a52b156390d9c1658465164b3b0f5a874ba3d4b9e59ea0068e6475ec1d6dc0` |
| First R5b/R6a release ABBA report | `8220506fa83c974a656054b60dd80fbc59bb9b1dfbfd6a08ef9539acb5415a5e` |
| Second R5b/R6a release ABBA report | `42d78403768ef33544c5c5a567d3a08a99a12de2231c97d352fff5f1e1081146` |
| Private pooled R5b/R6a validation record | `e3e6ac5bc8e1ba264e34a098f00fb09368b8a8f50c25f017e6fd538cb56f5c72` |
| Aggregate-only pooled R5b/R6a result | `0284c7d183e1e9d046229ff06f5dfc232af7eb167b8d4722fcce6aa6a8aa2a00` |
| R6a native validation report | `327b9155c12bc7c18fce93322ab4ba912cdfe488328273fa2f0da0962fa73759` |
| Rejected first R6a native aggregation record | `dbee2c770ad126bb41234377b591664290579f562d411f0306a7f8718dbeb2c8` |
| Blocked second R6a native aggregation record | `e09bd950f33f3fb932c02b0016aa80111f5507b752d5bbc9a085d7f9cda8f9fe` |
| R6b qualification report | `f62b49ab2a3f2a189cf971c8125223fdf97bdb7cda994c1141a642c13629300a` |
| R6b isolated-case audit | `0a459ebf775b8a7f9a504cc22c945beb39e496dfda37dbd94c663610ebc47427` |
| R6b 199-file tested compiler-input map | `92e94252dae0ed09e227d4b2a9c0bbea4974adbd19cb223616af8a7ed21089b2` |
| Qualified R6b runtime release | `3762dd01d687d6e1bc097710114c9ff66bcfad7cd21d5089a27b483eb4e02530` |
| Qualified R6b diagnostic libtest | `d953102b6cc48365411a5053211ed841af1e2871f1449dfc0722a702974de8f0` |
| R6b exact diagnostic report | `a7814fe292a20804a900842b25a335bdbe9f63b8ca4eb20a82c050a1cba993e4` |
| Original successful R6b probe stdout | `1f7f91962cbdc38a55bb31fb00aa1cec0c7dc9e3e0a17c60cdbac31fd5ca10e2` |
| First R6a/R6b release ABBA report | `a3cf9f9344218b566e9bf0e17b2151efa7d86cae02e5b5a1cd37619cc46ab8da` |
| Second R6a/R6b release ABBA report | `4ff3f9b8091cc55a81e593315e22469d0d36315003294771ab7d45224f4bb267` |
| Aggregate-only pooled R6a/R6b result | `c4a1b871e5c69c105ee638cb7c1b95abf7914771ad2271b36c23a0af9f093d0b` |
| R7b predeclared validation plan | `455bd25a8ad741d953a260fbf7f75a8d9b113c1b861f40140f8bb1c18c51852b` |
| R7b four-file source composition manifest | `6711824786360f6b6b9b3ba1617fafd69bf1a59bc616f6637cf36bfd35fbf1b2` |
| R7b qualification entry point | `6478427c5ae51d81cc7d8ffbeef837248f98132d55dbadf95e718af93e25f159` |
| R7b original successful qualification report | `e63877be21b851550c7f1d27f4d86e897f6fe02b0999ab6b4bcbc6762dbf380f` |
| R7b original isolated-case audit | `d60d40f3fd648325a82ac079c9d58267ecfcbfe132cb3d5b06e7969e34243ed0` |
| R7b 200-file tested compiler-input map | `d7770688369f0f60406bddf499519efd045b5bd0864f596a343760d37a07d59a` |
| Qualified R7b runtime release | `7c8207d38d89c34b18e07e91e2702bed99803365d90b4b06643d8d6e6d34cc5e` |
| Read-only R7b qualification summary | `97bd83f0c077324c3c38632686fd9a4f65bfb0ca18544b17020168f545b73561` |
| Frozen R7b performance launch binding | `d3a21ad121c5c76a084f0f1428bfd9ab45e8563b5200fdd178e35b191ba5b434` |
| First R6a/R7b release ABBA report | `49db903d863aa70695f0b71212152d4f88b8d120d0c92384ddf6a67d4053f73b` |
| Second R6a/R7b release ABBA report | `82eb17b7c5301d07b3e2f247923ef2cca8f02a9415c1d747d95bdc173f0412af` |
| Aggregate-only pooled R6a/R7b release result | `2cb02bf68d0c963608868a8850e24f52faf593e7ef1a188210b3d58136657eeb` |
| Original eight-process R6a/R7b inventory RSS report | `592d74d91a9450bc896bd6336f1189929c9f9e5f3fe8165310f35374bc8280e2` |
| Derived fixed RSS gate verification | `0aa79c41c7de8809ab32db21e9e01b6ad1badd6f59433cb8d0ebbe50f3935582` |
| Frozen inventory RSS experiment harness | `a9f840198a8d153862dd17732146039a50b45c969dad679173e5c447a79801ba` |
| Inventory RSS harness regression source | `9bafd07ab92c210cbe4cc0e47000bcbb3afb5aa1e9aefbdf1b8b6ddf10856395` |
| R7b paired-native pre-execution plan addendum | `5d8a55659acf2b33695c079d6f225a48280c08220221eb519f5ca0c8de96a27d` |
| Frozen R7b paired-native actual launch binding | `167d4a2cbcaae6ae5261e0a8c0314640b39a89e66b9f42f59c5bd0b50a63ae59` |
| Original successful R7b paired-native report | `31915c7f234c21705398e6f0f1af9f490c286677d82dce1ec7cad2c916ca9f69` |
| Complete R7b paired-native evidence derivation | `18e52f322446c0dc811899ba16df61964ed553eb41c2987cd6b82badad37aa53` |
| R7b forwarding/custody reconciliation summary | `96e0e45b757959443151d3d2d97a7ecfc252a6bd59895d3de2344d078aa07c96` |
| Final R7b resource-versus-latency adoption decision | `deaa16a230f9276536c1aea1d4643d7ac57b33a028f9b59302f62dbc57e9894c` |
| Paired-qualified native runner | `980357ba4c1f44d93e3a306415ebd63c4dc8b830328c556e48596b01e3df18cf` |
| Paired-native harness regression source | `3db0e88c646ce09e4ba6367b36fb9435eb76a1cbe5bacbec8025880cce6782fa` |

The qualification runner, exact-case auditor, registry-cohort release harness
and native suite are maintained under [`tools/x230/20261028`](../tools/x230/20261028/).
The source map produced after formatting, retained executable hashes and
original run reports bind each experiment to its own source. Final publication
identity and exact-head/prospective-merge CI acceptance are recorded against
[PR #77's current head and checks](https://github.com/TrillionniumFoundation/hepta-runtime/pull/77).
The published compiler inputs must match the accepted tested map; this report
does not claim a GitHub CI result for its own commit, and a completed historical
test report cannot substitute for current-head checks.

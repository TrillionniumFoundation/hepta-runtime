# A50 large archive: failed and incomplete comparison

**The formal A50 large ABBA attempt failed and did not complete its fixed inventory.**
It executed 60 of 80 measured slots: 46 succeeded and 14 returned product
failures. The final r07 controller's one fixed archive warmup failed, so its
20 measured slots and eight waves remain explicitly unexecuted. Both A50
controllers did finish: C1 was 8/8 and C4 was **30/32**, below the required
32/32. The small regression-guard pass does not authorize performance adoption.

The immutable original report is **222,182 bytes**, SHA-256
`076079ce16dd95d3996651c801567fc12b82e76936693c2b8843750cf6bc1ce0`; the original
protocol is **10,877 bytes**, SHA-256
`0e88d817a7c6f0bf056c66fe68f3cc0e62d3a87f7df0ae966e603523e33511f3`.
The actual attempt ran from `2026-10-26T06:10:23.521733+00:00` to
`2026-10-26T06:22:11.898250+00:00`. Its terminal state is
`phase=failed, complete=false, passed=false`.
[large-summary.json](large-summary.json) retains all 80 original slot rows,
all 32 original wave rows, all twelve original setup rows, every failure and
all sixteen raw gates, together with the independent Decimal recomputation.
No row or failed controller was selected out, and no retry replaces this result.

## Fixed inventory and all setup failures

| Controller | Arm | C1 correct / attempted / planned | C4 correct / attempted / planned | Measured failures | Terminal state |
|---|---|---:|---:|---:|---|
| 0 | r07 A | 4 / 4 / 4 | 4 / 16 / 16 | 12 | Complete |
| 1 | A50 B | 4 / 4 / 4 | 14 / 16 / 16 | 2 | Complete |
| 2 | A50 B | 4 / 4 / 4 | 16 / 16 / 16 | 0 | Complete |
| 3 | r07 A | 0 / 0 / 4 | 0 / 0 / 16 | 0 attempted | Failed fixed warmup |

There are 19 successful waves, five completed waves containing product
failures, and eight unexecuted waves. Slots **60–79** were never written.
All 60 attempted measured requests had one write attempt and received and
journaled their original reply. The fourteen measured failures comprise
eleven r07 preparing/validation-unavailable responses, one r07 total-deadline
response, and two A50 total-deadline responses.

All four native seed calls succeeded. All four `usage_stats` index kickoffs
failed with the total-deadline response. Three fixed archive warmups succeeded;
controller 3's warmup failed after **3001.671754 ms** with
`archive index preparing or validation unavailable; repeat only this metadata query`.
The controller stopped under the frozen rule
`one fixed archive warmup failed; no readiness retry`. These are twelve
actual setup tool calls with seven successes and five failures, kept separate
from the 80 planned measured slots. Including setup, 53 of 72 attempted tool
calls succeeded and nineteen failed.

| Controller | Arm | Setup purpose | Response elapsed ms | Failure |
|---|---|---|---:|---|
| 0 | r07 | index_kickoff | 3002.324291 | total deadline |
| 1 | A50 | index_kickoff | 3001.764241 | total deadline |
| 2 | A50 | index_kickoff | 3002.296917 | total deadline |
| 3 | r07 | index_kickoff | 3005.615389 | total deadline |
| 3 | r07 | archive_warmup | 3001.671754 | preparing / validation unavailable |

The setup failures and twenty unexecuted slots remain part of the result.
The first three controllers' completed measurements cannot supply the missing
final baseline controller.

## Numeric scope: candidate observations, incomplete baseline

| Mode | Arm | Correct / attempted / planned | Sum of executed wave wall s | Scoped CPU s | Scoped CPU interval s |
|---|---|---:|---:|---:|---|
| C1 | r07 A | 4 / 4 / 8 | 8.800603046 | null | unavailable |
| C1 | A50 B | 8 / 8 / 8 | 16.154128246 | 30.300000 | 30.220000–30.380000 |
| C4 | r07 A | 4 / 16 / 32 | 12.011635398 | null | unavailable |
| C4 | A50 B | 30 / 32 / 32 | 16.763119369 | 31.199383 | 31.159379–31.239387 |

C1 CPU is the process CPU difference between the pre-C1 and pre-C4
endpoints. C4 CPU is the **inclusive allocation through original wait4**:
whole-life user plus system CPU minus the pre-C4 cumulative process CPU.
It includes remaining work, final original verification and shutdown, and is
not exact pure-C4 CPU. Every executed wave, including all failures, stays in
the wall and CPU allocation.

The baseline arm's two scoped CPU totals are **null** because controller 3
never generated the required measured endpoints. Controller 0's valid partial
CPU and controller 3's setup-only whole-life CPU cannot fill those missing
endpoints. Whole-life wait4 totals exist for both arms, but they cover unequal
executed work and must not be used to infer CPU savings.

The original report still computes two descriptive ratios from the available
wall data: C1 wall/attempt **0.917785301846…** and C4 successful calls/s
**5.374134938847…**. Their raw inequality flags are true; the populations are
unequal (8 versus 4 C1 attempts, and 32 versus 16 C4 attempts).
They are retained for faithful reporting, **not accepted as speedups or
completed ABBA comparisons**. All three CPU ratio fields remain null and
their gates remain false.

The original wait4 RSS guard also fails its recorded inequality:
**114,688 > 113,251.6 KiB**, an excess of **1,436.4 KiB**. The threshold is
`max(102956 × 1.10, 102956 + 4096)`. All four wait4 receipts are present;
however, the second baseline controller stopped before measurement, so this
is an observed failed guard within an incomplete comparison, not a completed
balanced memory comparison. The fixed guard uses wait4 peak RSS. Sampled
`/proc` high-water marks are separately retained and do not replace that
frozen metric. Neither metric establishes steady-state or soak memory use.

The independent calculation uses 50-digit Decimal arithmetic, integer CPU
ticks, integer monotonic wave timestamps, and original wait4 user/system
seconds. Counts, RSS threshold, all sixteen gate values and original numeric
values match; the original binary-float tails differ only at negligible
rounding precision. This review does not reread the remote wire, fixture,
host-snapshot, source or ELF bodies.

## Actual custody and guard receipts versus aggregate gates

The raw aggregate gates are not rewritten. Several are false because the
experiment did not finish, rather than because an actual recorded host,
source or child-cleanup check failed.

| Actual evidence retained in the original report | Observation |
|---|---|
| Four original controller shutdowns | All four original children reaped, exit code 0, raw stdout EOF captured; no shutdown error, unmatched reply or protocol violation |
| Outer custody adapter | Four normal original closes, **zero fallback uses**; no renewed cleanup or reconstructed measurement |
| Fixture witnesses | All four post-shutdown content and identity digests match each controller's initial witness |
| Host receipts | Both blocks' before/after gates clear (four receipts); all three controllers reaching measurement have a clear premeasurement gate |
| Qualified bundle/source fences | Both per-block fences passed, including the failed block's finally path |
| Actual client pending inventories | All 24 executed waves have their required distinct pending IDs |
| Existing process endpoints | All nine measured endpoints show zero child CPU ticks and empty owned-thread child lists |
| Final global frozen-input receipt sweep | **Not reached** after the failed block; neither final top-level host/input aggregation field was written |

The last item matters: successful per-block receipts do not justify
inventing an end-of-all-block frozen-input sweep. Conversely, the absent
top-level aggregation fields do not erase or reverse the successful checks
that are actually recorded. Controller 3 has no measured process endpoints;
the missing endpoints are not evidence that it spawned a child.

### All sixteen original gates, unchanged

| Gate | Raw value | Interpretation |
|---|---|---|
| `actual_client_pending_matches_each_fixed_wave` | false | False because eight planned waves were unexecuted; all 24 executed waves record the required distinct pending count. |
| `all_controller_custody_and_fixture_proofs` | false | The frozen gate also requires every controller status=complete. Controller 3 failed setup; all four owned children were nevertheless reaped and all four fixture-after-shutdown digests match their initial digests. |
| `all_host_gates_clear` | false | Top-level aggregation field absent after the failed block; both blocks retain clear before/after host receipts, and three controllers that reached measurement retain clear premeasurement host receipts. |
| `all_qualified_inputs_unchanged` | false | Top-level aggregation field absent. Both per-block bundle/source fences passed; the final global frozen-input receipt sweep after all successful blocks was not reached. |
| `baseline_c1_8_correct_for_cpu_attribution` | false | Only 4/8 planned baseline C1 calls ran; controller 3 stopped at warmup. |
| `c1_cpu_per_attempt_le_1_10` | false | Undefined (null ratio), not passed: baseline C1 CPU has no complete two-controller endpoints. |
| `c1_wall_per_attempt_le_1_10` | true | Raw true for unequal observed populations (candidate 8 versus baseline 4 attempts); not an admissible complete ABBA improvement. |
| `c4_inclusive_cpu_per_attempt_le_1_10` | false | Undefined (null ratio), not passed: baseline C4 CPU has no complete two-controller endpoints. |
| `c4_inclusive_cpu_per_success_le_1_10` | false | Undefined (null ratio), not passed: baseline C4 CPU has no complete two-controller endpoints. |
| `c4_successful_calls_per_second_ge_1_50` | true | Raw true for 32 candidate versus 16 baseline attempts; incomplete comparison, not an admissible speedup. |
| `candidate_c1_8_correct` | true | Eight of eight candidate C1 calls succeeded. |
| `candidate_c4_32_correct` | false | Thirty of 32 candidate C4 calls succeeded; two genuine total-deadline product failures. |
| `candidate_c4_successes_not_lower` | true | Raw true (30 versus 4 successes), with half the planned baseline C4 inventory unexecuted; insufficient for adoption. |
| `complete_fixed_inventory` | false | 60/80 attempts and 24/32 waves executed; slots 60..79 and all controller-3 waves remain explicitly unexecuted. |
| `no_observed_controller_children_or_reaped_child_cpu` | false | False because controller 3 has no measured endpoints; all nine existing endpoints show empty owned-thread child lists and zero child CPU ticks. |
| `wholelife_max_rss_regression_guard` | false | Observed candidate wait4 peak 114688 KiB exceeds recorded limit 113251.6 KiB. All four wait4 receipts exist, but baseline controller 3 never measured; no completed balanced-ABBA memory result. |

The conjunction is false. The four raw true flags do not authorize adoption;
the fixed inventory and candidate C4 correctness both failed independently.

## Candidate failed wave: what the client actually observed

Both candidate failures occurred in **controller 1, wave 4**, the first C4
wave, slots 25 (`first_32`) and 26 (`quarter_16`). Each exact error is
`archive metadata query total deadline exceeded; repeat only the metadata query`.
The complete four-slot wave is retained below, including its two successes.

The unchanged frozen client helper records all four RPC IDs
`[9, 10, 11, 12]` in its pending dictionary before delivery. It joins the
four messages into **one 590-byte atomic nonblocking os.write**. Each row's
`write_attempts=1` marks once-only delivery of that request within this one
write; it does not mean four independently timed write syscalls.

All four rows share pending-snapshot time **1697397903329711 ns** and common
pre-write start **1697397903340964 ns**, separated by **0.011253 ms**.
Their recorded start spread is zero because one timestamp is copied to
all four rows. **No os.write-return timestamp or per-request write-completion
span was captured.** The full wave lasts **3.003818743 s**, including delivery,
reply waits, DTO validation and journal flush.

| Slot | RPC ID | Query | Outcome | Reader receive monotonic ns | Receive elapsed ms | Caller consumption elapsed ms |
|---|---:|---|---|---:|---:|---:|
| 24 | 9 | first_1 | success | 1697399834291429 | 1930.950465 | 1931.121778 |
| 25 | 10 | first_32 | total deadline | 1697400905900430 | 3002.559466 | 3002.702148 |
| 26 | 11 | quarter_16 | total deadline | 1697400905696281 | 3002.355317 | 3002.725140 |
| 27 | 12 | tail_32 | success | 1697399834044717 | 1930.703753 | 3002.738404 |

The first reply was slot 27 at **1930.703753 ms**. Slots 24, 25 and 26 had not
yet been received at that instant. The final reply was slot 25 at
**3002.559466 ms**, giving a first-to-last receive span of **1071.855713 ms**.
This establishes overlapping client waits after four pending IDs were
registered; it does not establish server admission, actual 1 ms cohort
membership, or the time spent under STORE_LOCK.

In particular, slot 27's `caller_wall_ms=3002.738404` reflects when the
sequential waiter loop consumed its already-arrived reply. Its actual reader
receive time was **1930.703753 ms**. Treating caller consumption time as reply
arrival would invent a different overlap pattern. Server blocking-closure
registration and cohort membership were not instrumented in this experiment;
client concurrency cannot substitute for them.

## Every measured failure

| Controller | Arm | Wave | Slot | Query | Failure category | Response elapsed ms |
|---|---|---:|---:|---|---|---:|
| 0 | r07 | 4 | 5 | first_32 | preparing / validation unavailable | 3002.133157 |
| 0 | r07 | 4 | 6 | quarter_16 | preparing / validation unavailable | 3002.262748 |
| 0 | r07 | 4 | 7 | tail_32 | preparing / validation unavailable | 3001.478769 |
| 0 | r07 | 5 | 8 | first_32 | preparing / validation unavailable | 3001.322058 |
| 0 | r07 | 5 | 9 | quarter_16 | preparing / validation unavailable | 3000.929966 |
| 0 | r07 | 5 | 10 | tail_32 | total deadline | 3001.470350 |
| 0 | r07 | 6 | 13 | tail_32 | preparing / validation unavailable | 3001.733985 |
| 0 | r07 | 6 | 14 | first_1 | preparing / validation unavailable | 3001.284874 |
| 0 | r07 | 6 | 15 | first_32 | preparing / validation unavailable | 3000.908984 |
| 0 | r07 | 7 | 17 | first_1 | preparing / validation unavailable | 3001.610035 |
| 0 | r07 | 7 | 18 | first_32 | preparing / validation unavailable | 3001.731369 |
| 0 | r07 | 7 | 19 | quarter_16 | preparing / validation unavailable | 3001.231593 |
| 1 | A50 | 4 | 25 | first_32 | total deadline | 3002.559466 |
| 1 | A50 | 4 | 26 | quarter_16 | total deadline | 3002.355317 |

All exact error strings, costs, delivery timestamps and original row fields
remain in the linked JSON and immutable raw report. No failure is converted
into an omitted cost, timeout retry, or successful subset.

## Interpretation and publication review

The comparison is **r07 versus A50**, not A48 versus A50. It does not isolate
the incremental effect of the 32-record batching change. Candidate C4
30/32 is a failed correctness gate, even though the second candidate
controller alone achieved 16/16. This workload uses fixed native client
waves on a private synthetic archive; it does not establish saturated-server,
multi-host, soak, durability or power-loss performance. The small
64-record serial-path result and its passed regression guards remain a
separate observation.

The A50 source's bounded validated-Record payload estimate is not a hard
bound on cache decoding allocations, transient heap or total RSS. Measured
RSS and the failed recorded guard remain visible. No adoption, production
deployment, retry, historical-result pooling, or claim that optimization is
exhausted is recorded. [next-steps.md](next-steps.md) records the remaining
evidence and access boundaries without changing this failed attempt.

A local body review of the two exact raw JSON files above detected no
credential, private-key or token material and no unrelated full-host process
inventory. Host-snapshot entries in these bodies are paths, sizes, hashes
and identity receipts; the full snapshot bodies are not embedded here.
Process samples concern the owned controllers. Their explicit startup
environment contains only LANG, PATH, RUST_LOG, SHELL and
TOKIO_WORKER_THREADS. Native seed hex decodes to the same nonsecret
request Record fields already present in the report. Owned-task identifiers,
synthetic IDs and custody metadata can be retained. Neither raw file was
edited or redacted, and this review did not execute a workload or contact
X230.

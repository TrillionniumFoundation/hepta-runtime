# A50 next steps: evidence required before another source change

**A50 is source-qualified, but the fixed large comparison is incomplete and failed.** This checkpoint stops further speculative source patches and preserves the original failures. The next candidate needs additional observations that distinguish the remaining causes. This stopping point does not establish hardware saturation, an absolute optimum or exhaustion of every possible optimization.

This document is a static analysis of the actual qualified sources plus the retained final A50 report. It does not launch another workload, retry the failed round, change a deadline or alter the pinned authentication binding. The [qualification summary](qualification-summary.json), [large results](large-results.md) and [large summary](large-summary.json) remain the records of their respective observed outcomes.

## 1. What the completed operation actually established

The original large report has schema `hepta-a50-native-archive-cohort/v1`, is 222,182 bytes and has SHA-256 `076079ce16dd95d3996651c801567fc12b82e76936693c2b8843750cf6bc1ce0`. It ran from 2026-10-26 06:10:23.521733 to 06:22:11.898250 UTC and ended with `complete=false`, `passed=false` and `performance_adopted=false`.

| Retained scope | Actual result |
|---|---|
| Planned fixed ABBA inventory | 80 measured calls across four controllers |
| Measured calls actually attempted | 60: 46 succeeded and 14 failed |
| Unexecuted measured calls | 20, slots 60–79, belonging to the final baseline controller |
| A50 candidate measured calls | 38/40 succeeded; C1 8/8 and C4 30/32 |
| Candidate failures | Controller 1, first C4 wave 4, slots 25 and 26 |
| Final baseline setup | Its one fixed archive warmup failed; the prescribed remaining measured block stayed unexecuted |
| Original controller cleanup | All four original children were reaped by `wait4`, each with exit 0; no custody-adapter fallback was used |

The two candidate failures were `first_32` and `quarter_16`, with recorded elapsed times of 3,002.559466 ms and 3,002.355317 ms and the public total-deadline error. The other two calls in that same client wave succeeded at 1,930.950465 ms (`first_1`) and 1,930.703753 ms (`tail_32`). This is a useful distribution to explain, but it does not identify the server cohort membership or the stage that consumed each call's budget. The raw report explicitly records both server admission timestamps and server cohort membership as **unobserved**.

The last baseline controller's archive warmup returned the generic index-preparing/validation-unavailable error at 3,001.671754 ms. Its preceding kickoff also recorded a product failure; these setup outcomes remain separate from the 60 measured attempts. There was no readiness retry. The incomplete baseline has null aggregate C1/C4 CPU attribution. Any partial wall or throughput ratios retained by the raw calculation are not an accepted comparison and must not be reused to claim an A50 improvement. Original child exit 0 proves orderly process completion in this fixture; it does not make the failed query inventory pass. See the [large evidence summary](large-summary.json).

## 2. Admission, collection and deadline: eight permits are not two readers

The unchanged public metadata path in [request_audit.rs][audit] and the archive [coordinator][batch] has the following order.

| Stage | Actual boundary and budget consequence |
|---|---|
| Metadata API entry | `archive_history` / `usage_stats` constructs one absolute `Instant::now() + QUERY_BUDGET`; `QUERY_BUDGET` is 3 s. This is not a new budget at worker start. |
| Metadata admission | `run_metadata_query` acquires one of **eight** global metadata permits. Each caller acquires its own permit before reaching the cohort coordinator. Waiting consumes the same absolute budget. |
| Blocking submission | The owned permit moves into that caller's original `spawn_blocking` closure. Blocking-pool queue time also consumes the original budget; a late worker checks the deadline before starting the query. |
| Cohort registration | After the blocking closure starts, a large-hinted request reaches `execute → register(..., Instant::now())`. The first member's recorded `entered + 1 ms` fixes the collection cutoff. |
| Joining | A caller may join only before that cutoff, before freeze and before the relevant deadlines, with at most eight members. A new member can shorten the group's minimum deadline; it cannot extend the cutoff. |
| Freeze | The leader fixes the member list and earliest member deadline, removes that group from the collecting registry and releases coordinator locks before archive observation. |
| Observation and completion | The original absolute deadline covers locking, ready/drain work, full observation, projection and final checks. The caller also rejects a successful worker result observed after its own deadline. |

These rules are visible in `request_audit.rs` at the permit definition and `run_metadata_query` (lines 32 and 1732–1765), and in `request_archive_batch.rs` at `collect`, `freeze`, `register` and `execute` (lines 215, 235, 348 and 486). [Audit source][audit] · [Coordinator source][batch]

The **two original-reader threads** belong to one large snapshot. They do not constitute a two-permit metadata admission limit. Four client calls are therefore not necessarily split into two rounds by admission. The fixed measured C4 workload uses four simultaneously pending `request_archive` RPC IDs; `usage_stats` is used for kickoff, not as a second measured C4 tool. The native driver explicitly does not guarantee simultaneous server admission or common cohort membership. [Fixed workload and measurement scope][large-driver]

The 1 ms clock currently starts after blocking-pool scheduling, not at network receipt, client send, semaphore acquisition or public metadata API entry. Consequently, client concurrency alone cannot prove that all four calls reached registration within one collection interval. Conversely, two deadline errors alone cannot prove that they formed a second group: scheduling after shared completion and late-result rejection are also boundaries requiring observation.

## 3. The global snapshot lock and work that A50 leaves intact

In the unchanged [index source][index], `read_snapshot_with_mode` takes `STORE_LOCK` at line 1927 and the slot state guard at line 1936. It keeps both through complete content verification, query projection and the final database/version/layout/deadline checks, returning at line 1991. This is a lock shared within one runtime process, not a host-wide or multi-host lock.

`query_lock` uses a FIFO ticket gate and `Condvar::wait_timeout` with the original deadline. Once its turn arrives, it uses `inner.try_lock`; this path is not a repeated busy-spin loop. Slot-capacity, ready and an incomplete drain have their own bounded sleeps after releasing the relevant guards. A regular state mutex acquisition and an already-running filesystem syscall are still not forcibly interruptible by this deadline. [Audit lock implementation][audit-lock] · [Snapshot implementation][snapshot]

One frozen `pages` cohort receives one complete fresh observation. Its page projections share a read transaction and PendingView. The verifier has its own preceding read transaction; the verifier and projections should not be described as one redb transaction. Different cohorts do not share a cached proof that the previous cohort already validated every original. Pages and usage also have separate coordinators and snapshot entry points. [Pages and usage projections][index]

A50 batches messages between the coordinator and two original readers. It does not remove these remaining costs:

- Every independent large snapshot still walks the complete namespace and validates every effective original Record and stamp.
- The coordinator still performs per-record database lookup, decode, identity and ORDER checks before submission.
- Each reader still performs the original descriptor, path/stamp, read, parse, field-validity and expected-Record checks.
- Each page projection still re-reads its selected originals; overlapping page requests do not automatically eliminate those existing checks.
- Each large snapshot creates its two scoped reader threads and bounded channels.

These are static costs, not a measured ranking of bottlenecks. The exact tested A50 content source is [request_archive_content.rs][content], SHA-256 `720c992a407fbe1bb3fa4ff9918d0772b4187065f848da947aa2fa96eb7a297a`; its binding is in the [source export manifest](source-export-manifest.json).

Background work can also postpone readiness or a query drain. The worker sets `state.busy` for background apply and performs that apply after releasing its short claim/state guards; the whole background apply must not be reported as holding `STORE_LOCK`. Query-triggered catch-up on the non-watched-large path does execute `apply_traced` under the query's outer global guard. The outer quiet-checkpoint/seal call sites do not themselves hold that guard. This review did not establish the entire internal seal lock duration. [Worker and drain implementation][index]

No next candidate should simply release the snapshot guards, skip the full scan, reuse a previous cohort's completed observation or accept a partially verified batch. The present contract includes bounded and complete pending-tail reconciliation, generation/version checks, full Record coverage, final namespace fences, per-record cancellation/deadline checks, original-thread joins and panic propagation through the original guards. An in-progress original I/O operation must finish and be joined before the locks and permits protecting it are released. The 3 s deadline rejects late success; it is not a promise that all cleanup finishes exactly at 3 s. [Content verifier][content] · [Qualification design](qualification-design.md)

## 4. Pre-registration before `spawn_blocking`: conditional feasibility

Moving pure-memory cohort registration earlier is a concrete hypothesis for reducing blocking-scheduler variation between arrivals. It has not been implemented here and the completed A50 report does not prove the motivating group fragmentation.

`large_hint` and `register` touch the coordinator registry, group state, reply slots and bounded member storage. They perform no file access, take no archive slot state guard and do not acquire `STORE_LOCK`. The potentially long collect/wait-for-completion operations are separate. The healthy critical sections are small, but their ordinary mutex acquisition is not a hard real-time guarantee. [Coordinator implementation][batch]

A normal-path design could acquire the original permit, pre-register without an intervening await, immediately hand the complete owned token to the original blocking closure, and then retain the existing collect/freeze/read/stage/cleanup sequence. It must record the first member's cutoff once, preserve the minimum absolute deadline and refuse late membership. Starting or rescheduling a worker must not reset either clock. Changing where registration occurs changes internal admission timing even if the numerical window stays 1 ms; this is not an automatically equivalent code rearrangement.

The existing lifetime proof is stronger than a freely movable registration token: **when the current registry exposes a group, its leader is already running inside its original blocking closure**. Pre-registration before submission loses that proof. The following states need explicit handling before such a candidate is ready.

| Boundary | Required ownership proof |
|---|---|
| Leader registered but not yet submitted | Followers must not depend on a leader whose submission or failure publication can be indefinitely delayed by the resources those followers consume. |
| Follower registered, submission fails or the queued closure is destroyed | The original member permit cannot be released while the shared leader still owns its I/O. Cleanup must also avoid an unbounded wait on an async executor thread. |
| Worker starts after its deadline | The pre-registered token and permit must already have a defined common owner and destruction order before any early return. A token left in an unconsumed query capture is insufficient proof. |
| Caller times out or is cancelled | Dropping the async future or join handle must not discard the permit while the original queued/running work or its shared observation remains active. |
| Leader panics or fails before/after observation starts | Every exposed member must receive the correct terminal fallback exactly once, after the relevant original cleanup; a newer same-root group must remain untouched. |
| Freeze or observation has started | Later requests remain outside that observation, even if joining would reduce work. |

The existing follower `Waiter::drop` calls `wait_complete`. The existing `Completion::drop` removes only its original group and publishes completion/fallback. Both currently run within a lifecycle designed around an already-running blocking owner. Moving registration to async code can move these destructors onto an executor or a failed-submission path. Merely making the token `Send`, or assuming submission cannot fail, does not resolve the permit lifetime or blocking-cleanup risks. See `request_archive_batch.rs:124–177` and `285–323`, together with `request_audit.rs:1748–1753`. [Coordinator][batch] · [Metadata admission][audit]

Before implementation, the design would need to specify unsubmitted, accepted, observing and completed ownership, including queued-task destruction and cancellation. Focused validation would then need to cover each transition, late-worker deadline handling, the original held-reader cancellation/join cases and no success after the fixed minimum deadline. This checkpoint does not select that change for adoption or start those tests.

## 5. The observations needed to choose the next change

The most useful missing evidence is a bounded, correlated account of each call's budget and each actual cohort. A future diagnostic should retain the original deadlines and work inventory and record enough locally assigned call/cohort identity to connect:

1. Public metadata API entry and its original absolute deadline.
2. Permit wait start/acquisition, blocking submission and actual closure entry.
3. Registration time, leader/follower role, first-member cutoff, frozen member count and minimum deadline.
4. Initial hot/archive lock wait, ready/drain waits, snapshot lock acquisition and the start of full observation.
5. Original-reader completion and joins before the walk's terminal namespace fences; verifier return, projection, final snapshot fences, cohort completion and per-caller delivery or late-result refusal.

Record unsuccessful, cancelled and unexecuted cases with the same inventory discipline as successful calls. A missing trace event must remain missing evidence, with any bounded-log overflow or truncation explicit. The instrumentation changes the diagnostic conditions and must be identified separately; it does not replace this failed A50 round or enter its performance totals.

The existing `HEPTA_ARCHIVE_INDEX_TRACE` output does not close these gaps. `metadata_drain` starts after `ready`; it does not cover the full permit/pool/collection/initial-hot-lock/ready interval. Its snapshot phase does not isolate original I/O from coordinator decode, projection and final checks. It emits only stages above 100 ms and carries no RPC/cohort identity. Therefore a zero reported `store_lock_wait_us`, or an absent short-stage line, cannot establish zero total lock or scheduling delay. [Trace and snapshot source][index]

The [retained A49 diagnostic](../a49/results.md) failed during warmup, before all 20 selected measured slots. It supports only its recorded warmup phase observation. It cannot supply the missing C4 grouping evidence or be retried and pooled into a successful history. Similarly, the repeated count of two candidate C4 failures in separate experiments is insufficient to attribute the failures to collection-window splitting.

The technical decision order is to explain the observed failure path, choose one bounded change that preserves the stated invariants, and only then conduct a separately identified qualification/comparison if work resumes. No extra budget, wider collection window, weaker validation, stale-result reuse or more readers is assumed by this analysis.

## 6. Multi-host and recovery acceptance remain separate

The latest retained current-agent preflight from this 2026-10-26 optimization campaign is documented in the [native-auth report](../native-auth-20261026.md) and [evidence JSON](../native-auth-20261026.json), operator job `1a17637f098-96a-a8f`. **At that recorded observation**, the current socket existed and `ssh-add -l` returned 1; the attempt did not establish a usable agent identity. Its exact identity count is unknown. The historical count of zero is a separate observation and must not be substituted for the missing current count. This next-steps review made no new agent probe and does not claim the retained socket state is a fresh observation at publication time.

That retained evidence did not establish native multi-host acceptance in this round. The existing route requires a usable already-authorized current agent in the operator session, a fresh profile bound to that socket and the pinned SSH configuration/known-hosts, and the original bounded native validation. Restoration and acceptance have not been demonstrated by the retained evidence. An IdentityFile cannot silently replace the authentication source of that same-profile acceptance; this is a limitation of the recorded validation binding, not a claim that runtime or OpenSSH universally prohibits IdentityFile. [Current-agent boundary](../native-auth-20261026.md)

PR72 remains a separate source branch. Its [immutable A43/A46/A47 results][pr72] establish X230 source qualification, real local business `Popen`, preserved exit 0/7 behavior, ambiguous-relaunch refusal and six actual pre-business SIGKILL cuts across the two versions. The A47 harness executed the exact extracted Python supervisor/launcher/status code, with 10/10 correctness cases and 128/128 measured business jobs. It did not drive the complete Rust MCP/SSH path. Those results do not establish recovery after partial external business effects, host reboot or power loss, multi-host recovery or a global exactly-once guarantee. A50 does not incorporate that owner-barrier source change.

The present checkpoint therefore preserves three distinct outcomes: qualified A50 source, an incomplete failed large performance comparison, and still-unestablished native multi-host/recovery scopes. Additional evidence is the prerequisite for another defensible optimization decision. No absolute hardware or optimization limit is claimed.

## Source identity references

The unchanged sources below were read at actual A48 checkpoint `a9ba701676138f7e379dab07b38af27c72c46ed8`; their SHA-256 values match the corresponding rows in A50's [actual tested map](source-tested-map.json).

| Source | SHA-256 |
|---|---|
| `request_audit.rs` | `3e29b190fe9bf7784697ea27dede1dd8ce6f133c7074d65993fd730a651099ca` |
| `request_archive_batch.rs` | `19c71818b7b0e85d49ffcf30594dad006430ff65f4e47096f49dff4d540ed0bc` |
| `request_usage_batch.rs` | `867f33dda2e83d261db36b6159d8b9db18d5ba8f8963ca1cc3d170ce28d2d991` |
| `request_archive_index.rs` | `5cec6362637d1ac17c9b6ae55e4d5b9c317ae893e818ac8c8d54b5e8b7cd389d` |
| A50 actual `request_archive_content.rs` | `720c992a407fbe1bb3fa4ff9918d0772b4187065f848da947aa2fa96eb7a297a` |

[audit]: https://github.com/TrillionniumFoundation/hepta-runtime/blob/a9ba701676138f7e379dab07b38af27c72c46ed8/src/mcp/runtime/request_audit.rs
[audit-lock]: https://github.com/TrillionniumFoundation/hepta-runtime/blob/a9ba701676138f7e379dab07b38af27c72c46ed8/src/mcp/runtime/request_audit.rs#L340-L455
[batch]: https://github.com/TrillionniumFoundation/hepta-runtime/blob/a9ba701676138f7e379dab07b38af27c72c46ed8/src/mcp/runtime/request_archive_batch.rs
[index]: https://github.com/TrillionniumFoundation/hepta-runtime/blob/a9ba701676138f7e379dab07b38af27c72c46ed8/src/mcp/runtime/request_archive_index.rs
[snapshot]: https://github.com/TrillionniumFoundation/hepta-runtime/blob/a9ba701676138f7e379dab07b38af27c72c46ed8/src/mcp/runtime/request_archive_index.rs#L1912-L1992
[content]: ../../../../src/mcp/runtime/request_archive_content.rs
[large-driver]: ../../../../tools/x230/a50/run_native_archive_cohort_a50_r01.py
[pr72]: https://github.com/TrillionniumFoundation/hepta-runtime/blob/2e950f45e331bed702f7c36ec5a9415bed741358/docs/experiments/x230/a43-a46-a47-results.md

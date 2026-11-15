# R14 cancellation concurrency review and optimization frontier

Status: **candidate-awaiting-qualification**. Source frozen at 2026-11-03T20:50:28.507636+00:00. This document records implementation and static review, not passed qualification or accepted performance results.

## Binding and scope

The frozen source is /home/qian/hepta-runtime-optimization-20261103-r14/source. The complete 219-entry source map is in implementation-ready.json (SHA256 efdc0a817aa4a9b80106a31b899678a4b7863523dd47e145f99b5d6ee2aa6442; 30,253 bytes). The 24,212-byte source-diff.patch has SHA256 d38b5fb5eac384086c202b5ba5730171a12e7bf605e1341259e6ef40ed796a77.

baseline-binding.json has SHA256 11b5996d6f18b3df2f2a0e804ed2b2e45980a52a50c6b28eeff99aadd7081d5f. It binds R13 qualification-03/report.json (fabf43fed5a839923b436ef370b70023cfef90e265d696b1095f37f31e24d0e9) and the R13 runtime (91baf096139002075ead3c2b9043ffe12269c155650c41bd4258efd3ac5ef364). R13 source and qualified binaries are preserved.

Only src/mcp/runtime/jobs.rs, jobs_cancel_io_tests.rs and jobs_cancel_read_tests.rs changed. Public schemas, persistence formats, remote protocol and dependencies did not change. cargo fmt --all exited 0; format-01.json is bound by SHA256 1ce8bc7094707795bbe44ca109621bf4ad4d5dc7c44182f36ebb25719b9deb23. The implementation agent ran no compilation, tests or benchmarks. Root owns the complete qualification and measurements.

## Publication capacity 8 and physical preparation capacity 2

MAX_CANCEL_PUBLICATIONS stays 8. MAX_CANCEL_PREPARATIONS is a new independent process-local semaphore with capacity 2. The actual cancel_job path supplies both pools to run_cancel_intent.

| Stage | Publication permit | Preparation permit | Meaning |
| --- | --- | --- | --- |
| Waiting for publication admission | Not yet owned | Not requested | No receipt work is submitted. |
| Waiting asynchronously for preparation admission | Owned by outer future | Not yet owned | Cancelling this unsubmitted waiter immediately returns publication capacity. |
| Blocking closure submitted, queued or running | Owned by closure | Owned by closure | At most two receipt-validation/intent-append closures are submitted, including blocking-pool queued work. |
| Successful blocking closure exit | Returned with original ownership | Released on actual exit | Preparation capacity becomes available before remote/completion work. |
| Remote response and completion audit | Existing continuation ownership | Not retained | Eight publication continuations remain possible. |

Both permits are acquired asynchronously before spawn_blocking. There is no synchronous semaphore wait inside the closure. The preparation guard covers prepare and append, remains physically owned after caller disappearance, and is not returned with the original publication permit and ownership.

Cancellation before blocking submission has no physical work to protect: the outer future drops its publication reservation. Cancellation after submission leaves both guards in the closure until it actually exits. If the closure result has no receiver, dropping that result releases its returned publication permit and ownership.

The two-slot budget is not a bound on all incoming request allocations, all Tokio blocking tasks or physical remote SSH operations that may outlive an outer caller under their existing transport owner.

## Why the permit covers prepare plus append

The selected scope keeps the complete existing blocking closure and its ownership transfer intact. append_audit_with uses one global AUDIT_LOCK, so eight cancellation writers waiting on that lock do not provide eight-way disk-append parallelism.

Limiting only check_operation_ref would reduce concurrent receipt parsing but would still permit eight queued/running append closures. It would need a separate append budget and explicit intermediate guard handoff to maintain a comparable physical-work bound.

There is a deliberate tradeoff: if both closures wait for a busy audit lock, later receipt validation waits too. The current wrong-host large-receipt workload fails before append. It can measure receipt concurrency; it cannot empirically distinguish validation-only from validation-plus-append scope. No audit-append performance gain is inferred from that workload.

## Error and ownership behavior

Original receipt errors still come directly from prepare. Failed preparation or failed intent append cannot start remote cancellation. Either closed admission pool returns the existing operation-intent-unavailable error, releasing any already acquired permit. A panic/join failure retains the established unavailable result and guard cleanup.

The return type remains the original publication permit plus ownership. R13's Arc binding and original receipt identity continue through the unchanged remote/completion path. No preparation wait is added after ACK; unavailable preparation capacity cannot downgrade ACK or an uncertain remote outcome.

These are code-review conclusions pending qualification. The test assertions below are preserved or added; they are not reported as passed by this document.

## Test coverage

| Test | Change or preserved assertion |
| --- | --- |
| cancel_intent_contending_for_real_audit_lock_keeps_executor_live_and_custody | Both guards remain held during real audit-lock contention and after caller cancellation; both pools drain after physical exit. |
| saturated_new_launch_capacity_does_not_block_original_cancellation | Preparation is independent of launch/start-outcome/observation/publication capacity and is free after preparation. |
| failed_or_closed_cancel_intent_never_submits_remote_cancel | Adds preparation_closed; retains redacted errors and zero remote effects, verifies no prepare entry on either closed pool and full recovery. |
| cancel_ack_is_owned_before_waiter_cancellation_with_all_publication_slots_reserved | Deliberately holds all preparation permits after preparation; ACK completion still proceeds with publication ownership. |
| slow_cancel_receipt_preparation_keeps_executor_live_and_original_bytes | Retains executor liveness, original bytes and errors; verifies one preparation permit while blocked and both free after return while publication remains held. |
| cancelled_receipt_preparations_queued_in_blocking_pool_keep_reservations | With one blocking thread occupied, eight outer requests yield two submitted closures and six asynchronous waiters. Aborting all returns six publication reservations; two physical submissions retain both guards. |
| invalid_cancel_receipts_keep_original_errors_before_intent_or_remote_effect | Retains exact errors, zero append/remote effects and no audit file; both pools recover. |
| public_cancel_reserves_original_capacity_before_reading_a_receipt | Exercises the actual public entry/global pools: publication is acquired first, neither blocked stage reads a receipt, and cancelling an unsubmitted preparation waiter returns publication capacity. |
| cancelled_intent_writers_retain_two_physical_preparation_slots | Replaces the old eight-writer bound test with two physical append owners and six asynchronous waiters; caller cancellation cannot admit a third physical writer early. |
| cancelled_receipt_preparations_keep_two_physical_slots_and_release_unsubmitted_waiters | Replaces the old eight-reader bound test: two physical readers, six returned unsubmitted reservations, exactly two reads/appends and zero remote effects. |
| two_preparation_slots_preserve_eight_publication_continuations | New: eight successful returned publication reservations coexist with both preparation slots free; a ninth waits without consuming preparation, then proceeds when one publication reservation releases. |

The last test proves eight helper continuation reservations, not eight simultaneous physical remote SSH operations. The read-test drain helper now takes the required permit count. Expected suite delta: one added nonignored test; ignored count unchanged. Existing exact error, ownership, real lock, actual public entry and executor-liveness assertions are not weakened.

## Measurement and adoption gate

R13's already generated summaries motivated this candidate: against R11, large escaped receipts showed whole-child VmHWM of about 5.19 times / 3.91 times and pooled CPU per measured mixed RPC about 56.27% / 45.20% higher at one / two executor workers, despite improved responsiveness. These are preliminary summary values; the independent raw reconstruction belongs to qualification_failure_audit. The input summaries and negative results were preserved in /home/qian/hepta-runtime-optimization-20261103-r13/preliminary-performance-summary.json.

R14 is not accepted from these R13 values or static correctness alone. Adoption requires complete qualification, matching source/binary binding, local and native campaigns and recovery checks. Root owns the final decision.

Cancellation CPU and throughput use measured pooled denominators, with warmup separate. Whole-child VmHWM differs from projection held-cohort RSS. Median per-process p95, a p95 merged from raw latencies, and pooled throughput are not interchangeable. Native ABBA/concurrency grouping and all negative changes must remain visible.

## Remaining optimization frontier

This is a bounded review under the current semantics, not proof of absolute optimality.

### Pin verification in multi-host observation

Static review of the normal warm path without master renewal counted three request-profile validations, each with two verify_files checks around the agent, each with worker and owner-acceptance full reads: twelve complete pin-set passes. Six pinned files mean seventy-two full content reads/hashes, not twelve individual file reads.

These checks implement phase-boundary change detection. Cross-call caching, skipping content rehashes or substituting inode/mtime/size cannot provide equivalent verification. Existing cases include content changes that preserve metadata and changes visible through shared mappings. The owner's post-await content check is part of the contract.

Immutable fixed-path preprocessing or hash-read buffer tuning might preserve semantics, but their benefit needs isolation from SSH and hashing cost. fixed_observation_preparation_abba measures fixed command preparation, not this full pin path. Its result cannot justify dropping content checks.

### Escaped JSON parsing

R13 reduces retained operation metadata; escaped strings still require decoding and temporary allocation. An allocation-free custom parser needs independent correctness evidence for Unicode escapes/surrogates, malformed input, bounded reads, field and duplicate/unknown-field behavior, errors and receipt binding. It is a new parser correctness project, not an established low-risk next optimization.

### Remote snapshots

Repeated request.json reads and directory checks might be optimized after profiling. Reusing a prior result changes replacement detection unless an explicit snapshot/generation contract makes reuse valid. A deeper remote snapshot protocol needs independent refusal and recovery evidence. It cannot be introduced as a cache while claiming unchanged phase-boundary behavior.

### Negative persistence experiments remain part of the evidence

Reviewed previous cases included two-pass streaming with roughly 64–205% CPU regressions, a one-buffer bounded writer with roughly 162–344% escaped-input CPU regressions and a two-buffer variant with roughly 6.32–21.32% regressions. These ranges belong to those original experiment cases, not R14. The selected single-pass capacity hint reduced plain-input Vec allocation; it was not a universal CPU/RSS improvement.

### Stop condition

If qualified R14 measurements demonstrate a worthwhile resource improvement while preserving acceptable latency/throughput, eight publication continuations and recovery behavior, this round can stop at that measured point and publish complete evidence including regressions. A correct candidate with material remaining regressions is not accepted merely because its tests pass.

Further work remains possible, but the candidates above require new profiling, parser correctness work or a revised remote snapshot contract. The final report should describe reaching this round's measured semantics-preserving frontier, with these explicit limits, and should not call the runtime absolutely optimal.

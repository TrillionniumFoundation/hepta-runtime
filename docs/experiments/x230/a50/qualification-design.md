# A50 bounded original-reader batches: design and evidence requirements

**Preparation only.** The following describes the frozen A50 source and the checks required for publication. Actual stage results, timing, compiler artifacts and post-format source hashes must be supplied from the final run; no A50 qualification or benchmark pass is asserted here.

## One change in how work reaches the original readers

A48's complete fixed large experiment observed higher CPU per attempt and substantially more voluntary context switches than r07, while still missing two candidate C4 deadlines. Those results motivate testing the per-record channel handshake as a source of overhead. They do not by themselves attribute every context switch to that handshake. A49's failed warmup trace placed almost all of that invocation's measured metadata-drain time in snapshot reading; it supplied no completed measured calls or C4 causal evidence. The original reports remain in the [A48](../a48/large-results.md) and [A49](../a49/results.md) sections.

A50 keeps two original reader threads and uses a fixed batch size of 32 records. For an entirely successful 65,536-record complete validation, this changes the structural request-plus-reply message count from 131,072 to 4,096. That arithmetic is not a measured throughput, CPU or memory improvement.

The coordinator selects a lane with `floor(submitted / 32) % 2`. Each lane has either a partial batch under construction or one outstanding queued, running or unconsumed batch. It cannot have both. The next batch for a lane may begin only after its previous complete reply is consumed. Including coordinator-side partial batches, the two lanes retain at most 64 original tasks. Backpressure occurs before decoding or cloning the next expected record.

This intentionally raises the task retention bound from A48's two records to at most 64. This is a task-count bound. Database views, pending entries, allocator overhead and the two existing original-read buffers remain separate. Actual wait4 peak RSS and measured CPU still require the frozen comparisons.

### Static memory accounting

The unchanged authoritative-record size limit is **2,048 bytes**. `Record` contains three owned strings plus scalar fields, has no collection field and rejects unknown JSON fields. Valid request IDs and owners are 64 ASCII hexadecimal characters; a valid tool name has 1–64 ASCII lowercase/underscore characters. The task also owns a 69-byte filename. Thus a **legal, validated** task has at most `64 + 64 + 64 + 69 = 261` bytes of effective string content. Sixty-four such tasks contain at most **16,704 bytes (16.3125 KiB)** of that content, versus 522 bytes for two tasks: an increase of at most 16,182 bytes of validated string content. These definitions are in the unchanged parent [request_audit.rs](https://github.com/TrillionniumFoundation/hepta-runtime/blob/a9ba701676138f7e379dab07b38af27c72c46ed8/src/mcp/runtime/request_audit.rs).

That calculation excludes `String` capacity, task/Entry/stamp headers, allocator overhead, decoded temporary objects and the existing database/pending view. The compact cache codec constrains tool length and expands fixed-size IDs, but its legacy non-MAGIC path directly deserializes JSON without uniformly applying those validity checks in `decode`. Consequently the 261-byte calculation is **not a bound on arbitrary damaged-cache decoding or RSS**, and the authoritative-file limit must not be generalized into a bound on every cache allocation. See the unchanged [request_archive_codec.rs](https://github.com/TrillionniumFoundation/hepta-runtime/blob/a9ba701676138f7e379dab07b38af27c72c46ed8/src/mcp/runtime/request_archive_codec.rs).

Normal database admission supplies additional checks: `cached` runs the codec/cold upgrades, the cold row/fingerprint scan and complete original-content validation before returning a `ValidatedDatabase`. A newly built database instead reads authoritative records and writes them through `apply`. The worker folds pending publications through `apply` before assigning the database to ready state. New cache rows use the compact codec, and `PendingView` checks identity/tool counter keys before retaining a changed pending Entry. This review found no normal RPC path that admits an oversized legacy row into the ready database. These admission and publication paths are in the unchanged [request_archive_index.rs](https://github.com/TrillionniumFoundation/hepta-runtime/blob/a9ba701676138f7e379dab07b38af27c72c46ed8/src/mcp/runtime/request_archive_index.rs).

The existing `Fingerprint::row` limit is 4,096 bytes. It is applied before compact-view decoding in the cold row scan, but the legacy upgrade can copy and deserialize an old raw row before that guard. An abnormal cache image could therefore allocate during attempted migration before it is rejected; no normal RPC creation path or working damaged-cache reproduction was established here. A uniform pre-parse cap, including before an upgrade's raw copy, is a separate follow-up. This is an existing resource-boundary inconsistency, and does not establish a new A50 correctness regression or justify replacing the frozen normal-workload comparison. No A50 source or test was changed for this review.

The batch Vecs request storage for at most `64 × size_of::<OriginalTask>()` elements in total; actual allocator slack remains separate. Each task borrows its directory descriptor, so 64 tasks do not create 64 additional file descriptors. The two original readers still use one 2,049-byte authoritative-read array each, **4,098 bytes total**. `mem::take` transfers each full/partial Vec to its reader, and a later new batch calls `reserve_exact(32)` again: a successful 65,536-record pass therefore has **2,048 batch-Vec allocation cycles**, rather than two permanently recycled Vecs. This is a static accounting of the prepared implementation, with no claim of lower measured RSS.

## Complete observation and original custody remain required

Every task retains its own archive/directory references, filename, complete expected Record and stamp, global record number and unchanged absolute deadline. A batch may span different shard directories without replacing those per-record descriptors. Before and after each record, the worker checks cancellation and the same absolute deadline. It validates the contiguous task sequence and refuses a task with an extended or otherwise changed deadline.

The reply separates the original `(first, count)` envelope, the successful prefix and the original result. The coordinator first checks the envelope, then propagates an original read error with its source chain. It credits the batch only if the result succeeds and its verified prefix equals the full count. A shorter prefix, a wrong count or a stale identity cannot become complete coverage. A worker read failure stops that batch's suffix without setting global cancellation ahead of delivery and obscuring its original error.

`finish` dispatches a nonempty partial tail through the same reader path, receives all replies, checks complete coverage and joins both original threads before the existing terminal namespace fences. Error, cancellation and unwind cleanup discard any unsubmitted partial batch; they never flush it into new I/O. The existing join loop still consumes the actual scoped handles, preserves the original panic/guard-poisoning semantics and does not return while child I/O remains active.

The complete original-read function, descriptor policy, Record/stamp comparisons, serial verifier and cold-validation suffix remain byte-identical to A48. The parallel DB/ORDER/pending-view joins and terminal namespace checks remain present. A50 changes neither the fixed 1 ms collection window, 3 s product metadata deadline, eight metadata permits, large-row threshold nor the small/cold serial selection.

## Prepared test coverage

All 14 original tests in the parallel-reader test file remain, as do the 13 A48 required test basenames. Six new tests cover exact full/partial boundaries, original failures at batch positions 0/15/31 with a held second reader, producer cancellation with an undispatched tail, forged or repeated reply envelopes, malformed task sequences/deadline extension, and per-record descriptors across shard boundaries.

The existing held-child error/panic/deadline tests now fill two actual 32-record batches and hold records 0 and 32. A test-only cancellation event makes suffix assertions deterministic. The existing capacity test checks that record 65 cannot enter while both batches remain unconsumed. The existing final-namespace-fence and warm off-page tests now use 33 records so a full batch and a second-lane tail both participate.

The expected Linux top-level shape is **18 + 1,246 + 8 = 1,272 passed, 23 ignored**, only if the full original test run actually produces those summaries. Two existing nested filtered child summaries must remain visible and must not be added to that total. The 19 required basenames are a separate coverage condition. Three inherited basenames exist in both archive and usage modules, so the number of matching success lines can exceed 19. The [qualification contract](qualification-contract.json) lists every name and exact checks.

## Final qualification and source binding

The new qualification must independently execute format, fmt-check, clean-package, strict all-feature/all-target clippy, full tests and release. Preserve the original two Cargo jobs, two test threads, two Tokio workers, incremental-off configuration, fresh complete resource gates and fixed stage/worker/outer budgets. An earlier parent success cannot stand in for a new A50 stage.

Before writing a successful qualification section, verify the final ordinary report, entry and worker schemas and SHA identities; all six actual stages and guard receipts; original worker raw wait completion; unchanged parent/reused-input flags; source-bound compiler events with `fresh` strictly false; and copied artifact identities. A launch receipt or an expected test count is insufficient.

The actual 168-file maps must satisfy:

```text
qualification.source_tested == qualification.source_after == entry.source_after
```

`qualification.source_input` and `entry.source_preformat` instead identify the frozen prepared input map. Formatting may alter the two candidate files; its actual output must be exported and used for publication. Recompute all 168 source-body SHA-256 and Git blob identities, export the two changed bodies exactly, and compare the other 166 rows with the already published A48 object proof before the final non-force Git update.

## Readback scope

The read-only publication helper has a narrow `export-source` command: it reads the three final reports and every source body, checks source inventory/stat9 before and after, and emits a compressed JSON transport containing full hash/Git-identity rows plus only the two changed bodies. It does not read ELF or stage-log bodies, run a build/runtime, change services, access the network or write files. The caller supplies the three already reviewed final report SHA values.

The separate local review command rehashes downloaded report/test-log bodies, checks the actual 19 test basenames and top-level summaries, verifies the exported source against the published parent object map, and writes exact changed-source copies to a new local review directory. Its output explicitly excludes credential review, performance adoption, GitHub tree readback and unobserved artifact-body readbacks. Root performs those remaining publication steps separately.

The A48 historical test ELF is bound by the pinned parent report/compiler evidence; the parent proof does not rehash its body. Current A50 artifact SHA values are calculated by the original qualifier when it copies and reads those new artifacts. The worker's strict-fresh postcheck ties compiler events, copied-artifact declarations and reports together; it is not a second artifact-body rehash. Any later benchmark-loader or explicit body readback is a separate observation that needs its own receipt.

All actual A50 outcomes remain to be inserted after the original evidence arrives. A failed qualification or comparison must remain a failed result in the published history.

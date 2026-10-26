# A43 owner publication barrier: independent experimental source

**Validation checkpoint: 2026-10-25 21:55 EDT (2026-10-26 01:55 UTC).**

This private experimental branch builds on the [r07 recovery
parent](r07-recovery.md). It does not include A42 archive-cohort changes. It
reduces the nominal owner-publication directory barriers while preserving both
owner-file syncs before business launch. Publishing this source is not adoption,
deployment or merge. This candidate has not run qualification at this checkpoint.

## Source and intended sequence

The prepared preformat source set contains 166 files, with canonical source-map
SHA-256 `80a73b1f41c886c8b7d3d08d8cc6f99356729f979a707bf943bf675592222b6f`.
The shared recovery-parent map is
`4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d`.
The preformat identity is intentional: no candidate-specific format, Clippy,
test or release result is claimed. Any later formatting or source change will
need its own identity and validation record.

Only these three source files differ from that parent:

- `src/mcp/runtime/jobs.rs`
- `src/mcp/runtime/jobs_output_durability_tests.rs`
- `src/mcp/runtime/jobs_owner_publication_tests.rs`

Each owner-intent and started record retains exclusive no-follow creation,
complete write, flush, file sync and close. After both records complete, the
supervisor synchronizes its already pinned job-directory descriptor once.
The unchanged business-process launch boundary follows that shared barrier.
The original lifetime owner lock remains held.

| Owner-publication segment | R07 | Candidate |
| --- | ---: | ---: |
| File syncs | 2 | 2 |
| Directory syncs | 2 | 1 |
| Extra directory opens | 2 | 0 |
| Extra directory closes | 2 | 0 |

These are nominal explicit operations in the implementation. Kernel retries
and platform details can change actual counts. They are not measured timing,
throughput, CPU or memory improvements. No new SSH round trip, cross-job batch,
queue, resource limit or retry mechanism is introduced.

The guarantee concerns the business-effect boundary. The existing macOS
supervisor-identity helper may run before owner publication; this design does
not claim that every platform creates zero helper children before the barrier.

## Failure and recovery behavior

Any create, write, flush, file-sync, close or final directory-sync failure
propagates before business launch. Surviving owner names remain tombstones,
including empty or malformed records; a fresh supervisor must not parse-fail
its way into a second business execution. The first create can fail before
any owner name exists. That case relies on the existing outer synchronized
request binding and ambiguous-prior-launch refusal, not an invented tombstone.

The shared barrier removes the earlier intermediate point where only the first
owner name had a completed directory sync. Before the common barrier returns,
no business process has been submitted. After it returns, both file syncs and
closes preceded the directory sync. The unchanged later child receipt, output
barriers, exit record and exit witness retain their original order. Missing
actual child-exit evidence remains Unknown with no automatic retry.

## Actual scheduling outcome and unexecuted qualification

The A44 owner-candidate scheduling window ran from **21:37:34 to 21:47:34 EDT**
on October 25, 2026 (01:37:34 to 01:47:34 UTC on October 26). It completed its
600-second window with 20 discrete samples at 30-second intervals. Every sample
contained a live unrelated Cargo/rustc pair; **0 of 20 samples were clear**.
Four samples also fell below the 2 GiB available-memory floor. The observer
terminated with the recorded no-clear outcome and exit 2, without timeout or
cancellation. Discrete samples do not prove that every instant was busy.

The owner qualification entry was **never invoked**. Candidate-specific format,
Clippy, tests, release compilation and native performance validation therefore
remain **unexecuted**. The r07 parent's passing tests do not qualify these
changed files, and A42's distinct source and runtime results are not combined
with this candidate.

Seven new Rust tests are prepared but **none of those seven tests has run**.
They comprise 22 initial cases and 20 fresh-interpreter tombstone checks. They
exercise actual file operations and independently opened locks while
intercepting the business `Popen` boundary. Cases include partial writes and
owner names, flush/sync/close failures, the directory barrier, controlled
interruption cuts and lock exclusion. These are intended fixture coverage,
not executed results.

Reaching an intercepted launch boundary is not business-child execution.
Controlled exception cuts are not SIGKILL or power-loss tests. These tests use
the Linux-only parent test module; a future Linux pass would not establish
native macOS acceptance. Final release same-key native canaries and multi-host
controller recovery remain separate validation stages.

At this checkpoint, the separate A45 read-only release scheduling observation
for A42 is **in progress**. It has no terminal result and supplies no new
qualification or runtime validation for A43. A later owner experiment requires
its own admitted execution and recorded outcome. The completed A44 refusal
remains preserved and does not establish that all optimization is exhausted.

| Retained record | Bytes | SHA-256 |
| --- | ---: | --- |
| A44 owner scheduling report | 28,797 | `196e418a9e7d15010798f9c899ffc7e0966a5ef8f98f65d688cc1d758280e7b2` |
| Independent review of all 20 original snapshots and terminal record | 17,732 | `647277f75e2279d33a5acc1060208228d9be71f9e7a32d2703611dbf0dc12e3f` |

Operational process snapshots and executable bodies are retained separately;
this branch contains the reviewable source and this validation statement.

## Measurement and adoption

Qualification alone does not establish a performance gain. A fixed comparison
against the exact r07 release must measure complete work, including actual
business start and terminal completion, every failure, CPU and RSS under the
same deadlines and resource limits. Submission acknowledgment alone may occur
before the changed owner barrier and can miss the intended effect.

No global exactly-once business guarantee, reboot or power-loss guarantee is
claimed. Combining this candidate with A42 creates a new source tree that
requires independent qualification and acceptance.

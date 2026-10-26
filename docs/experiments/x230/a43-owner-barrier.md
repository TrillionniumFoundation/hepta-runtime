> **Current status — 2026-10-26 UTC:** A43 has passed all six X230 A46
> qualification stages (1,241 tests passed, 23 ignored) and A47's 10 correctness
> cases plus all 128 measured local business jobs. This does not establish a
> stable performance or memory improvement. See the [current A46/A47 results](a43-a46-a47-results.md)
> and [summary](a43-a46-a47-summary.json), including original archived evidence.
> The original unqualified checkpoint below is retained at its historical date.

---

## Historical checkpoint - original document retained verbatim

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


## A46 qualification and A47 real owner-lifecycle update — 2026-10-26 UTC

The earlier preformat/unqualified checkpoint and its no-clear observations
are preserved. A separately admitted A46 attempt subsequently executed all
six qualification stages on X230, from **03:29:15.471 to 03:43:18.853 UTC**.
Format, format check, package clean, strict Clippy, all-feature tests and release
all returned 0. Every stage retained its own complete 2 GiB memory/disk gate,
two jobs/workers/test threads and the original budgets; the original worker
was raw-reaped with status 0 and retained custody.

The complete test inventory is **1,241 passed, 0 failed, 23 ignored**
(18 + 1,215 + 8); the two filtered child summaries are not counted twice.
All seven new owner-publication tests executed successfully. Test and release
artifacts were strictly `fresh=false`. Only `jobs_owner_publication_tests.rs`
changed during format. The final **166-file** tested map is
`b9eaddec7cb30de7e18f2131bebeee98145e3d41e00243b13ec50f6fe01c0d9b`.
The 13,497,648-byte release copy has SHA-256
`60f6955cc77a07b5a95b24c175611a59901c7d912abfb960f7c8673e472354f7`.
The r07 parent remained unchanged; A42/A48 changes are not included.

A47 then completed **10/10 declared local correctness cases and 128/128 measured
jobs** in fixed r07/A43/A43/r07 order, with 32 jobs per version at each of C1
and C4. Normal cases executed real business `Popen`, preserved exit 0 and exit
7, and reached confirmed durable terminal publication. Six real SIGKILLs,
three cuts per version, occurred after owner-intent close, started close or
the final owner-directory sync, all before business launch. Bound original
pidfds and raw wait4 status 9 (decoded return code −9) established the kills.
Restart and ambiguous same-key relaunch were refused, with no second business
effect. No unexpected
failure, measurement timeout, retry or unexecuted slot occurred.

| Pooled r07 → A43 observation | C1 | C4 |
| --- | ---: | ---: |
| Completed jobs/s | 6.787901 → 6.835106 (+0.695%) | 15.337808 → 15.548363 (+1.373%) |
| Whole-lifecycle supervisor wait4 CPU | 4.229883 → 4.186100 s (−1.035%) | 6.185351 → 6.361896 s (+2.854%) |
| Median submit → business completion | 119.925 → 118.746 ms (−0.983%) | 182.631 → 188.244 ms (+3.074%) |

The A47 pass means correct, complete execution, not a performance-superiority
gate. This one fixed ABBA does not establish a stable performance gain.
Wait4 RSS maxima increased strictly across all eight cells and A43 occupied
the middle rounds, so the lower pooled candidate maxima are not attributed
to memory optimization. Both original file syncs remain; the pre-business
directory barrier count changes from two to one as a structural fact.

This comparison executes exact Python owner-path code extracted from the
qualified sources with isolated Linux effects. It does not establish full
MCP, SSH, multi-host, macOS, reboot or power-loss acceptance, or recovery after
partial business effects. Previous CI records remain historical. Full
stage/case/cell details and retained SHA-bound evidence are in
[A46/A47 results](a43-a46-a47-results.md) and the
[machine-readable summary](a43-a46-a47-summary.json).

The complete qualified-source Git-object proof also binds this publication:
165 of the 166 prepared-source blobs stay identical to the checkpoint, and
only the formatted owner-publication test changes. The five captured original
qualification/lifecycle report and log files are archived losslessly with
original and compressed SHA-256 identities; their owned fixture metadata and
synthetic identifiers contain no authentication credentials or private keys.
The results document links the archive, source proof and read-only recomputation
helper, and identifies referenced sidecars that are not bundled.

> **Current follow-up, 2026-10-26 UTC — A50:** [Bounded original-reader batches](a50/README.md) passed all six fresh qualification stages (1,272 passed, 23 ignored) and all six fixed small-archive regression gates. The large ABBA attempt is **failed and incomplete**: 60/80 measured attempts, 46 successes, 14 failures, 20 unexecuted; candidate C4 is 30/32. The final baseline's one fixed warmup failed, so partial ratios are not accepted as performance gains. [A50 full results](a50/large-results.md), [A49's retained failed diagnostic](a49/results.md), and [next evidence/design boundaries](a50/next-steps.md) preserve all failure states. No adoption, native multi-host acceptance, deployment or absolute optimization limit is claimed.
>
> The earlier A48/A46/A42 checkpoint follows verbatim as history.

> **Current follow-up, 2026-10-26 UTC:** A48 completed a new six-stage qualification (1,266 passed, 23 ignored) and passed the fixed small-archive guard. Its complete large comparison failed C4 correctness and two CPU gates. See [A48 results](a48/README.md), the [retained A46 comparison](a42-a46-release-small.md), and [current multi-host admission](native-auth-20261026.md). The original checkpoint below is retained verbatim. Neither candidate is presented as an adopted performance gain.

# A42 fresh archive cohorts: tested source, release admission pending

**Validation checkpoint: 2026-10-25 21:55 EDT (2026-10-26 01:55 UTC).**

This private experimental branch contains the actual formatted A42 revision-03
source. It is available for review with its complete failed and unexecuted
validation state. It has not produced a new qualified release or a new
performance result, and it is not deployed or merged. Scheduling observation
continues; later outcomes require a separately recorded update.

## Change and source identity

The candidate builds on the [r07 recovery parent](r07-recovery.md). It changes
five archive-related files above that parent:

- `src/mcp/runtime/request_archive_batch.rs`
- `src/mcp/runtime/request_archive_batch_tests.rs`
- `src/mcp/runtime/request_archive_index.rs`
- `src/mcp/runtime/request_archive_page_batch_tests.rs`
- `src/mcp/runtime/request_audit.rs`

A bounded coordinator collects eligible already-admitted archive page queries
for a fixed 1 ms window. Membership freezes before a new complete observation
starts; no prior result or content lease is reused. Collection time remains
inside each request's original absolute deadline. Each member has its own
result slot, owner/page checks and original blocking-worker custody. Tests
cover freshness, membership, failure and deadline behavior.

| Identity | Value |
| --- | --- |
| Complete source files | 168 |
| Actual formatted/tested source-map SHA-256 | `c1ae8a69901aee16e03871e920a6a7e321672c9b30b3a6e75d3560390b8c2e11` |
| Shared recovery-parent map | `4da4bae757abb1e31b250efb406e62fab32a6a0bd537f9642911ddf8b4d3000d` |
| Test executable SHA-256 | `bf4f3fecfda0fb78cebaac83c7f154c3410371dee1f25172ebf92596aa33275a` |

The separate A43 owner-publication experiment is not included. A combined tree
would need a new source identity and independent qualification.

## Qualification and release-completion outcome

The original revision-03 qualification on X230 Rust 1.95.0 passed format,
format check, package-cache clean, strict all-feature/all-target Clippy and
all-feature tests. **1,264 top-level tests passed, 0 failed and 23 were ignored.**
All 30 new A42 tests passed exactly once. Nested subprocess summaries are not
counted again. Some top-level ignored entries are subprocess-only helpers
invoked by passing parent tests; these totals do not claim execution of the
ignored remote integration or manual benchmark suites. The original release
gate refused to start Cargo because a separate compilation was active, so that
qualification remains failed with zero release executions.

On **2026-10-25 EDT**, a new bounded scheduling observation obtained a clear
sample. A separately recorded release-only completion entry then reached its
own immediate gate at **21:30:46 EDT** (2026-10-26 01:30:46 UTC). That gate saw
an already active, unrelated Cargo/rustc compilation and refused to launch
release Cargo. Available memory and disk exceeded their declared floors.
A clear point observation was not an exclusive reservation.

| New release-only attempt, revision 02 | Actual result |
| --- | --- |
| Qualification worker invocations | 1 |
| Release Cargo executions | **0** |
| Release compilation log | 0 bytes |
| Original worker exit | 1; authoritative raw wait status retained |
| Original worker custody | Retained through actual reap; original group quiet before reap |
| Signals, timeout or cancellation | None |
| Native benchmark executions | **0** |

This was a busy-host refusal, not loss of the original worker's custody. The
wrapper's overall success predicate requires exit 0; its generic failure
wording does not supersede the concrete successful custody/reap record.
The source remained equal to the original actual-tested 168-file map throughout
the captured before/after checks. The failed original qualification was not
rewritten, and no release or benchmark success is inferred from these checks.

## A45 continuation at this checkpoint

A new read-only scheduling observation started at **21:54 EDT** on October 25
(01:54 UTC on October 26). Its state at this checkpoint is **observing**, with
no terminal outcome. It allows up to 1,800 seconds of passive observation at
30-second intervals, retains the same busy-process and 2 GiB available-memory
and disk gates, and launches no Cargo or native benchmark automatically.
The longer scheduling window does not extend any product, test or release
deadline. No new release entry or benchmark had run in A45 at this checkpoint.

Any later clear sample still requires a separately bound release entry and its
own immediate admission gate. Prior failures remain intact. No final no-clear
result, fresh release, benchmark pass or completed optimization claim is inferred
from an in-progress observation. Current multi-host acceptance is also limited
by the latest failed agent preflight recorded in the recovery-parent document.

## Evidence identities

| Retained record | Bytes | SHA-256 |
| --- | ---: | --- |
| Original revision-03 qualification | 40,283 | `b7374df702c477f394b5f3ba2ed94337daa23f8dde54fb38370df6b2d5172b6d` |
| Original full test log | 420,430 | `824af67bd04ed494599cf6078558565e08821b79895f3a035a669dc7cbd9ee96` |
| Release-only revision-02 worker report | 221,571 | `8570cf262e8d5a30aa4fdadd88dd842fbb1b6b737c15528ae4d1f8942ddf256d` |
| Release-only revision-02 entry report | 186,023 | `ac3b0c077102e2d71f0ec7ea4452425a41101d635e2737ec9b3c1390be5b63d7` |
| Immediate release host-gate record | 59,806 | `a8f3491f14fd9391bc4014996efa921356a3094a2c34e2b33924b94335c7c9c1` |

The complete operational records remain with the retained evidence. This
documentation publishes identities and findings without adding machine process
snapshots, credential data or executable bodies to this source branch.

## Performance and adoption limits

The fixed pending comparison uses r07 as baseline. Passing the small C1 gate
would establish compliance with its stated wall/CPU/RSS guard, which allows up
to 10% wall/CPU growth; it would not by itself establish a speedup. Passing the
large C4 experiment would support only its direct r07/A42 workload comparison.
A net improvement over published A40 requires a fresh direct A40/A42 comparison.
Historical ratios cannot be multiplied into a new measured result.

Four pending client request IDs do not prove concurrent server admission or
membership in the same cohort. No new throughput, CPU, RSS, sustained-load or
multi-host recovery result is claimed. An admissible release window, an actual
fresh release and all fixed benchmark gates remain required before performance
adoption. The current inability to complete those steps does not establish a
global optimization limit.



## A46 subsequent evidence — 2026-10-26 UTC

The dated checkpoint above remains preserved. A separate A46 attempt has now
completed the source-bound release and passed the fixed small C1 regression
guard. The large C1/C4 comparison completed all 80 measurements; C4 improved
from 8/32 to 30/32 correct responses, but two candidate deadline failures
prevented adoption. See [A46 release and complete archive evidence](a42-a46-release-small.md) and its
[machine-readable summary](a42-a46-summary.json). The original release refusals
and A45 `no_clear_observed` remain retained. A46 is a complete failed adoption
comparison, not a successful subset or a replacement for the older records.


## A48 follow-up

The exact qualified A48 source and the complete failed large comparison are recorded in [the A48 result index](a48/README.md). A separate bounded diagnostic and a possible record-batch candidate cannot replace or be pooled into either historical failed comparison.

# X230 A50 bounded original-reader batches

**A50 passed its complete six-stage source qualification and small-archive regression guard on X230. The large fixed comparison failed and is incomplete; no performance adoption is claimed.** The final run completed on 2026-10-26 at 06:02:20 UTC. The original full test run reports **1,272 passed, 0 failed and 23 ignored**. Its exact post-format source, final report identities and full 168-file Git object proof are available below. Qualification success alone does not establish a throughput, CPU or RSS improvement.

| Evidence | Current status |
|---|---|
| [Actual qualification summary](qualification-summary.json) | All six stages passed; raw original-worker completion and report/source bindings checked |
| [Full tested source map](source-tested-map.json) | All 168 paths; actual post-format map `5728b8a5d2beef13a218c08cc8c30ea3feb99f0ec36277e1b7efee41c098a95c` |
| [Git object proof](qualified-git-object-map.json) | Every qualified source body was hashed on X230; 166 unchanged parent objects and two exact changed bodies |
| [Source export manifest](source-export-manifest.json) | Report receipts, export proof, local review and exact source publication paths |
| [Design and evidence requirements](qualification-design.md) | Preserves the frozen design and preregistered expectations; actual observations are in the qualification summary |
| [Machine-readable qualification contract](qualification-contract.json) | Expected schemas, 19 required test names and counting rules; kept separate from actual results |
| [Small fixed comparison](small-results.md) | 8,192 measured / 8,848 total calls correct; all six regression gates passed; no observed small-workload speedup |
| [Large fixed comparison](large-results.md) | Failed and incomplete: 60/80 measured attempts, 46 successes, 14 failures and 20 unexecuted slots; candidate C4 30/32 |
| [Next evidence and design boundaries](next-steps.md) | Cohort timing and submission ownership need additional evidence; no absolute optimization ceiling claimed |

## Fixed comparison outcomes

The small comparison retained both opposite-order blocks and all eight rounds. Against r07, A50 measured wall time was 33.292333194 s versus 32.519600830 s (**+2.376%**), and observed CPU was 29.08 s versus 28.37 s (**+2.503%**). The conservative CPU ratio was 29.24 / 28.21 = **1.036511875**, below the fixed 1.10 guard. Whole-round original wait4 peak RSS was 34,900 versus 34,880 KiB. These 64-record runs did not enter the large parallel reader path and do not isolate A48-to-A50 effects.

The large ABBA attempt ran from 06:10:23 to 06:22:11 UTC. Controllers 0/A, 1/B and 2/B completed their fixed inventories; controller 3/A failed its single fixed archive warmup after the prescribed 60-second idle. That warmup returned `archive index preparing or validation unavailable` after about 3,001.672 ms. Its 20 measured slots were never attempted, and there was no readiness retry.

Both A50 controllers completed all 40 candidate measurements: C1 **8/8** and C4 **30/32**. The two C4 errors were controller 1, wave 4, slots 25/26 (`first_32`, `quarter_16`), each reporting the original total deadline near 3,002 ms. Across the entire attempted comparison there were 60 measurements, 46 successes and 14 failures, plus 20 explicitly unexecuted slots. All four original controllers were reaped through their actual wait4 receipts and all four original fixture checks remained true; the new outer custody fallback was never used.

The baseline CPU aggregate is null because its second controller never reached measurement. The original report's partial wall/rate ratios and whole-life resource observations are preserved for inspection, **not accepted as a balanced A/B benefit**. Its overall result is `complete=false`, `passed=false`, `performance_adopted=false`. Some aggregate proof gates also remain false because complete fixed coverage or the final whole-run receipt sweep was not reached; that does not mean an actually captured host/source/child receipt failed. The detailed [large results](large-results.md) distinguish those scopes.

## Actual qualification

| Stage | Exit | Recorded duration |
|---|---:|---:|
| Format | 0 | 2.354 s |
| Format check | 0 | 1.969 s |
| Clean package | 0 | 0.383 s |
| Strict clippy, all features and all targets | 0 | 48.774 s |
| Full tests, all features | 0 | 507.360 s |
| Release build, all features and binaries | 0 | 311.634 s |

Every stage ran once after its fresh host gate cleared. The original limits remained two Cargo jobs, two test threads, two Tokio workers, incremental compilation disabled, 1,800 seconds per stage, 6,600 seconds for the guarded worker and 7,000 seconds for the outer attempt. The original worker was retained through its actual `waitpid`, with raw status 0, no signals, and no live member in its process group before reap. Parent inputs and reused dependencies remained unchanged.

The top-level test summaries are **18 + 1,246 + 8 = 1,272 passed**. The two nested filtered child summaries remain in the original log and are excluded from that total. All 19 required test basenames have successful lines; three inherited names occur in two modules, yielding 22 matching lines. Both the test and release compiler events report `fresh=false` and point to this exact A50 source directory. The copied release SHA-256 is `01a8dfaf79e10c245e371f435998591147c39350e2a191caecb1a79d0536e2a0`.

## Exact source to publish

The actual tested compact map is `5728b8a5d2beef13a218c08cc8c30ea3feb99f0ec36277e1b7efee41c098a95c`. The frozen prepared map remains `e348cb3fb70a1d9dde8f97d722e65052c2ffba7807d409a2c822d75c314f4dd0`. Both changed files were formatted during qualification, so the prepared overlay must not replace the actual exported bodies.

| Changed source | Actual SHA-256 | Git blob |
|---|---|---|
| `src/mcp/runtime/request_archive_content.rs` | `720c992a407fbe1bb3fa4ff9918d0772b4187065f848da947aa2fa96eb7a297a` | `1c2b4b04384a15d491bdb121c1280f414dbb29a2` |
| `src/mcp/runtime/request_archive_content_parallel_tests.rs` | `1db236fe1188c86280ee76acd2628d3c3530451f0a5ca71a50a667610d058376` | `73fdf6d020ef852d503643b4b0ed97619fc8ab70` |

The other 166 source files and Git blobs match the actual [PR71 A48 parent a9ba701](https://github.com/TrillionniumFoundation/hepta-runtime/commit/a9ba701676138f7e379dab07b38af27c72c46ed8), whose compact qualified map is `be631e20eb7ec586c77807bb4e38b6529c5cda1fcc906eb1fac20f793c8c0ff1`. The source exporter read all 168 bodies on X230, checked their SHA-256 against the final qualification and checked source inventory/stat9 before and after. It exported only the two changed bodies. The local reviewer rehashed those bodies, recomputed their Git identities and compared the complete map/object proof with that parent.

The [source manifest](source-export-manifest.json) identifies the exact source-review paths to use for publication. The published map JSON has its own file SHA-256; it is distinct from the compact-map hash. Final GitHub tree readback and compare-and-swap publication are separate steps.

## Scope and retained history

A50 groups the existing two original readers' messages into batches of at most 32 records per lane. Coordinator partial batches and outstanding batches are mutually exclusive per lane, preserving a maximum of 64 retained tasks, with backpressure before the next expected-record decode. Every record still receives its original full Record/stamp verification, cancellation/deadline checks and original-thread cleanup. This raises retained task count from A48's two; it is not evidence of lower memory usage. The design document explains the narrower validated-string accounting and the existing legacy-cache parsing caveat.

The original reports and source bodies remain unchanged. This local publication review rehashed the downloaded qualification, entry, worker and test-log bodies. It did not independently read the ELF bodies, release-log body or raw host-gate bodies; their original qualifier/worker receipts remain identified in the summary. The source export itself performed no build, benchmark, service change or GitHub operation.

The [complete A48 large comparison](../a48/large-results.md) remains failed. The [A49 diagnostic](../a49/results.md) also remains failed: warmup did not complete and its 20 measured slots were unexecuted. Their results supplied motivation for this candidate and do not count as successful A50 performance evidence. The [prequalification README](README.prequalification.md), frozen design, contract, source overlay and preparation receipts preserve the earlier expected-versus-observed distinction.

The small and large A50 comparisons retain their fixed schedules, original numeric gates and every failed or unexecuted call. The incomplete large result and two candidate deadline errors prevent performance adoption. The next source candidate requires the additional observations and ownership design in [next steps](next-steps.md). The independently qualified A43 owner-barrier work in [PR72](https://github.com/TrillionniumFoundation/hepta-runtime/pull/72) remains a separate source branch. This qualification does not establish multi-host acceptance, SSH-agent behavior, power-loss durability, production deployment or optimization exhaustion.

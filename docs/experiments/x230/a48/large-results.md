# A48 large archive: complete failed comparison

**The formal large ABBA comparison failed.** All four controllers completed all
80 measured attempts: 54 succeeded and 26 failed, with no unexecuted slot or
retry. A48 reached 30/32 correct C4 replies, below the required 32/32, and failed
both the C1 CPU/attempt and C4 inclusive CPU/attempt regression gates. The
small pass and higher C4 successful-call rate do not override these failures.
No performance adoption or production deployment is established.

The unchanged original report is **247,764 bytes**, SHA-256
`8c0377e52d930d93597f7b4e551d68101a29bffe6dd9aaa3d9bcdf22a036215f`. It spans `2026-10-26T04:11:50.046383+00:00` to
`2026-10-26T04:24:09.479384+00:00`. Protocol SHA-256 is
`5a3c8e814b3614d1c6729d474a38571e517ef0bc603690a104288576ca3afd8e`. [large-summary.json](large-summary.json) retains all 80 slot
outcomes, every failed measured row, all twelve setup calls including all four
failed kickoffs, every numeric gate and the independent recomputation.

## Complete inventory and failure classification

| Controller | Actual source | C1 correct | C4 correct | Measured failures |
|---|---|---:|---:|---:|
| 0 | r07 | 4/4 | 4/16 | 12 |
| 1 | A48 | 4/4 | 14/16 | 2 |
| 2 | A48 | 4/4 | 16/16 | 0 |
| 3 | r07 | 4/4 | 4/16 | 12 |

r07's 24 measured failures comprise **23 preparing/validation-unavailable
responses and one total-deadline response**. A48's two measured failures are
both total-deadline responses in controller 1, wave 6: slot 33 (`tail_32`) and
slot 34 (`first_1`). All measured failures are `request_archive` product
responses received after one write attempt; they are not omitted or treated
as unexecuted transport errors. The second A48 controller's 16/16 C4 result
is retained alongside the first controller's 14/16 and is not selected alone.

All four native seeds and four fixed archive warmups succeeded. **All four
`usage_stats` index kickoffs failed with the total-deadline response.** These
are setup failures, kept separate from the 80 measured slots but retained in
the formal result: `all_setup_queries_successful=false`. Across measured and
setup tool calls, 62 of 92 succeeded and 30 failed.

| Controller | Source | Kickoff tool | Response elapsed ms | Failure |
|---|---|---|---:|---|
| 0 | r07 | usage_stats | 3002.483581 | total deadline |
| 1 | A48 | usage_stats | 3002.246829 | total deadline |
| 2 | A48 | usage_stats | 3001.409739 | total deadline |
| 3 | r07 | usage_stats | 3002.141651 | total deadline |

## Numeric outcome with all failed attempts retained

| Mode | Source | Correct / attempted | Sum of wave wall s | Observed scoped CPU s | Successful calls/s |
|---|---|---:|---:|---:|---:|
| C1 | r07 | 8/8 | 17.554973 | 17.550000 | 0.455711 |
| C1 | A48 | 8/8 | 15.200376 | 32.810000 | 0.526303 |
| C4 | r07 | 8/32 | 24.029057 | 24.087558 | 0.332930 |
| C4 | A48 | 30/32 | 16.389460 | 35.386045 | 1.830445 |

C1 CPU is the controller `/proc` difference between the pre-C1 and pre-C4
endpoints. C4 CPU is **inclusive through original wait4**: whole-life utime plus
stime minus the pre-C4 cumulative CPU. It includes remaining work, final
verification and shutdown; it is not exact pure-C4 CPU. Failed attempts remain
in both CPU allocation and all wave-wall denominators.

| Fixed gate | Observed | Result |
|---|---:|---|
| Candidate C4 correctness = 32/32 | 30/32 | **Fail** |
| C1 conservative CPU/attempt ratio ≤ 1.10 | 1.882655982 | **Fail** |
| C4 conservative inclusive CPU/attempt ratio ≤ 1.10 | 1.473166419 | **Fail** |
| C1 wall/attempt ratio ≤ 1.10 | 0.865872915 | Pass |
| C4 conservative inclusive CPU/success ratio ≤ 1.10 | 0.392844378 | Pass |
| C4 successful-call-rate ratio ≥ 1.50 | 5.497982489 | Pass |
| Whole-life wait4 peak RSS guard | 95,944 ≤ 119,948.4 KiB | Pass |

Both arms passed C1 correctness (8/8); A48's 30 C4 successes exceeded r07's 8.
The report records complete inventory, owned controller cleanup, unchanged
fixtures and qualified inputs, clear host gates, correct client pending counts,
and no observed controller children/reaped-child CPU. Those integrity records
do not convert the three failed performance gates or the four kickoff errors
into success. All sixteen original gates are retained in the JSON.

The independent calculation used integer CPU ticks, monotonic wave timestamps
and original wait4 utime/stime, with the frozen endpoint allowances. It matches
the original counts, ratios, RSS limit and every gate. This is a report-body
numeric review; it does not claim a new independent read of wire, fixture,
source or ELF bodies.

## Interpretation and diagnostic boundary

The comparison arm is **r07, not A42**. Its differences cannot be separated into
an incremental causal effect of A48's new two-reader page path. The apparent
5.498× C4 successful-call rate coexists with two candidate deadline failures
and CPU/attempt regressions, and must not be presented as an adopted win.
This fixed client-wave workload is not saturated-server or multi-host throughput;
RSS is a whole-life regression guard, not steady-state memory evidence.

The original wait4 records show whole-life voluntary context switches of
5,151/4,648 for the r07 controllers and 995,383/939,922 for A48. This is a
concrete diagnostic clue, but it includes setup and shutdown and does not by
itself localize the overhead or prove its source. Actual server admission times
and frozen cohort membership were not observed. A49 remains a separate,
explicitly frozen diagnostic; its results must not replace or be pooled into
this failed formal comparison. Product deadlines, failure rows and fixed gates
remain unchanged.

## Every measured failure

| Controller | Source | Wave | Slot | Query | Failure category | Response elapsed ms |
|---|---|---:|---:|---|---|---:|
| 0 | r07 | 4 | 5 | first_32 | preparing / validation unavailable | 3001.678459 |
| 0 | r07 | 4 | 6 | quarter_16 | preparing / validation unavailable | 3001.456881 |
| 0 | r07 | 4 | 7 | tail_32 | preparing / validation unavailable | 3001.083575 |
| 0 | r07 | 5 | 8 | first_32 | preparing / validation unavailable | 3000.790281 |
| 0 | r07 | 5 | 9 | quarter_16 | preparing / validation unavailable | 3001.577349 |
| 0 | r07 | 5 | 10 | tail_32 | preparing / validation unavailable | 3001.397930 |
| 0 | r07 | 6 | 13 | tail_32 | preparing / validation unavailable | 3001.787935 |
| 0 | r07 | 6 | 14 | first_1 | preparing / validation unavailable | 3002.324023 |
| 0 | r07 | 6 | 15 | first_32 | preparing / validation unavailable | 3001.192595 |
| 0 | r07 | 7 | 17 | first_1 | preparing / validation unavailable | 3001.770745 |
| 0 | r07 | 7 | 18 | first_32 | preparing / validation unavailable | 3001.842355 |
| 0 | r07 | 7 | 19 | quarter_16 | preparing / validation unavailable | 3001.505331 |
| 1 | A48 | 6 | 33 | tail_32 | total deadline | 3003.043126 |
| 1 | A48 | 6 | 34 | first_1 | total deadline | 3003.280299 |
| 3 | r07 | 4 | 65 | first_32 | preparing / validation unavailable | 3002.686885 |
| 3 | r07 | 4 | 66 | quarter_16 | preparing / validation unavailable | 3002.580586 |
| 3 | r07 | 4 | 67 | tail_32 | preparing / validation unavailable | 3002.034821 |
| 3 | r07 | 5 | 69 | quarter_16 | preparing / validation unavailable | 3002.104432 |
| 3 | r07 | 5 | 70 | tail_32 | total deadline | 3001.984603 |
| 3 | r07 | 5 | 71 | first_1 | preparing / validation unavailable | 3001.407101 |
| 3 | r07 | 6 | 72 | quarter_16 | preparing / validation unavailable | 3002.675085 |
| 3 | r07 | 6 | 73 | tail_32 | preparing / validation unavailable | 3003.019895 |
| 3 | r07 | 6 | 74 | first_1 | preparing / validation unavailable | 3003.250437 |
| 3 | r07 | 7 | 77 | first_1 | preparing / validation unavailable | 3002.369231 |
| 3 | r07 | 7 | 78 | first_32 | preparing / validation unavailable | 3002.597185 |
| 3 | r07 | 7 | 79 | quarter_16 | preparing / validation unavailable | 3001.803373 |

The exact error messages and all original failure fields remain in
`large-summary.json` and the original report. The two new raw bodies reviewed
for publication—the large report above and the 125,595-byte small report,
SHA-256 `877b93e7daa09857103d280f7dd44cfc79d5e7aac19ed443780153385712f513`—
contain no detected credential/private-key/token material or unrelated full-host
process inventory. Their owned-task, controller, receipt and nonsecret synthetic
identities may be retained. Neither raw report was edited.

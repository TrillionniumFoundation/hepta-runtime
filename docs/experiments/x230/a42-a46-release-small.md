# A42 A46 continuation: qualified release and complete archive comparison

**Evidence update: 2026-10-26 UTC. Large comparison complete; adoption gate failed.**

A46 completed one new release build of the existing A42 source and passed the
fixed small-archive regression guard. The small workload measured no speedup.
The fixed large C1/C4 comparison completed all 80 planned measurements. A42
improved successful C4 throughput but retained two deadline failures and did
not pass the complete-correctness gate. It is not adopted on this evidence.

## Source and qualification

The source remains the A42 experiment in [PR #71](https://github.com/TrillionniumFoundation/hepta-runtime/pull/71),
published at [`eb57edfbb0db8b934534bb511674ab4635e5e31a`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/eb57edfbb0db8b934534bb511674ab4635e5e31a).
Its 168-file compiler-input map is
`c1ae8a69901aee16e03871e920a6a7e321672c9b30b3a6e75d3560390b8c2e11`.
The separate A43 owner-publication changes are not included.

The new qualification explicitly composes the five passing revision-03 stages
with one A46 release stage. It preserves each stage's origin:

| Stages | Origin | Result |
| --- | --- | --- |
| Format, format check, package-cache clean, strict Clippy, all-feature tests | Original A42 revision 03 | Retained passes; 1,264 top-level tests passed, 0 failed, 23 ignored |
| Release build | New A46 release-only attempt | Exit 0; 306.096104 s; one Cargo execution |

The release ran from **03:02:00.773 to 03:07:06.877 UTC** on X230 Rust 1.95.0.
Its own complete immediate host gate passed with the original busy-process and
2 GiB memory/disk floors. Budgets remained 1,800 s for release, 1,900 s for the
worker and 2,100 s for the outer entry, with two Cargo jobs and two Tokio workers.
The original worker was reaped with raw status 0 and retained custody; no retry,
signal, service change or agent access occurred.

The compiler emitted a source-bound `fresh=false` release artifact. The copied
ELF is **13,517,992 bytes**, SHA-256
`dde7f516d39ec8f6b7ee010e5747f55b0b10d742c419df22fd96ecbfffdd5299`.
The retained source maps and file identities agree before and after the new
attempt. The five older stages were not rerun. No missing historical
`source_after` was invented, and no historical clear window admitted this build.

The [original checkpoint](a42-fresh-cohort.md), original revision-03 release
refusal, revision-02 busy refusal and A45 `no_clear_observed` remain intact.
A46 is a separate newly authorized attempt; it does not convert those attempts
into successes or alter their admission rules.

## Small-archive result

Two opposite-mapping ABBA blocks completed all **8,848 tool calls**, including
**8,192 measured calls**, without a correctness failure. Each version had four
fresh controllers and 4,096 measured calls. Each round used 64 seed records,
eight warmups and 1,024 measured C1 calls across `usage_stats`, `request_history`
and `request_archive`. No retries or historical results were pooled.

| Metric | r07 | A42 | Guard or observed difference |
| --- | ---: | ---: | --- |
| Measured loop wall | 32.6367653 s | 32.7966756 s | Ratio 1.004899699; limit 1.10 |
| Successful measured calls/s | 125.502634 | 124.890707 | A42 −0.487581% |
| Measured controller CPU | 28.42 s | 28.63 s | A42 +0.738916% |
| Conservative CPU comparison | Lower bound 28.26 s | Upper bound 28.79 s | Ratio 1.018754423; limit 1.10 |
| Maximum whole-round wait4 RSS | 35,096 KiB | 35,056 KiB | Candidate limit 39,192 KiB |

All six completeness, correctness, wall, CPU and RSS gates passed. CPU bounds
retain four ticks per measurement interval; RSS is the maximum of all four
whole-round peaks for each version. The wall measurement includes the native
C1 RPC, DTO/oracle checks and journal flush loop. These are not saturated server
throughput or steady-state memory measurements.

## Retained receipt identities

The [machine-readable summary](a42-a46-summary.json) contains the full metrics,
stage origins, guard values and additional receipts. These identities refer to
the retained original operational evidence; raw process snapshots and executable
bodies are not reproduced here.

| Record | Bytes | SHA-256 |
| --- | ---: | --- |
| A46 composed qualification | 238,044 | `d6ee0938ef816c5f472edb967fe2764fc3bc05b4e958243e102f1d542c4fa46f` |
| Composition witness | 416 | `baca9840ef28c634b82f62e86c4f5756856dc5af79c67d33e4fc06df76d6fc1d` |
| A46 entry receipt | 186,968 | `d890909b75535eb8247a8c1035311a5d5f65afa872f97f7ebdd75ac5afa106cb` |
| Small comparison report | 276,833 | `4334c721f0f416909e61ce6dd294fc925c869b002b123208d9322033b3e967e7` |
| Small numerical evaluation | 35,731 | `c6a6fab822a83f9a9fc6882f05e6619d3e2d8c9162395236d66d0c2830e9f720` |

## Large-archive result and adoption boundary

The fixed large comparison completed in ABBA order with four fresh private
archives of 65,536 records each, four owners and 512 hot records. Each archive
contained one native seed and 65,535 synthetic records. All 80 measurement
slots were attempted exactly once; no failed result was replaced.

| Metric | r07 | A42 |
| --- | ---: | ---: |
| C1 correct responses | 8 / 8 | 8 / 8 |
| C1 wall per attempt | 2.190336 s | 2.199463 s |
| C4 correct responses | 8 / 32 | 30 / 32 |
| C4 successful responses/s, including failed-wave cost | 0.332900 | 1.620033 |
| C4 inclusive CPU per attempt | 0.752860 s | 0.580415 s |
| Maximum whole-life wait4 RSS | 109,248 KiB | 111,704 KiB |

The C4 successful-response rate ratio was **4.866423**. Conservative CPU ratios
were 0.773891 per attempt and 0.206371 per success; C1 wall/CPU and the RSS
regression guards passed. **The candidate C4 32/32 correctness gate failed.**
Its two errors occurred in the last C4 wave of the first candidate controller,
at 3,003.241 and 3,003.049 ms, and both reported the unchanged metadata query
deadline. The second candidate controller completed all its measured calls.
This complete inventory is retained rather than selecting that better round.

All four initial index-kickoff queries also reported the 3 s product deadline.
The protocol allowed that declared setup error, then used one fixed 60 s idle
and one successful archive warmup per controller; there were no readiness
retries. Thus `all_setup_queries_successful=false` is retained separately.
All controllers completed, every original fixture and qualified input remained
unchanged, the host gates passed, and all original children had complete wait
receipts. The report is `complete=true`, `passed=false`, with no unexecuted
measurement slots or outer execution error.

The terminal report is 340,612 bytes, SHA-256
`f27bd56b054449768fe052749ae414b52114ada53890cbf5a8574612b0cd575b`;
the unchanged large protocol is 9,860 bytes, SHA-256
`e197b94d1e797ca367a5dbe93b7679fccefbc0aef9becf383e2a9c2f17cea90e`.
These are fixed native client waves, not saturated-server or multi-host
throughput. Inclusive C4 CPU extends through actual controller cleanup and
uses conservative endpoint bounds; RSS is a whole-life guard, not a soak.

The next separate A48 candidate will test the existing bounded two-reader
complete-original validation kernel for large pages. That proposal retains
the 1 ms collection cutoff, freeze-before-observation and original 3 s budget.
Its outcome is not part of this A46 report.

The small evaluator records `performance_adoption_authorized=false`. It verifies
the captured qualification documents and journals, but does not independently
reread qualified source/ELF bodies or original raw wire/fixture bodies. The
complete original evidence audit and remaining fixed benchmark gates are
separate adoption requirements. Pending client IDs do not establish shared
server-cohort membership. The direct comparator is r07; a net A40/A42 result
requires a fresh direct comparison. This A46 evidence adds no multi-host,
reboot or power-loss acceptance and establishes no global optimization limit.

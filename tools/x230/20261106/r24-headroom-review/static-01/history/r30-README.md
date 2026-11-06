# R30: shared MCP tool router on accepted R24

**Status: qualification passed; original six-host observation failed; candidate not adopted.**

R30 isolates the fixed, unfiltered `ToolRouter` cache from the cumulative R29
candidate. Its source baseline is accepted R24
`baab4def80be7af015b2e7a594cb302f66c4130e`. The R25 cancellation reserve,
R26 JSON deferral, and R28 cancellation-command cache are absent.

## Change

The MCP server initializes its fixed tool definitions once with `OnceLock` and
reuses them for dispatch and tool listing. Visibility, caller authority, request
context, configuration and session state are still evaluated for each request.
Schema tailoring operates on cloned definitions.

The two changed compilation inputs are `src/mcp/server.rs` and
`src/mcp/server_tests.rs`. Tests cover independent live MCP sessions, working
directories, delta caches and teardown; runtime visibility changes after router
initialization; and repeated legacy/modern schema listing without shared mutation.

## Qualification on x230

The original eight-stage qualifier completed once, without retries:
format, format check, harness tests, Clippy, test build, isolated tests,
independent isolated-test audit, and release build.

| Result | Value |
|---|---:|
| Passed tests | 1647 |
| Failed tests | 0 |
| Ignored tests | 34 |
| Selected tests | 1681 |
| Qualification harness files unchanged | 19 |
| Compilation inputs matched to the publication checkout | 220 |

The native qualification job is `1a1ade0d4f4-fc05-5b52`; it completed with exit
code 0 and complete, durable, untruncated logs. The authoritative receipt is
[qualification-native.json](qualification-native.json). The post-qualification
materializer verified the original reports, raw log hashes, audited test
inventory, binaries and source maps; see
[qualification-summary.json](qualification-summary.json).

The tested runtime binary SHA256 is
`9c30ec2a6b8299755184d6a91e4d6b694a384f8589eb3f4cb65f31d4c8b996c8`.
The unchanged jobctl SHA256 is
`61c90260057a405626a24a36ad43303c632f72d2d97929296acdffd748b79d62`.

## Source custody

[candidate.patch](candidate.patch) is the original **pre-format** input applied
to R24. [input.json](input.json) freezes that input and its baseline. The
qualifier applied Rust formatting before testing;
[qualified-source-map.json](qualified-source-map.json) records the final tested
source. All 220 hashes were compared with this publication checkout and matched.
[prepare_qualify.py](prepare_qualify.py) is the actual launcher used on x230.

## Original six-host observation: rejected

The original frozen six-host ABBA observation completed all four rounds at
concurrency 1, 8 and 16. It retained **2,303 successes out of 2,304 measured
calls**. In round 2, candidate B at concurrency 1, one `process_status` request
for `rog` (request ID 72) returned `observation transport deadline; no automatic
retry` after **10,010.97226 ms**. That cell passed 191 of 192 calls; the other
11 cells passed 192 of 192.

The observation child and its parent exited 1. The native audit, boundary,
cancellation-recovery and observation-summary stages were not reached, and
normal lifecycle ABBA was not started. No benchmark was repeated to replace
this failure. The original throughput, p95, CPU and RSS thresholds remain
unchanged; passing isolated tests does not establish performance acceptance.

All four normal controller shutdowns and all four restart shutdowns completed.
The compiler-monitor audit passed with 281 samples, and the frozen source,
binaries and topology remained unchanged. This evidence does not establish
whether the router change caused the timeout or whether an environmental issue
caused it. The failed sample remains part of the result.

R24 remains the accepted baseline. The separate R31 candidate starts from R24
and excludes this router change. Saturated cancellation capacity remains
unverified by these runs.

## Reproducible evidence

[FAILURE.md](FAILURE.md) records the original failure and report identities.
[DEADLINE_REVIEW.md](DEADLINE_REVIEW.md) explains the total-deadline boundary
and why the retained failure does not identify its internal stage.
[qualification-evidence-01.tar.gz](qualification-evidence-01.tar.gz) contains
the qualification reports, raw stage logs, isolated test records and independent
audit, with a SHA256 manifest. Its archive SHA256 is
`3756716c9afdcb30c55b3d55b6e1a33b087a8236d6f33b8d7c8c69771064b304`.
The archive verifier recomputes the 1647/0/34 test counts without extracting or
executing archived files.

[observation-evidence-02.tar.gz](observation-evidence-02.tar.gz) preserves all
26,094,122 selected bytes of the original observation evidence in a 2,297,281-byte
archive. Its SHA256 is
`2dec641992e76f280b942c8f1a5dafd873ffc90f8ffce2eb3afc195bc5a7cfb2`.
[observation-compact.json](observation-compact.json) is recomputed from the raw
round/cell/call records, and includes the complete failed request. The original
[failed native terminal](observation-native.json) and [parent report](observation-parent.json)
are also readable separately.

The `parent-runner` directory preserves the five exact measurement parent and
materializer scripts plus their sealed bundle manifest. The original
`archive_r30_evidence.py` is retained even though its 16 MiB selected-input limit
was too small for the 26,094,122 bytes of observation receipts. That archive
packaging failure did not run or repeat any benchmark. The separate revision
for the observation archive only changes bounded packaging capacity; original
reports and samples remain intact.

Profile/credential configuration and ELF/test executables are excluded from
published raw archives and listed in their manifests. The host-local Mac
holder stdout/stderr remains on the Mac; its authoritative failed native
terminal receipt is retained with the observation evidence.

## Publication CI

For source commit `dbedaf9be0bbb65812fa9dbfcd9d7c0fb13f1ffd`, GitHub Actions
push run `42128006116` and pull-request run `42128073872` were both still queued
at 2026-11-05 23:59 UTC. They are not reported as green. The completed x230
eight-stage qualification is documented independently above.

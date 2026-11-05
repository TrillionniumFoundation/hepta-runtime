# R30: shared MCP tool router on accepted R24

**Status: qualified experimental candidate; six-host performance acceptance is pending.**

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

## Source custody and pending measurements

[candidate.patch](candidate.patch) is the original **pre-format** input applied
to R24. [input.json](input.json) freezes that input and its baseline. The
qualifier applied Rust formatting before testing;
[qualified-source-map.json](qualified-source-map.json) records the final tested
source. All 220 hashes were compared with this publication checkout and matched.
[prepare_qualify.py](prepare_qualify.py) is the actual launcher used on x230.

The next gates use the existing frozen six-host topology and ABBA order, with
concurrency 1, 8 and 16, followed by normal lifecycle ABBA if observation passes.
Throughput, p95 latency, controller CPU and RSS retain the original thresholds.
No throughput or memory improvement is claimed before those measurements close.
Saturated cancellation capacity is an open, separate question; R30 adds no
reserve-capacity mechanism. No running production service is changed by this
candidate publication.

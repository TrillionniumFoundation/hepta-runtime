# R11 six-host native observation ABBA

**Functional validation passed; performance results are mixed.** C1 and C4 have observed regressions, while C8 improves slightly. This campaign does not demonstrate a general end-to-end throughput or resource improvement. All raw rows and all four rounds are retained.

## Experiment and calculation

X230 ran A → B → B → A from 2026-11-03T11:36:35.072800+00:00 to 2026-11-03T11:38:55.446838+00:00 (140.374 seconds), with native stdio MCP, two Tokio workers, the operator Python backend and six already-completed original jobs. Each round measured C1, C4 and C8 in that order, 96 calls per cell.

- A: qualified R10e runtime SHA-256 b4e9022de0c764f84450cb7ade4947de0858460f09a898d3c830270006cc1504.
- B: qualified R11 runtime SHA-256 660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c.
- Each version/concurrency aggregate contains 192 calls. Calls/s = total calls / summed cell seconds; CPU ms/call = 1000 × summed controller CPU seconds / total calls. Per-cell rates are not averaged.
- Latency p50/p95 use all 192 raw per-call values per version/concurrency, with nearest rank sorted[ceil(p × n) − 1]. Per-cell quantiles are not averaged. No successful-call filtering was used.
- Cell wall time includes thread-pool setup/drain. Per-call latency starts inside the worker before RPC handling/validation and excludes time queued before worker execution. Initialization, preflight and restart probes are excluded from measured rates.
- CPU uses direct controller /proc/stat utime+stime deltas, with PID/birth identity checked at both endpoints. It includes controller background work during the cell and excludes SSH descendants, remote helpers and the Python driver. The report stores deltas, not raw endpoint counters.

## Pooled results

| C | Version | Calls/s | Controller CPU ms/call | p50 ms | p95 ms |
|---:|:---:|---:|---:|---:|---:|
| 1 | A | 6.128275 | 68.020833 | 156.563241 | 210.329660 |
| 1 | B | 6.069801 | 69.166667 | 160.904650 | 206.761108 |
| 4 | A | 15.697410 | 80.729167 | 249.446904 | 308.131457 |
| 4 | B | 15.114576 | 81.614583 | 251.818554 | 372.530156 |
| 8 | A | 18.031759 | 85.000000 | 430.386659 | 526.538658 |
| 8 | B | 18.288164 | 83.072917 | 422.706472 | 517.132046 |

Candidate change is (B/A − 1) × 100. Positive throughput is better; negative CPU or latency is better.

| C | Calls/s change | CPU/call change | p50 change | p95 change |
|---:|---:|---:|---:|---:|
| 1 | -0.954% | +1.685% | +2.773% | -1.697% |
| 4 | -3.713% | +1.097% | +0.951% | +20.900% |
| 8 | +1.422% | -2.267% | -1.784% | -1.786% |

**C4 is a measured regression:** throughput falls 3.713%, CPU/call rises 1.097%, and pooled p95 rises 20.900%. C1 throughput falls 0.954%, CPU/call rises 1.685%, and p50 rises 2.773%, while p95 improves 1.697%. C8 throughput improves 1.422%, CPU/call improves 2.267%, and p50/p95 improve about 1.79%. These are recorded sample changes, not significance or causality claims.

## All four rounds

| Round (zero based) | Version | C | Calls/s | CPU ms/call | p50 ms | p95 ms |
|---:|:---:|---:|---:|---:|---:|---:|
| 0 | A | 1 | 6.0723 | 67.1875 | 154.3194 | 249.3013 |
| 0 | A | 4 | 15.4881 | 80.5208 | 248.4855 | 315.1845 |
| 0 | A | 8 | 18.2840 | 84.6875 | 428.8192 | 498.4959 |
| 1 | B | 1 | 6.1253 | 68.4375 | 157.5186 | 203.6613 |
| 1 | B | 4 | 15.9559 | 79.3750 | 241.5419 | 310.7172 |
| 1 | B | 8 | 18.1477 | 82.5000 | 427.5935 | 517.1320 |
| 2 | B | 1 | 6.0153 | 69.8958 | 161.4839 | 212.1322 |
| 2 | B | 4 | 14.3575 | 83.8542 | 260.0406 | 410.1228 |
| 2 | B | 8 | 18.4308 | 83.6458 | 411.5926 | 522.9809 |
| 3 | A | 1 | 6.1853 | 68.8542 | 158.2267 | 194.6664 |
| 3 | A | 4 | 15.9124 | 80.9375 | 251.1385 | 297.6163 |
| 3 | A | 8 | 17.7863 | 85.3125 | 431.3010 | 539.7407 |

Both B rounds are retained, including the second B C4 cell with 14.3575 calls/s and 410.1228 ms p95. A finite ABBA with two runs per version and fixed concurrency order does not establish repeatability or code-level causation.

## Counts and invariants

| Phase | Calls | Status | Read | Result |
|---|---:|---:|---:|---|
| Initial preflights | 24 | 0 | 24 | 24 passed, 0 failed |
| Measured cells | 1152 | 576 | 576 | 1152 passed, 0 failed |
| Normal restart probes | 48 | 24 | 24 | 48 passed, 0 failed |
| All tool calls | 1224 | 600 | 624 | 1224 passed, 0 failed |

Every measured cell contains eight calls for each of 12 host/tool combinations. That gives 192 measured calls per host, with 576 status and 576 read calls overall. Across all phases each host has 204 calls: 100 status and 104 read; the extra reads are preflights. Eight MCP initialize requests and eight initialization notifications are outside the 1,224 tool-call count.

All rows have okay=true, isError=false and automatic_retry=false, with the expected original job ID. All 624 read rows match original stdout digests and byte counts with empty stderr. DTO hashes happen to be stable for all 12 host/tool pairs; this is an observed fact, not an additional functional acceptance requirement.

Eight distinct controller PID/birth generations exited through stdin EOF with exit 0, no unmatched responses or reader errors, and no observed descendant survivors. All four restart probes preserve original receipts and successful readbacks. The report records zero process starts, remote mutation tool calls and automatic RPC retries.

| Host | Original job ID | Stdout bytes |
|---|---|---:|
| ai395 | 1a16a4035ad-b1270-1 | 46 |
| mac | 1a16a403e55-b1270-2 | 44 |
| main | 1a16a4046ac-b1270-3 | 45 |
| pocket4 | 1a16a40534e-b1270-4 | 48 |
| rog | 1a16a405d21-b1270-5 | 44 |
| x230 | 1a16a40671b-b1270-6 | 45 |

The reported source_originals_unchanged=true means six frozen job receipt files, not a Rust source tree. The reviewed harness checks source and copied receipts after each round, checks binaries before each round, and rechecks source receipts and binaries on completion. The final binary_hashes_unchanged flag is true. Separate archived qualifications match the exact A/B runtime hashes: R10e has 210 tested source entries and R11 has 213; both have source_tested == source_after, unchanged harness maps and all eight stages at exit 0.

Independent reconstruction verifies recorded counts, balance, identity/output digests and lengths, CPU-delta arithmetic and raw latency aggregation. The benchmark report does not contain full DTO payloads, raw after-file bytes, raw CPU endpoint counters or an execution-bound harness hash; complete returned-data validation is performed by the reviewed harness.

## Resource observations and retained errors

The peaks below cover each first controller’s whole lifetime, including setup, preflight and all three concurrency cells. RSS/FD/tree CPU use approximately 100 ms sampling and are incomplete. They cannot be attributed to a specific cell. The direct controller CPU metric is independent of this sampler.

| Round | Version | Controller RSS KiB | Controller FD | Tree RSS KiB | Tree FD | Main errors |
|---:|:---:|---:|---:|---:|---:|---:|
| 0 | A | 17032 | 81 | 95424 | 132 | 2 |
| 1 | B | 17036 | 80 | 102752 | 145 | 1 |
| 2 | B | 17088 | 89 | 108780 | 245 | 3 |
| 3 | A | 16748 | 84 | 109932 | 156 | 2 |

These observations do not establish a resource reduction. Candidate controller RSS peaks are 17,036–17,088 KiB versus baseline 16,748–17,032 KiB. The second B run has an observed tree FD peak of 245. Nine FD-sampling PermissionError entries are preserved, including one for the second B controller itself and one during the final A restart.

- Round 0 A, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1956807/fd'.
- Round 0 A, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1957105/fd'.
- Round 1 B, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1957836/fd'.
- Round 2 B, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1958211/fd'.
- Round 2 B, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1958448/fd'.
- Round 2 B, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1958010/fd'.
- Round 3 A, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1959335/fd'.
- Round 3 A, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1959347/fd'.
- Round 3 A, restart_shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1959482/fd'.

**Sampler boundary caveat:** the original report labels per-cell differences of asynchronous tree CPU snapshots as lower bounds. That guarantee is unsupported: pre-cell work can enter a later snapshot and endpoint work can be missed, so boundary error can have either sign. These original deltas are retained but are not used as CPU/call evidence.

## Coverage and archive

This run covers warm read-only observation of completed jobs with ordinary controller restart. It does not cover new launches, process_wait, system jobctl, controller SIGKILL, target reboot, physical power loss, WAN partition or production owner transfer. Separate recovery reports cover the intentionally injected SSH-master and controller SIGKILL cases. This finite campaign does not establish a universal optimization ceiling.

- [Complete report, byte-exact gzip](native-observation-abba.json.gz)
- [Independent machine-readable summary](native-observation-summary.json)
- [R10e qualification](r10e-qualification.json.gz)
- [R11 qualification](r11-qualification.json.gz)

Original JSON: **633,352 bytes**, SHA-256 9fd1cc2fce6e01797c6269487f0d0a7379756e3a5ae205e0728e412c92a89ac0.

Gzip: **95,676 bytes**, SHA-256 246241fff6e09e1dda08b9f1a5a4c3147efa62e85a8df8f296e32774987d007d. Six version-pinned chunks of at most 16 KiB passed individual and whole-file hash checks. Decompression exactly reproduces the original bytes.

Only report.json was compressed. Profile, ssh_config and known_hosts file contents were excluded. No redaction or removal of negative observations was performed.

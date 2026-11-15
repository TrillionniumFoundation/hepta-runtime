# R11 inventory campaign 02 — independent recomputation

**Recommendation:** retain the measured large-payload read/projection changes; do not claim every workload is faster or that RSS materially falls.
This is local warm-inventory evidence from matching libtest profiles, not release-binary, SSH, six-host, or full MCP throughput.

Verified: **20 cases, 80 executed sample processes, 688 successful measured calls, 0 failed calls, 0 automatic retries**. Plain: 18/72/624; escaped: 2/8/64.
All ABBA orders, within-case response hashes, fixture manifest hashes, fixture-unchanged flags, raw latency identities, process exits, and wait4 RSS >= in-process sampled high-water checks agree.
Independent recomputation matched all 580 numeric runner-statistic fields (max absolute difference 0; tolerance 1e-12 relative / 1e-9 absolute).

A = immutable R10e behavior plus the identical benchmark module; B = qualified R11. CPU and throughput aggregate both arm processes; RSS is their whole-child peak median.
- A binary: `cd5e73d1df2a6def1385dd6699711ffeeeef78feea3ae7e2e0106fc360e26597`.
- B binary: `664e821762647be2bea2224aa566be2fb9d9983131c77af22f6f085cb556668b`.
- Identical benchmark module: `e0bd1eb185404122773c11415413e631d21bd04970ed1fb2764d654bdd3d1f56`.
- Profile recorded equal: opt-level 1, debuginfo 0, debug assertions and overflow checks on, test=true.

## C4 emphasis

| Payload | Mode | C | CPU ms/call A → B | Calls/s A → B | RSS median KiB A → B | p50 ms A → B | p95 ms A → B |
|---|---|---:|---:|---:|---:|---:|---:|
| plain 1 KiB | list | 4 | 5.299 → 5.365 | 374.62 → 468.60 | 25320 → 25320 | 9.331 → 7.050 | 19.023 → 11.245 |
| plain 1 KiB | page | 4 | 6.339 → 5.910 | 401.11 → 430.62 | 25320 → 25320 | 6.529 → 6.291 | 15.856 → 14.624 |
| plain 64 KiB | list | 4 | 12.101 → 11.563 | 210.63 → 230.52 | 25320 → 25320 | 13.205 → 12.521 | 28.529 → 26.808 |
| plain 64 KiB | page | 4 | 12.299 → 11.652 | 205.40 → 191.93 | 25320 → 25320 | 12.355 → 12.312 | 31.529 → 29.244 |
| plain 768 KiB | list | 4 | 95.566 → 77.840 | 28.64 → 34.97 | 25320 → 25320 | 107.092 → 84.326 | 213.868 → 180.271 |
| plain 768 KiB | page | 4 | 94.788 → 78.066 | 26.54 → 29.03 | 25320 → 25320 | 129.178 → 107.919 | 204.572 → 204.808 |
| escaped 64 KiB | list | 4 | 158.978 → 154.745 | 17.50 → 17.89 | 20464 → 20464 | 182.245 → 173.895 | 324.564 → 327.166 |
| escaped 64 KiB | page | 4 | 157.066 → 146.317 | 15.11 → 19.21 | 20464 → 20464 | 213.633 → 179.595 | 345.308 → 256.940 |

## All 20 cases

| Payload | Mode | C | CPU ms/call A → B | Calls/s A → B | RSS median KiB A → B | p50 ms A → B | p95 ms A → B |
|---|---|---:|---:|---:|---:|---:|---:|
| plain 1 KiB | list | 1 | 3.652 → 3.568 | 278.45 → 283.48 | 25320 → 25320 | 3.036 → 2.962 | 3.526 → 3.427 |
| plain 1 KiB | list | 4 | 5.299 → 5.365 | 374.62 → 468.60 | 25320 → 25320 | 9.331 → 7.050 | 19.023 → 11.245 |
| plain 1 KiB | list | 8 | 5.638 → 5.451 | 671.72 → 654.47 | 25320 → 25320 | 9.655 → 9.525 | 12.759 → 13.685 |
| plain 1 KiB | page | 1 | 4.043 → 3.941 | 250.28 → 255.76 | 25320 → 25320 | 3.405 → 3.359 | 3.922 → 3.960 |
| plain 1 KiB | page | 4 | 6.339 → 5.910 | 401.11 → 430.62 | 25320 → 25320 | 6.529 → 6.291 | 15.856 → 14.624 |
| plain 1 KiB | page | 8 | 6.130 → 6.178 | 598.21 → 619.27 | 25320 → 25320 | 10.888 → 11.306 | 14.187 → 13.905 |
| plain 64 KiB | list | 1 | 8.039 → 7.809 | 125.29 → 125.89 | 25320 → 25320 | 7.473 → 7.204 | 7.702 → 8.068 |
| plain 64 KiB | list | 4 | 12.101 → 11.563 | 210.63 → 230.52 | 25320 → 25320 | 13.205 → 12.521 | 28.529 → 26.808 |
| plain 64 KiB | list | 8 | 12.706 → 11.447 | 302.46 → 273.43 | 25320 → 25320 | 24.729 → 23.077 | 28.260 → 38.821 |
| plain 64 KiB | page | 1 | 8.293 → 7.805 | 120.95 → 128.95 | 25320 → 25320 | 7.615 → 7.265 | 8.072 → 7.622 |
| plain 64 KiB | page | 4 | 12.299 → 11.652 | 205.40 → 191.93 | 25320 → 25320 | 12.355 → 12.312 | 31.529 → 29.244 |
| plain 64 KiB | page | 8 | 12.603 → 11.771 | 225.44 → 227.68 | 25320 → 25320 | 30.466 → 28.014 | 41.547 → 41.483 |
| plain 768 KiB | list | 1 | 54.283 → 45.353 | 18.45 → 22.07 | 25320 → 25320 | 53.421 → 44.383 | 55.332 → 45.512 |
| plain 768 KiB | list | 4 | 95.566 → 77.840 | 28.64 → 34.97 | 25320 → 25320 | 107.092 → 84.326 | 213.868 → 180.271 |
| plain 768 KiB | list | 8 | 98.478 → 78.518 | 29.59 → 33.70 | 25706 → 25320 | 217.270 → 201.515 | 318.316 → 301.693 |
| plain 768 KiB | page | 1 | 58.107 → 46.852 | 17.23 → 21.26 | 25320 → 25320 | 55.105 → 45.363 | 62.476 → 50.036 |
| plain 768 KiB | page | 4 | 94.788 → 78.066 | 26.54 → 29.03 | 25320 → 25320 | 129.178 → 107.919 | 204.572 → 204.808 |
| plain 768 KiB | page | 8 | 100.101 → 81.211 | 28.41 → 35.00 | 25320 → 25320 | 224.804 → 191.612 | 331.909 → 267.408 |
| escaped 64 KiB | list | 4 | 158.978 → 154.745 | 17.50 → 17.89 | 20464 → 20464 | 182.245 → 173.895 | 324.564 → 327.166 |
| escaped 64 KiB | page | 4 | 157.066 → 146.317 | 15.11 → 19.21 | 20464 → 20464 | 213.633 → 179.595 | 345.308 → 256.940 |

## Every directional regression

These are descriptive differences, including sub-percent movements; two processes per arm do not establish statistical significance.

| Case | Regressed metric(s), candidate change |
|---|---|
| plain 1KiB list C4 | CPU/call +1.241% |
| plain 1KiB list C8 | calls/s -2.567%; p95 +7.260% |
| plain 1KiB page C1 | p95 +0.972% |
| plain 1KiB page C8 | CPU/call +0.787%; p50 +3.834% |
| plain 64KiB list C1 | p95 +4.747% |
| plain 64KiB list C8 | calls/s -9.600%; p95 +37.368% |
| plain 64KiB page C4 | calls/s -6.559% |
| plain 768KiB page C4 | p95 +0.116% |
| escaped 64KiB list C4 | p95 +0.802% |

## Noise and scope

- CPU ms/call = 1000 * sum(measured user+system CPU deltas) / sum(successful calls) over both processes of each arm.
- Calls/s = sum(successful calls) / sum(measured wall seconds); it is not the median of per-process throughputs.
- p50/p95 use the nearest-rank quantile over all raw call latencies of an arm, not a percentile of process medians.
- RSS is the median of two wait4 whole-child maximum-RSS values in Linux KiB; includes fixture checks/warmup and is not measurement-only or retained heap.
- Two plain 768 KiB list C8 baseline samples have wait4 maxrss 128 KiB above the earlier in-process high-water reading. All comparisons consistently use wait4, not a mixture of those endpoints.
- 20 cases, only two processes per arm/case. C1/C4/C8 have 4/16/32 call latencies per arm; C1 and C4 p95 is the observed maximum.
- Warm fixture hash checks and a warmup precede timing. No cold-disk, disk-write, SSH, six-host, or full MCP throughput claim.
- Campaign endpoint snapshots both contain cargo PID 1950444, with no rustc entry. They are not proof of an idle machine or continuous absence of compiler work.
- Temperatures increased from 65/69 C to 74/73 C at the observed endpoints. Only endpoint environment observations are retained.
- Fixture bytes are no longer present after the campaign. This audit checks canonical manifest hashes and every sample's retained before/after verification, not a new read of deleted fixtures.
- Child stdout/stderr digests are retained in source reports; this audit operates on their retained parsed benchmark blocks, not separately downloaded stdout files.

Largest within-arm throughput spreads (max/min - 1; only two process observations):

- plain 1KiB page C4, arm A: 92.68%.
- plain 64KiB list C4, arm B: 80.52%.
- plain 1KiB list C4, arm A: 51.74%.
- plain 64KiB list C8, arm B: 36.15%.
- plain 64KiB page C4, arm B: 33.56%.

CPU/call decreased in 18/20 cases; throughput increased in 17/20. RSS was identical in 19/20, with only a 1.50% decrease for plain 768 KiB list C8.
For all six plain 768 KiB cases CPU/call decreased 16.45–20.27%, while calls/s increased 9.38–23.37%.
The clearest throughput regressions are plain 64 KiB list C8 (-9.60%, p95 +37.37%) and page C4 (-6.56%), despite lower measured CPU/call.
The escaped 64 KiB diagnostic retains owned-string fallback: list C4 shows CPU -2.66%, calls/s +2.20%, p95 +0.80%; page C4 shows CPU -6.84%, calls/s +27.11%.
Large wall changes with small CPU changes are sensitive to scheduling/background conditions. The cargo process and temperature drift must remain visible.

## Retained inputs

- [Plain original report, lossless gzip](inventory-plain.json.gz)
- [Escaped original report, lossless gzip](inventory-escaped.json.gz)
- [Campaign environment/commands, lossless gzip](inventory-campaign-02.json.gz)
- [Complete independent 20-case summary](inventory-campaign-02-summary.json)

# R11 native observation: independent C4 recheck

**The first campaign’s C4 p95 regression did not repeat directionally.** The original +20.900% p95 observation remains preserved. This C4-only recheck measures p95 −2.249%, throughput −0.300% and controller CPU/call +1.253%. It does not establish a general no-regression result.

## Separate campaigns

The recheck ran on X230 from 2026-11-03T11:56:48.955184+00:00 to 2026-11-03T11:57:47.673041+00:00 (58.718 seconds), with four rounds in A → B → B → A order. Each round has one C4 cell with 96 measured calls. It uses the same A/B runtime hashes, six original job IDs/output expectations, native stdio MCP and two Tokio workers as the first campaign.

The first campaign’s C4 cell followed its C1 cell. In the targeted recheck, C4 follows only preflight. This change in preconditioning limits direct cross-campaign attribution; the results are presented separately, with neither campaign substituted for the other.

Each A/B entry below pools 192 calls across two rounds. Calls/s is total calls divided by summed cell wall seconds. CPU/call is summed direct controller CPU divided by calls. p50/p95 are nearest-rank percentiles of pooled raw latencies, not means of per-round percentiles. No rows were filtered by success.

| Campaign | Version | Calls/s | CPU ms/call | p50 ms | p95 ms |
|---|:---:|---:|---:|---:|---:|
| First ABBA | A | 15.697410 | 80.729167 | 249.446904 | 308.131457 |
| First ABBA | B | 15.114576 | 81.614583 | 251.818554 | 372.530156 |
| C4 recheck | A | 16.000809 | 78.958333 | 243.063639 | 322.669224 |
| C4 recheck | B | 15.952858 | 79.947917 | 241.403344 | 315.412781 |

| Metric: B versus A | First campaign | C4 recheck | Direction |
|---|---:|---:|---|
| Calls/s | -3.713% | -0.300% | Same direction |
| Controller CPU ms/call | +1.097% | +1.253% | Same direction |
| p50 latency | +0.951% | -0.683% | Reverses |
| p95 latency | +20.900% | -2.249% | Reverses |

Throughput is lower in both samples, but its observed change narrows from −3.713% to −0.300%. CPU/call rises in both, by +1.097% and +1.253%. Both p50 and p95 change direction. Two rounds per version in each finite campaign do not prove statistical equivalence, establish code-level causation, or erase the first campaign’s tail-latency observation.

## All recheck rounds

| Round (zero based) | Version | Calls | Seconds | Calls/s | CPU ms/call | p50 ms | p95 ms |
|---:|:---:|---:|---:|---:|---:|---:|---:|
| 0 | A | 96 | 6.137036 | 15.642730 | 80.104167 | 250.787996 | 322.782128 |
| 1 | B | 96 | 6.086747 | 15.771971 | 80.000000 | 242.419431 | 337.945534 |
| 2 | B | 96 | 5.948714 | 16.137943 | 79.895833 | 239.584158 | 315.412781 |
| 3 | A | 96 | 5.862357 | 16.375666 | 77.812500 | 238.574423 | 319.472749 |

## Integrity and actual counts

| Phase | Calls | Status | Read | Failed |
|---|---:|---:|---:|---:|
| Preflight | 24 | 0 | 24 | 0 |
| Measured C4 | 384 | 192 | 192 | 0 |
| Restart probes | 48 | 24 | 24 | 0 |
| All tool calls | 456 | 216 | 240 | 0 |

- Every measured cell contains eight calls for each host/tool pair. Each host has 64 measured calls and 76 total calls, including 36 status and 40 read.
- All 456 tool rows are okay=true, isError=false and automatic_retry=false. All 240 read rows match original stdout hashes and byte lengths, with empty stderr. Original job IDs and frozen receipt descriptions match the first campaign.
- All four rounds pass. Eight distinct controller PID/birth generations exit normally through stdin EOF with exit 0, no reader errors or unmatched replies, and no observed descendant survivors.
- The report records source originals and binaries unchanged, zero process starts and zero remote mutation tool calls. A/B runtime hashes match the first campaign and the archived R10e/R11 qualifications, including unchanged tested source and harness maps.
- DTO hashes are observed stable, but hash stability is not a functional pass requirement. Full DTO payloads, raw CPU endpoint counters and after-file bytes are not contained in the report; recorded digests/lengths and aggregates were independently checked against the reviewed harness’s validation contract.
- The two separate campaigns together record 1,536 measured and 1,680 total tool calls with zero tool failures. This is a count, not a pooled performance estimate.

## Resources and retained limitations

There are **eight** resource-sampling PermissionError entries in the recheck, including a controller FD-directory entry for PID 1970696. The first campaign’s nine entries remain untouched, giving 17 across the two preserved reports. Resource sampling cannot be described as complete or error-free.

| Round | Version | Controller RSS peak KiB | Controller FD peak | Tree RSS peak KiB | Tree FD peak | Main errors | Restart errors |
|---:|:---:|---:|---:|---:|---:|---:|---:|
| 0 | A | 16248 | 67 | 87444 | 125 | 3 | 1 |
| 1 | B | 16648 | 75 | 87496 | 131 | 1 | 2 |
| 2 | B | 16244 | 70 | 94188 | 126 | 1 | 0 |
| 3 | A | 16300 | 70 | 93576 | 128 | 0 | 0 |

- Round 0 A, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1969940/fd'.
- Round 0 A, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1970028/fd'.
- Round 0 A, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1970133/fd'.
- Round 0 A, restart_shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1970189/fd'.
- Round 1 B, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1970313/fd'.
- Round 1 B, restart_shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1970531/fd'.
- Round 1 B, restart_shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1970548/fd'.
- Round 2 B, shutdown: PermissionError: [Errno 13] Permission denied: '/proc/1970696/fd'.

The sampler observes approximately 100 ms intervals across controller lifetimes. It misses activity and cannot establish a complete resource reduction. Per-cell asynchronous tree-CPU snapshot differences are not guaranteed lower bounds, despite the raw field label: their boundary error can have either sign. Those values are retained but are not used for CPU/call.

Controller CPU/call uses direct same-PID/birth utime+stime deltas and excludes SSH descendants, remote helpers and the Python driver. Per-call latency excludes time queued before a worker begins; cell throughput includes executor setup/drain. Scope remains warm status/read observation of completed jobs with ordinary controller restart. This does not test launches, process_wait, system jobctl, controller SIGKILL, physical power loss, target reboot or WAN partition.

## Archived evidence

- [Recheck full report](native-observation-abba-c4-recheck.json.gz)
- [Recheck machine-readable summary and campaign comparison](native-observation-summary-c4-recheck.json)
- [Preserved first campaign results](native-observation-results.md)
- [Preserved first campaign full report](native-observation-abba.json.gz)

Recheck original: **243,413 bytes**, SHA-256 2f08bd36f0cd11843d1783e49b285f90717880572052d56ebf41ec75c473221f.

Recheck gzip: **38,321 bytes**, SHA-256 a611b2b7ec86be8c289bcad86214e8d3ac3547fd738279f19c82802de695fb6b.

Downloaded the raw report through 15 version-pinned chunks of at most 16 KiB, validating each chunk hash and exact offsets. Gzip was generated locally with mtime=0 and verified to decompress to the exact raw bytes. No remote archive process was launched. Only report JSON is included; profile, ssh_config and known_hosts files are not included. No redaction was performed.

The first campaign’s raw report and three published evidence artifacts remain byte-exact. Their original hashes are included in the recheck summary.

# R36 asynchronous read supplement

This is a separate descriptive experiment. It does not modify the sealed R36 observation/lifecycle controls, their acceptance gates, runtime flags, or capacity/owner policies. It runs no remote job or command: each new asynchronous operation performs one real `process_status` or `process_read` against the same six frozen completed jobs, through the original native Controller and SSH observation profile.

## Fixed protocol

| Item | Definition |
| --- | --- |
| Order | A/B/B/A, accepted R24 versus qualified R36 |
| Controller | One active native stdio Controller; original `--runtime-prewarm`, `--runtime-audit-group-commit`, observation profile flags; 2 Tokio workers; allocator arena maximum 1 |
| Cells | C1 followed by C8 in each fresh round |
| Warmup | 12 new logical operations per cell |
| Measured | 24 new logical operations per cell; 48 observations per arm/concurrency over ABBA |
| Host/tool schedule | Sorted six hosts; six status operations then six read operations, repeating |
| Total | 288 distinct background operations: 192 measured and 96 warmup |
| Polling | `operation_status` every 10 ms while queued/running/settling |
| Results | Original SDK bytes in pages of 16,384 bytes; full byte count and SHA-256; maximum 1 MiB |
| Deadline | Each admission start through full original-result verification must finish within 45 seconds; 270-second new-call budget for the campaign |
| Failure | Keep the original attempt and its partial evidence; no start replay, skipped samples, or automatic retry |
| Adoption | No new performance threshold; original OBS and normal lifecycle remain the formal gates |

The current source's `Slot::take()` tracks active requests without the tool description's historical four-per-owner/eight-global rejection. The supplement uses the actual current implementation and returned receipts. C8 is offered client concurrency; it does not establish maximum supported capacity.

## What is timed

**Admission latency** is each new `operation_start` RPC. The reported admission receipt rate divides the number of new admissions by the sum of cohort admission windows. Background dispatch can overlap these windows; this is neither pure metadata CPU nor job compute throughput.

**Validated settlement latency** runs from that admission RPC's start through durable `completed` status and full original SDK result retrieval and validation. It includes polling, transport capture, JSON/base64/hash checks, journal writes, and cohort scheduling. The full-cell verified-read rate uses the entire measured cell duration. It is not pure background handler execution time.

Controller CPU uses the same original PID/birth and raw `/proc` utime/stime counters around the full timed cell. It includes audit, real background read, status polling and result retrieval. It excludes Python harness CPU and cannot be described as cluster CPU. The original 100 ms resource sampler is retained. RSS peaks are computed from controller samples wholly within each measured window plus its raw VmRSS endpoints; they remain observed peaks, not complete high-water marks.

Warmup, idempotency checks, changed-argument refusal, and new-owner checks do not enter measured latency aggregates. Original result files and the final per-cell JSON are written after the timed cell. Raw native transport and resource traces retain the original capture behavior.

## Correctness and ownership

Every new operation must return a new server-generated ID, report durable `completed` with no active owned future and an available original payload, and return the exact original serialized SDK result. Each result is reassembled by byte offset and checked against its full SHA-256 before decoding. The inner job ID, successful terminal state, original stdout marker, empty stderr, exact cursors, completeness and audit fields are validated against the frozen job records.

After each cell, every operation is called again with its identical idempotency key and typed arguments. It must return the original ID with `reused=true`; durable status must remain completed and the full original payload must remain byte-for-byte identical. The reused admission receipt may say `async_state=unknown` after its live future has left the registry; that field alone is not treated as a failure or completion proof. One changed-argument reuse per cell must explicitly refuse the immutable key binding.

After the timed cells and clean original Controller shutdown, the harness starts a new stdio Controller using the same state/config/profile and a new evidence directory. Status and result access to a representative original operation must explicitly refuse the owner/scope binding. An RPC failure, timeout or unrelated audit failure never counts as successful isolation. This check makes no new async start.

## Install and seal

Install only `seal_protocol.py` and `run_async_read_abba.py` into the new `supplement-tools-01` directory under `/home/qian/hepta-runtime-optimization-20261106-r36`. Leave `r36-control` and all original gates unchanged.

The sealer requires the successful original qualification and the existing `rust-ci-qualification-bindings-01.json` produced by the R36 control materializer. It checks the original R36 helper, accepted R24 and actual R36 binaries/source maps, original native tools, frozen jobs, topology and profile. It then writes the sealed protocol and a small held-agent launcher **before any workload starts**:

```bash
/usr/bin/python3 -I -B /home/qian/hepta-runtime-optimization-20261106-r36/supplement-tools-01/seal_protocol.py \
  --sealer-sha256 ACTUAL_SEALER_SHA256 \
  --runner-sha256 ACTUAL_RUNNER_SHA256 \
  --qualification-bindings-sha256 ACTUAL_QUALIFICATION_BINDINGS_SHA256
```

The output gives the actual identities of `async-read-protocol-01.json` and `supplement-tools-01/held_async_read_supplement.py`. The generated launcher embeds the protocol and runner hashes, so neither can be changed between sealing and launch unnoticed.

Copy the exact generated launcher to the Mac holder's local input path, verify its reported hash, and run the unchanged `held_agent_campaign_02.py` with `--remote-script` pointing at that launcher, a fresh `--out` path, and `--timeout-seconds 600`. The original holder still transmits stdin and supplies only `--launcher-sha256`; the launcher passes the already sealed protocol identity internally. No credential path or SSH identity is invented by these scripts.

The expected healthy runtime is a few minutes. The 270-second budget prevents further async submissions, while the original Controller's initialization and graceful cleanup retain their own bounded waits. The 600-second holder limit leaves cleanup room; this is not a promise to force-kill an uncertain remote owner at five minutes.

## Evidence and review

The experiment writes only its new `async-read-abba-01` tree and the short private socket parent `/home/qian/h36ar01`. Retain the protocol, generated launcher, complete holder streams/terminal, report, all original Controller transport/index/resource/stderr files, supplemental request journals, per-operation serialized original payloads, per-cell records, compiler monitor/audit, and any error/partial-cell records. Private copied SSH profile/config files stay private under the existing evidence export policy.

The final report's `summary` contains pooled per-arm values and B/A ratios for admission rate/latency, full validated settlement rate/latency, controller CPU and observed RSS. It is descriptive and sets no new adoption gate. `passed` requires complete correctness, immutable source/inputs, owner closure and valid original compiler monitoring. Failed or incomplete measurements are preserved, without an aggregate success claim.

`review_pure.py` and `pure-review.json` cover synthetic protocol cases only: paging/full SHA, frozen output, wrong identity/scope/state, reused unknown live receipt, and rejection classification. They are not runtime, SSH, qualification or performance evidence.

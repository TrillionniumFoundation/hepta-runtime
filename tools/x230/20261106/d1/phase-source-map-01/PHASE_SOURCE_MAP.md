# D1 phase labels: source map and interpretation

This is a read-only index for the pending C1 diagnostic evidence, not a new optimization. The existing candidate README already defines the record families, CPU accounting and blind spots; it is not rewritten here. This index adds exact formatted-source/function locations and narrow decision conditions.

**There are 18 synchronous wrapper sites and 17 distinct labels.** `encode_observation` occurs once in `status_job` and once in `read_job`. The trace also contains many wall-only phases and markers; those are not additional synchronous CPU buckets.

## Sources already available

- Original design and timing scope: `/tmp/hepta-runtime-recovery-20261106/r24-phase-cost-candidate-recovery-02/README.md`, sections “What each record means”, “CPU and wall accounting”, and “What this preparation cannot determine” (Git blob `34650add12ccadb18c4d402a152eb4b9181ad98e`). Its preparation-time build status is historical; this note does not rewrite it.
- Original scheduling and attribution plan: `references/diagnostic-plan-01.json` in the same directory (Git `b33e16ffe92c425e59bb4643acdde4202e468614`).
- Existing raw parser: `summarize_trace.py` in the same directory (Git `064cd62dd7f60ee11d538b4b21f4674283591572`).
- Existing measurement-category rule: `/tmp/hepta-runtime-recovery-20261106/d1-c1-parent-template-05/README.md`, lines 193–198: preflight, warmup, measured and restart remain separate.

The five fetched D1 files were read at published commit `9f3dd5a8e3ebbac4631527a7710d41570ca78a85` and independently SHA-checked against the actual 222-input qualification map `98824381ae2009e909fc28e07087d8646d3131229e146c04ecd9f58c60a14133`. R24 text was checked against the frozen accepted map at `baab4def80be7af015b2e7a594cb302f66c4130e`. Exact identities and per-site positions are in `phase-source-map.json`.

## Eighteen sites

Paths below are relative to the repository root. “A” is the R24 expression line; “D1” is the actual formatted wrapper line.

| Label / site | Source function | Location A → D1 | Measured scope |
| --- | --- | --- | --- |
| `router_build` | `OctofsServer::call_tool` | `src/mcp/server.rs` 2426 → 2435 | Original router construction only; no native audit/dispatch CPU. |
| `prepare_observation` | `prepare_observation` | `src/mcp/runtime/ssh.rs` 261 → 261 | Original bounded field check, request Value construction, command retrieval/copy, JSON encoding and payload validation. |
| `logical_admission` | `Proxy::enqueue` | `src/mcp/runtime/ssh_observation_pool.rs` 329 → 331 | Immediate admission16 try-acquire/error mapping; this does not wait for capacity. |
| `validation_worker` | `Core::verify_files (retained blocking closure)` | `src/mcp/runtime/ssh_observation_pool.rs` 689 → 708 | Whole worker full-file validation loop, shell resolution and policy checks; no semaphore/worker-queue wait. |
| `validation_owner` | `Core::verify_files (ticket.finish)` | `src/mcp/runtime/ssh_observation_pool.rs` 695 → 716 | Owner-thread fresh full-file pass plus current-owner, boundary, stop and deadline checks. |
| `socket_and_boundary` | `Core::execute_inner (peer lookup)` | `src/mcp/runtime/ssh_observation_pool.rs` 1501 → 1590 | Only profile::peer(&stream); not the surrounding root/socket/UID comparisons or connect wait. |
| `arguments` | `Core::arguments` | `src/mcp/runtime/ssh_observation_pool.rs` 742 → 767 | Original SSH argv/options construction; excludes execute_inner's later request.command.clone(). |
| `expected_argv` | `Core::spawn (expected argv bytes)` | `src/mcp/runtime/ssh_observation_pool.rs` 870 → 897 | Original NUL-delimited expected argv Vec required by post-exec proof. |
| `spawn` | `Core::spawn (Command::spawn)` | `src/mcp/runtime/ssh_observation_pool.rs` 882 → 912 | Only parent-side Command::spawn call; excludes pidfd_open/registry insertion/proof/reap and is not pure fork/exec cost. |
| `process_identity` | `process_identity` | `src/mcp/runtime/ssh_observation_pool.rs` 464 → 481 | Original /proc stat, exe metadata, UID metadata and cmdline reads/parsing; invocation count can vary. |
| `decode_observation` | `run_job_observation` | `src/mcp/runtime/ssh.rs` 368 → 370 | Original response JSON parse/error construction; remote exit-status handling precedes this span. |
| `audit_prepare` | `prepare_audit_at` | `src/mcp/runtime/jobs.rs` 2312 → 2312 | Original event Value construction, serialization and newline; shared audit helper, observation context only. |
| `audit_mutex` | `append_audit_with (AUDIT_LOCK)` | `src/mcp/runtime/jobs.rs` 2346 → 2348 | Synchronous mutex acquisition and error mapping; CPU and elapsed wall differ; preceding create_dir_all is outside. |
| `audit_critical` | `append_audit_with / append_audit_prepared_with` | `src/mcp/runtime/jobs.rs` 2350 → 2354 | Original critical operation including file/path checks, write, mandatory sync and final validation; inclusive of AuditWrite/AuditSync. |
| `audit_write` | `append_audit_at_with (Unix)` | `src/mcp/runtime/jobs.rs` 2431 → 2437 | Original whole prepared event write_all only. |
| `audit_sync` | `append_audit (synchronize closure)` | `src/mcp/runtime/jobs.rs` 2459 → 2465 | Mandatory per-event file sync_data; no directory sync included in this label. |
| `encode_observation` (status_job) | `status_job` | `src/mcp/runtime/jobs.rs` 4431 → 4448 | retain_observation_after_audit plus original pretty JSON encoding for status. |
| `encode_observation` (read_job) | `read_job` | `src/mcp/runtime/jobs.rs` 4515 → 4539 | retain_observation_after_audit plus original pretty JSON encoding for read; excludes the earlier unconditional seven-field request Value. |

Source links: [server](https://github.com/TrillionniumFoundation/hepta-runtime/blob/9f3dd5a8e3ebbac4631527a7710d41570ca78a85/src/mcp/server.rs), [jobs](https://github.com/TrillionniumFoundation/hepta-runtime/blob/9f3dd5a8e3ebbac4631527a7710d41570ca78a85/src/mcp/runtime/jobs.rs), [SSH preparation](https://github.com/TrillionniumFoundation/hepta-runtime/blob/9f3dd5a8e3ebbac4631527a7710d41570ca78a85/src/mcp/runtime/ssh.rs), [pool](https://github.com/TrillionniumFoundation/hepta-runtime/blob/9f3dd5a8e3ebbac4631527a7710d41570ca78a85/src/mcp/runtime/ssh_observation_pool.rs).

## What would establish a material CPU cost

1. First retain the already required native/owner closure and OFF/ON perturbation checks. Join raw events by the original native request ID and its interval, and select **measured** requests only. Do not divide whole-trace CPU, which also contains preflight/warmup/restart, by 192.
2. For each ON cell, report summed **exclusive synchronous thread CPU** per measured call, phase invocation counts, and per-host/status/read distributions. In particular, do not add inclusive `audit_critical` to its nested `audit_write` and `audit_sync`. Wall spans overlap and are not additive.
3. Compare to the original same-PID/start-ticks whole-controller CPU interval only if it brackets the same request set. Keep any mismatch or signed residual explicit. Native audit workers, reference checks, context bookkeeping, Tokio work, maintenance and other uninstrumented work can remain in that residual.
4. Use absolute cost as well as a fraction. As an illustration using the earlier **rough controller-only** 20 ms/call context, 20 μs/call is 0.1%, whereas 1 ms/call is 5%. These are arithmetic examples, not D1 measurements or a new gate. An isolated microsecond cost does not justify another full optimization qualification.
5. Large synchronous wall with little thread CPU means off-CPU time is present; it does not identify disk, a mutex, scheduling or network by itself. Large `capture`/`child_wait` wall does not measure SSH-child CPU or remote-helper CPU. No residual is labeled “network”.

The ordinary warm successful path has six `validation_worker` and six `validation_owner` full-set calls (three profile checks × two file verifications × worker/owner). The underlying six-file calls retain every original full read and authority check. This is not 72 physical disk reads or 72 SHA computations: R24 already uses bounded startup-verified reference bytes for eligible public executables, and `ring` SHA256 otherwise. Both profile and implementation are unchanged in D1. See [R24 PinnedFile::verify_checked](https://github.com/TrillionniumFoundation/hepta-runtime/blob/baab4def80be7af015b2e7a594cb302f66c4130e/src/mcp/runtime/ssh_observation_profile.rs#L281) and `Core::verify_files`. Cold renewal/error paths can have different counts.

## Narrow hypotheses, conditional on actual C1 costs

| Priority if evidence supports it | Evidence needed | Permitted next question; preservation constraint |
| --- | --- | --- |
| 1. Validation data path | Worker + owner exclusive CPU is a material, repeatable share in both ON rounds, with the expected call counts. Wall/CPU separation must be retained. | Locate the cost inside the existing fresh-open/full-read/byte-compare-or-hash path before choosing a patch. R24 already has `ring` and public-executable references. No skipped pass, cached FD/content/authority, reduced identity/deadline check, or automatic replay of R33 path caching is justified. D1 aggregates cannot by themselves distinguish lexical allocation, kernel reads, comparison, hash, shell resolution and metadata work. |
| 2. Observation preparation and JSON | `prepare_observation`, `decode_observation`, `encode_observation` and/or `audit_prepare` have material exclusive CPU after operation/output-size separation. | Consider only an observation-scoped elimination of a demonstrably redundant temporary or copy, preserving exact payload/result/error and durable-audit ordering. Shared audit preparation is also used by lifecycle operations, so a global serializer/lock change is not assumed safe. R35's earlier unused `read_job` request Value and later command clone lie **outside** the adjacent D1 wrappers; these phase totals cannot attribute their individual cost. |
| 3. Process/transport attribution, not an immediate patch | `spawn` CPU is substantial, or named CPU is small while capture/child/proof wall dominates and the controller residual is large. | Separate parent spawn CPU from original SSH-child accounting and remote helper startup/CPU before any persistent-channel design. The current trace cannot supply those two process CPU totals. Do not replace ownership/proof/reap with a persistent worker, relax deadlines, or add a second reaper on this evidence. |

These are conditional investigation directions, not three approved implementation candidates. If no material synchronous bucket emerges, the useful conclusion is that this C1 trace does not justify another small allocation patch.

## Known prior directions and cancellation protection

The prior experiment outcomes are already closed in the parent session; this note does not rerun or re-adjudicate them:

- **R31:** pidfd cancellation readiness was not adopted. The D1 status/read trace does not measure cancellation-helper wait and cannot validate that direction.
- **R33:** path-component allocation reduction did not pass the required C8 throughput gate. High validation totals would still need finer evidence; they do not reverse that outcome.
- **R34:** cancellation reserve was rejected by normal observation C8 throughput. C1 queue spans do not establish an 8+1 direct-transport saturation benefit or warrant capacity changes.
- **R35:** isolated R26 JSON deferral plus command ownership movement passed observation nonregression with mixed changes, then failed mandatory normal concurrent-cancel throughput (B/A approximately 0.92939). Aggregate all-operations improvement did not override that gate.
- **R30:** router sharing was not adopted after one original status deadline failure. No cause is assigned to router code or environment. A large `router_build` number would be a reason to investigate, not authority to reuse it.
- Prior R27-scale argument/serializer allocation work was already considered at microsecond scale; `arguments` and `expected_argv` need materially larger actual evidence before another qualification is useful.

Any future optimization must keep the accepted direct cancellation path, leases through actual reap, original helper/ACK-versus-terminal semantics, full profile/owner checks and per-event durability intact. Observation-local scope reduces coupling but does **not** prove lifecycle cancellation throughput is preserved. The original full qualification, observation and mandatory normal lifecycle gates remain required for adoption. No runtime source, gate, host state or frozen package was changed for this mapping.

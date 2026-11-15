# REA audit metadata query: main ext4 qualification

**Status: qualified for the fixed workload and resource window recorded here.**

The original durable job `1a1a2dc9e85-96a-7539` completed with exit code 0 and complete stdout/stderr. It was not cancelled or timed out, and the owner reported no truncation or log errors. The driver completed every scheduled item with zero retries and no Cargo invocation.

| Scheduled work | Result |
| --- | --- |
| Historical baseline A: original 64-publication case, four runs | 4 / 4 passed |
| Candidate B: original 64-publication case, four runs | 4 / 4 passed |
| Candidate B: 15 exact warm/cold/capacity/cancellation/deadline/content regressions | 15 / 15 passed |
| Baseline and candidate test listings | 2 / 2 passed |

The baseline also passed in this window. These results do not demonstrate a performance improvement. The earlier failed ext4 diagnostic remains preserved in [the historical diagnostic](../rea-audit-budget-diagnostic-20261103-r1/README.md); it has not been replaced, filtered out, or relabelled.

## What was exercised

The fixed sequence was **A B B A B A A B**, without retrying or selecting runs according to baseline outcomes. Each publication invocation selected exactly one test:

`mcp::runtime::request_audit::index::tests::large_pending_view_remains_exact_while_continuous_publications_progress`

The original three-second absolute metadata query deadline and exact content/count/cache/durability assertions remained in force. The full duration of a 64-publication test is not a single-query deadline measurement.

| Run | Variant | Whole-test wall time, seconds | Exit |
| --- | --- | ---: | ---: |
| 01-A-publication | A | 3.012270 | 0 |
| 02-B-publication | B | 3.056324 | 0 |
| 03-B-publication | B | 7.847285 | 0 |
| 04-A-publication | A | 2.813761 | 0 |
| 05-B-publication | B | 3.059137 | 0 |
| 06-A-publication | A | 2.810535 | 0 |
| 07-A-publication | A | 3.085217 | 0 |
| 08-B-publication | B | 3.127618 | 0 |

All 15 candidate regressions completed successfully:

| Case | Whole-test wall time, seconds |
| --- | ---: |
| `warm_usage_keeps_its_admitted_store_turn` | 0.192301 |
| `large_cache_preparing_reply_does_not_wait_for_the_query_budget` | 0.114365 |
| `bounded_index_capacity_waits_without_retiring_live_callers_or_blocking_writers` | 0.370741 |
| `large_pending_view_cannot_publish_while_a_taken_worker_cohort_is_in_flight` | 0.246902 |
| `metadata_deadline_does_not_leave_a_blocking_query_behind_the_store_lock` | 0.031712 |
| `audit_store_timed_cancellation_removes_head_and_middle_waiters` | 4.009520 |
| `large_pending_view_preserves_exact_states_tools_owners_and_cursor_pages_without_writes` | 0.333383 |
| `large_pending_view_rechecks_the_final_watch_and_each_returned_original_stamp` | 0.360486 |
| `metadata_query_cancelled_while_waiting_never_spawns` | 0.008828 |
| `metadata_query_cancelled_worker_retains_capacity_until_exit` | 0.008903 |
| `metadata_query_timed_out_worker_retains_capacity_until_exit` | 0.260806 |
| `metadata_query_expired_in_blocking_queue_never_runs` | 0.260996 |
| `metadata_query_preserves_result_and_original_deadline` | 0.008753 |
| `metadata_query_ready_success_consumed_after_deadline_is_refused` | 2.009999 |
| `archive_query_expired_deadline_does_not_open_missing_store` | 0.008226 |

The warm admission regression covers keeping the same admitted FIFO store turn. The remaining cases cover cold preparation, capacity waits, an in-flight worker cohort, deadline expiry, timed queue cancellation, exact owner/tool/state/content results, final watch and original stamp validation, cancelled/timed-out worker capacity ownership, and rejecting late results.

## Environment and process ownership

Every invocation used a short private TMPDIR on the historical main filesystem: `/dev/sda2`, ext4, mount `/`, device 2050, uid 1000, directory mode 0700. The driver checked the filesystem before and after each case. The actual exec child umask was 0022 for all 25 invocations, including the two listings.

The private fixture root was `/home/qian-qi/work/ha-7nj3v_07`. Host PSI, cgroup limits/pressure, process observations, stdout, stderr, argv, wall time, wait4 resource usage, and process identity/terminal records are retained under [run/](run/). All recorded owned process identities have pidfd exit confirmation; no case lost wait ownership, timed out, or required a termination reason.

The driver used pinned regular executable inodes, copied from a single source FD, fixed at mode 0500, rehashed, and executed through retained read-only FDs. The two approximately 575 MB executable copies remain at the recorded host paths and are deliberately excluded from this repository evidence directory.

This qualification is limited to the fixed 64-publication workload, the named regressions, and the observed main ext4 resource window. It is not a production capacity, steady-state RSS, all-workload latency/SLA, or hardware-independent claim.

Both variants had `HEPTA_ARCHIVE_INDEX_TRACE=1`. The old `metadata_drain` trace and the new `metadata_snapshot` trace have different scopes; this report does not compare their numeric fields as equivalent durations or calculate a speedup from them.

## Binary and source provenance

| Item | SHA256 |
| --- | --- |
| Frozen qualification driver | `c62bc491ed6a1046e59a82784fd535b4f48cd7149bd54cfe042134fa15183f82` |
| Historical baseline A test library | `7ec5383c2f5f56006564fb2eb3f8f7c72027c73f94f7c5e524cf7567ab8f90ed` |
| Candidate B test library | `924180ac166d07051d2aae8ffb349a99c086ad4964f420ddb5f089fbefedcd91` |
| Candidate source inventory | `0d4d316c6ea9de52276e359e711749a404d3e60191c4d37d7fcd8dcb2c39a28c` |
| Candidate full source diff | `79cef8bff8213a1f159c310a98ce5fdf29505113745a93b07debd2f61ef651ec` |
| Actual run summary | `317e98fd4a33974a5354bb1a7d547b817cbefbb42cae25d34fb48334a1fed2ae` |
| Original owner exit receipt | `3a3cd19662973a6e84a6901bd818d94166349742e7514775793b10b850f70b4c` |

The candidate is **HEAD `23246a5313957e9e97e324303bc47a91808f1ea8` plus six reviewed Rust modifications**, with the recorded dirty diff; it is not labelled a clean commit build. Its all-feature test artifact records features `default` and `remote-fs`. The historical baseline binary is identified by its own hash and retained feature/source evidence; matching relevant historical audit/usage sources does not claim that its entire old build is the current commit.

Before execution, the expanded integration worktree was moved intact to `/home/qian-qi/hepta-runtime-rea-blockers-integration-20261103-r1`. All tracked and untracked paths retained their inode identities and metadata. The original build path `/home/qian-qi/hepta-runtime-rea-blockers-20261103-r1` was restored as a detached frozen checkout with only the six Rust modifications. Its complete diff and all 7,902 original source-manifest file hashes, sizes and modes were verified. That frozen path remains unchanged.

The r2 build provenance retains the original aggregation-regex failure: compilation and the warm test had actually exited 0, but the wrapper failed to recognize the success summary. The subsequent [r3 continuation result](preparation/candidate-build-r3-result.json) is qualified and reused the same artifact. Neither record was rewritten to hide the earlier wrapper failure. The ext4 driver independently validated artifact/compiler/source linkage; it did not require the r2 whole-run qualified flag to be true.

## Evidence layout

- [run/summary.json](run/summary.json): complete machine-readable outcome and per-invocation records.
- [run/SHA256SUMS](run/SHA256SUMS): unchanged original driver text-evidence inventory.
- [operator/exit.json](operator/exit.json), [operator/launch.json](operator/launch.json), and the two operator logs: the original durable execution and its final owner receipt.
- [package-provenance.json](package-provenance.json) and [postflight.json](postflight.json): copy boundaries, independent result checks and identity references.
- [preparation/layout/](preparation/layout/): worktree migration identities, original full source verification and layout receipt.
- [preparation/README.md](preparation/README.md): frozen pre-execution instructions retained as a historical preparation record. Its earlier prepared status does not describe the completed execution.

All 174 regular non-pin files from the actual driver output (6,405,605 bytes) are copied byte-for-byte under `run/`; none of those text evidence files was selected out. The package also retains preparation/layout and original owner records. No experiment was rerun during packaging.

## Verify the retained files

From this directory:

```sh
sha256sum -c SHA256SUMS
(cd run && sha256sum -c SHA256SUMS)
```

The top-level inventory covers the delivered package except itself. The nested inventory preserves the exact original driver evidence paths and hashes. Both inventories were verified after copying.

Run finished at `2026-11-03T19:23:14.035892+00:00`.

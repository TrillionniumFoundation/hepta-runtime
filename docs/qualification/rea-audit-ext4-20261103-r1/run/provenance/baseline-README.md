# Single-run audit metadata budget diagnostic — 2026-11-03

## Outcome

The one authorized diagnostic execution **reproduced the failure** on private ext4 fixtures. The test process exited **101** after **17.142 seconds** (the Rust harness reports 17.08 seconds). The authoritative outer operator job `1a1a1df40b7-96a-7194` is **failed**, exit 101, with complete output; it was neither cancelled nor timed out.

The captured anyhow construction stack identifies the rejection at **the final exclusive audit-store lock acquisition**, before that attempt built its pending view or verified original records:

- `request_archive_index.rs:1756`: `query_lock` maps a store-lock deadline failure.
- `request_archive_index.rs:1936`: `read_snapshot_with_mode` requests the final snapshot lock.
- `request_archive_index.rs:2651` → `request_usage_batch.rs:504`: usage snapshot.
- `request_usage_batch.rs:439,474` → `request_audit.rs:2018,2011`: synchronous single-owner query.
- `request_archive_index_tests.rs:2959`: the concurrent observation that returned the error.
- `request_archive_index_tests.rs:3003`: later assertion unwrap after writer join and completion checks.

The preceding real-completion checks passed: the writer joined successfully, all 64 completion sequence/timestamps were present, and every measured durable-completion gap was below the unchanged 10-second progress watchdog. The assertion still failed on a recorded metadata-query error; the remaining final totals/cache/flush checks were not completed.

This is diagnostic evidence, **not a passing gate or a repair** of the earlier ext4 failures.

## Timing evidence and its limits

The failing `metadata_drain` trace reports:

| Field | Observed value |
|---|---:|
| `elapsed_us` | 989805 |
| `store_lock_wait_us` | 989804 |
| `state_us` | 0 |
| `snapshot_read_us` | 0 |
| `input_rows` | 0 |
| `outcome` | `error_or_unwind` |

The field measures the final acquisition phase, including error construction; it is not a direct kernel syscall timer. The original **3-second absolute query budget** also covers earlier hot/archive work and earlier lock acquisitions. This trace starts only after `ready()` returns. It does not attribute earlier budget consumption to individual stages.

The log also contains eight successful slow-phase traces, with `readonly_pending` outcomes and 34–58 pending rows. Each of those logged successful snapshots spent approximately 1.9–3.3 ms in `snapshot_read_us`; their final acquisition phases took approximately 98–353 ms. These are the traces exceeding the existing 100 ms emission threshold, **not an enumeration of every query**.

For this captured error, the construction stack is not inside the content scan or the `ready()` preparation loop. It establishes final lock-admission deadline exhaustion under the concurrent writer workload. It does not measure individual writer fsync operations, prove an exact lock-holder history, or establish that every earlier timeout had the same origin. The trace and backtrace have diagnostic overhead.

In the general implementation, a successful original write does not by itself certify a healthy disposable index: publication note/watch failures can invalidate the index without changing the original write result. That was a legitimate alternative before this diagnostic. No new state-field instrumentation was added, and this record does not claim exhaustive exclusion of every earlier transient state.

Host observations also show nonzero I/O pressure (IO `some avg10` 16.65% before and 18.64% after; `full avg10` 15.80% and 17.84%). CPU PSI `some avg10` was 0.00% at those endpoints. These are host-wide endpoint observations, not proof that a specific fsync caused the rejection. Root's separate full tmpfs gate could overlap this run, so it is not an isolated latency benchmark.

## Exact executable and source linkage

The executable is the existing all-features **test library**, not the CLI:

- Original: `/home/qian-qi/work/hepta-rea-full-20261103-r1-target/debug/deps/hepta_runtime-6697a3b98397d108`
- Fixed private copy: `/home/qian-qi/work/hepta-rea-audit-budget-diagnostic-20261103-r1/hepta-runtime-all-features-test-lib`
- SHA256: `7ec5383c2f5f56006564fb2eb3f8f7c72027c73f94f7c5e524cf7567ab8f90ed`
- Size: **573,870,560 bytes**
- Cargo test-lib fingerprint: features `["default", "remote-fs"]`, rustflags `[]`, profile fingerprint `7985834027869059696`.
- Watchdog source SHA256: `b2f60424f1e72a5c474bf47e0bf109a6e0692d85fabe83f67677c6d4c3299788`.
- Frozen source tree: `eff016991ae56572d55f6ba487550c8ded550a68028a0c24184ec75aa52e64d7`.

Identification combined the same-suffix Cargo test-lib fingerprint, dependency-file membership of the changed test source, executable/fingerprint timestamps within the source-monitored final-focused build, and the new watchdog's distinctive strings found in the executable bytes. An exact harness listing confirmed that the selected test exists and is the sole selected test. The prior source-before/source-after manifests match and their source monitor recorded zero events. All 555 recorded source paths were rechecked before and after this diagnostic with no byte/size/mode differences. Root's separate gate monitor covers additions/deletions beyond those recorded paths.

The copy used one opened source FD, hashed the bytes while copying, checked source identity/length/mtime/ctime before and after, and hashed the destination through its open FD. The fixed file is mode 0500; its identity and timestamps remained unchanged after execution. These records establish source/build linkage; Cargo metadata itself is not a cryptographic source attestation. Older test-library binaries were not selected.

## Execution contract

There was **one actual test invocation**, no retry and no Cargo invocation. A prior `--list --exact` invocation only identified the test.

Actual argv, also preserved in `execution-started.json` and `result.json`:

```text
/home/qian-qi/work/hepta-rea-audit-budget-diagnostic-20261103-r1/hepta-runtime-all-features-test-lib
--exact
mcp::runtime::request_audit::index::tests::large_pending_view_remains_exact_while_continuous_publications_progress
--nocapture
--test-threads=1
```

The child uses an explicit environment allowlist. The material settings are:

```text
TMPDIR=/home/qian-qi/work/hepta-rea-audit-budget-diagnostic-20261103-r1/ext4-fixtures
RUST_LIB_BACKTRACE=1
HEPTA_ARCHIVE_INDEX_TRACE=1
RUST_TEST_THREADS=1
```

The child launch set umask 0022, and the actual child `/proc/PID/status` reported **0022**. The parent remained 0077. The private fixture root is owned by UID 1000 with mode 0700, on `/dev/sda2`, filesystem **ext4**, mount options `rw,relatime`. Its directory was empty after the test unwound.

The 3-second production query budget, test assertions, 64-operation workload, source files, compiled target directory and root's running gate were unchanged. No other job was cancelled or stopped. The exact driver is preserved as `diagnostic-driver.py`; it intentionally refuses to reuse its existing workspace/evidence paths and contains no retry loop.

## Evidence inventory and publication boundary

- `test.stdout.log`, `test.stderr.log`: complete raw output from this exact test invocation, including the construction backtrace and archive phase traces.
- `test-list.*.log`: exact-name harness listing only.
- `binary-provenance.json`, `selected-test-lib-fingerprint.json`: pinned executable and build linkage.
- `environment.json`, `execution-started.json`, `result.json`: explicit environment, actual argv, process identity, endpoint pressure observations and cleanup result.
- `operator-job-status.json`, `operator-launch-receipt.json`: authoritative terminal status and selected actual launch fields.
- `source-verification-before.json`, `source-verification-after.json`: current 555-file source checks.
- `prior-source-*.json`, `prior-summary.json`: the already completed failed final-focused run's source/build context, copied unchanged.
- `analysis.json`: mechanically extracted trace rows and the bounded diagnostic conclusion.
- `SHA256SUMS`: hashes of all other files in this evidence directory.

The raw logs and copied metadata were inspected before closeout: they contain source/build paths, numeric diagnostics and this synthetic test's failure, with no credentials. The executable, actual private audit/archive state, fixture databases and production configuration are not included in this documentation directory.

The earlier [failed final-focused run](../rea-final-focused-20261103-r1/summary.json), the original r3 failure, and any later tmpfs/GitHub results remain separate records. Passing in another environment would not erase this ext4 lock-admission budget rejection or qualify physical power-loss durability.

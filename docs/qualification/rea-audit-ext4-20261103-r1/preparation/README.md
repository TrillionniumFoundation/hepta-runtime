# Ext4 audit admission qualification driver — 2026-11-03

## Delivery status

This is a **prepared driver**, not a passing qualification report. Its author
performed source review and Python AST/bytecode compilation without executing
the driver, either test library, a harness listing, or Cargo. Root selects the
resource window and runs the qualification separately. The three audit Rust
files in the author's dedicated worktree remain frozen.

The compiled three-second metadata query deadline, original 64-publication
workload, exact result assertions, cache checks and durability barriers are
unchanged.

## Pinned artifacts and source claims

| Variant | Input under `candidate-build-r2/` | SHA256 |
|---|---|---|
| A: historical failed baseline | `baseline-test-lib` | `7ec5383c2f5f56006564fb2eb3f8f7c72027c73f94f7c5e524cf7567ab8f90ed` |
| B: candidate all-features test library | `all-test-build-lib` | `924180ac166d07051d2aae8ffb349a99c086ad4964f420ddb5f089fbefedcd91` |

The build directory is
`/home/qian-qi/work/hepta-rea-blockers-20261103-r1/candidate-build-r2`.

The baseline's original fixed copy is read from the retained
[diagnostic evidence](../rea-audit-budget-diagnostic-20261103-r1/README.md):
`/home/qian-qi/work/hepta-rea-audit-budget-diagnostic-20261103-r1/hepta-runtime-all-features-test-lib`.
A later copy is accepted by identical expected content hash, not by pretending
it has that historical inode.

The baseline predates commit `23246a5313957e9e97e324303bc47a91808f1ea8`.
The driver checks the old evidence against its recorded Git objects, then
compares all 40 `request_audit*`, `request_archive*`, `request_usage*` and
`request_metadata*` Rust files, including tests, plus `Cargo.toml` and
`Cargo.lock`, against that commit. It checks the saved fingerprint's
`["default", "remote-fs"]` features, empty rustflags, equal source manifests and
completed zero-event monitor. The earlier failed result remains in the evidence.
**This does not label the entire older executable as a 23246 build.**

The candidate is **23246 plus six reviewed modifications**, with a dirty-source
manifest. Existing r2 evidence identifies:

- Test-library size: 574,527,992 bytes.
- Source inventory: `0d4d316c6ea9de52276e359e711749a404d3e60191c4d37d7fcd8dcb2c39a28c`.
- Dirty diff: `79cef8bff8213a1f159c310a98ce5fdf29505113745a93b07debd2f61ef651ec`.
- Features: `default` and `remote-fs`.
- A successful `all-test-build` stage and matching Cargo `compiler-artifact`
  message for the library test target.
- Equal source manifests, unchanged head/diff and a completed monitor with
  zero events and errors.

The r2 enclosing `qualified=false` is preserved: its later summary regex
rejected an actual exit-zero warm test. The driver independently requires
compilation exit zero, the matching artifact, original compile argv and stable
monitored inputs. It does not require the enclosing runner to claim full
qualification, erase the runner failure, or label the candidate a clean commit.

Current related sources and all six dirty paths are checked against that build
manifest. Current Git head and binary diff must match. Source state and fixed
executables are checked again at the end. These records establish build
linkage; they are not a cryptographic compiler attestation.

## Fixed schedule

A always means baseline; B always means candidate.

| Position | Variant | Workload |
|---|---|---|
| 1 | A | Original 64-publication case |
| 2 | B | Original 64-publication case |
| 3 | B | Original 64-publication case |
| 4 | A | Original 64-publication case |
| 5 | B | Original 64-publication case |
| 6 | A | Original 64-publication case |
| 7 | A | Original 64-publication case |
| 8 | B | Original 64-publication case |

**ABBA BAAB gives four planned invocations per variant, with zero retries.**
Baseline success does not trigger a search for failure. Baseline failure does
not select or filter candidate observations. Ordinary failures are retained
and the remaining predetermined cases run.

Candidate then runs these 15 exact regressions once:

1. `warm_usage_keeps_its_admitted_store_turn`
2. `large_cache_preparing_reply_does_not_wait_for_the_query_budget`
3. `bounded_index_capacity_waits_without_retiring_live_callers_or_blocking_writers`
4. `large_pending_view_cannot_publish_while_a_taken_worker_cohort_is_in_flight`
5. `metadata_deadline_does_not_leave_a_blocking_query_behind_the_store_lock`
6. `audit_store_timed_cancellation_removes_head_and_middle_waiters`
7. `large_pending_view_preserves_exact_states_tools_owners_and_cursor_pages_without_writes`
8. `large_pending_view_rechecks_the_final_watch_and_each_returned_original_stamp`
9. `metadata_query_cancelled_while_waiting_never_spawns`
10. `metadata_query_cancelled_worker_retains_capacity_until_exit`
11. `metadata_query_timed_out_worker_retains_capacity_until_exit`
12. `metadata_query_expired_in_blocking_queue_never_runs`
13. `metadata_query_preserves_result_and_original_deadline`
14. `metadata_query_ready_success_consumed_after_deadline_is_refused`
15. `archive_query_expired_deadline_does_not_open_missing_store`

The first eight use `mcp::runtime::request_audit::index::tests::`; the remaining
seven use `mcp::runtime::request_audit::query_tests::`. `plan.json` records full names.

One listing per binary verifies every required exact name before any test runs.
Each test uses `--exact`, `--nocapture` and `--test-threads=1`; passing requires
exit zero and exactly one passed test, with zero failed or ignored tests.
A zero-test selection cannot pass.

The complete schedule has **23 scheduled top-level test invocations and two listings**.
The existing warm-handoff and capacity fixtures may spawn their own test-library
children. Those are fixture implementation details, not retries; the driver
tracks their custody and terminal state. Per-run raw logs cover the top-level
stdout/stderr and inherited streams, preserving the fixtures' existing internal
output redirections.
All four candidate publication runs and all 15 regressions must pass.
Baseline failure is not a prerequisite. Missing runs, driver/log-limit errors,
changed identities, incomplete logs or unconfirmed termination prevent
qualification.

## Prepared invocation

Run after the compilation/resource window is clear. This command is prepared;
it has not been executed by the driver author:

```sh
python3 /home/qian-qi/hepta-runtime-rea-audit-20261103-r1/docs/qualification/rea-audit-ext4-20261103-r1/qualification-driver.py \
  --baseline /home/qian-qi/work/hepta-rea-blockers-20261103-r1/candidate-build-r2/baseline-test-lib \
  --baseline-sha256 7ec5383c2f5f56006564fb2eb3f8f7c72027c73f94f7c5e524cf7567ab8f90ed \
  --candidate /home/qian-qi/work/hepta-rea-blockers-20261103-r1/candidate-build-r2/all-test-build-lib \
  --candidate-sha256 924180ac166d07051d2aae8ffb349a99c086ad4964f420ddb5f089fbefedcd91 \
  --source-root /home/qian-qi/hepta-runtime-rea-blockers-20261103-r1 \
  --candidate-provenance /home/qian-qi/work/hepta-rea-blockers-20261103-r1/candidate-build-r2 \
  --output /home/qian-qi/work/hepta-rea-audit-ext4-20261103-r1 \
  --tmp-parent /home/qian-qi/work
```

`--output` must be a new independent directory outside the source checkout.
Existing evidence is never reused or overwritten. The driver neither commits
nor publishes files into repository documentation.

`--candidate-provenance` accepts the r2 build directory or a JSON manifest of
absolute references. A directory containing `provenance.json` uses that
manifest. This permits r3 to retain explicit links to the r2 artifact:

```json
{
  "launch": "/absolute/candidate-build-r2/launch.json",
  "source_before": "/absolute/candidate-build-r2/source-before.json",
  "source_after": "/absolute/candidate-build-r2/source-after.json",
  "artifact": "/absolute/candidate-build-r2/all-test-build-artifact.json",
  "build_result": "/absolute/candidate-build-r2/result.json",
  "continuation_result": "/absolute/candidate-build-r3/result.json"
}
```

`continuation_result` is optional and preserved verbatim. `build_result` points
to the record containing the successful `all-test-build` stage, original
source monitor and artifact linkage. Later continuation stages do not replace
those compiler records.

## Executable, fixture and process contract

Inputs open with `O_NOFOLLOW`, `O_NONBLOCK` and `O_CLOEXEC` and must be bounded
regular inodes. Copying reads **one source FD**, hashes its exact bytes, checks
source identity/length/mtime/ctime before and after against the named path,
rehashes through the destination FD, sets mode 0500 and closes every writable
copy FD. Each fixed executable retains a read-only FD. The child executes
that FD, so path replacement cannot redirect execution. Identity is checked
around every invocation; both fixed FDs are rehashed after the schedule.

Parent umask is 0077. Each test-library child has **umask 0022** and an explicit
environment allowlist. A ready/go exec shim lets the parent inspect
`/proc/PID/status` Umask and mount namespace before releasing even a fast
test. The shim executes the pinned FD and preserves that mask. Both variants
use `HEPTA_ARCHIVE_INDEX_TRACE=1`, `RUST_LIB_BACKTRACE=1` and
`RUST_TEST_THREADS=1`.

`TMPDIR` is explicit, mode 0700 and no more than 48 encoded bytes. A unique
`ha-*` fixture parent is created beneath the short `--tmp-parent`, with one
directory per invocation. `findmnt` and inode/device observations must show
**ext4 on the same device, source, mount and account as the original main-host
diagnostic**. The launch namespace is observed; filesystem/device checks also
follow each case. The driver cannot silently substitute tmpfs. Fixture
locations remain available for inspection.

The standalone, single-threaded driver is the sole reaper of its children.
It uses independent sessions, Linux subreaper support and pidfds. Process-group
signals are allowed only while the original leader remains unreaped and wait
ownership has not been lost. Afterwards, signals use bound pidfds. Descendant
discovery verifies the parent's live pidfd and the child's parent/start
identity; it does not act on unrelated host PIDs.

Exited, unreaped descendants reuse their recorded identity rather than
accumulating pidfds. Adopted children can be reaped while the leader remains
alive. After every known process exits, a final discovery/reap pass must also
show that the supervisor has no remaining children before it reports terminal.
Once SIGKILL cleanup begins, newly discovered live descendants also receive
SIGKILL through their pidfds.

Signal handlers only record interruption, allowing cleanup to finish.
`wait4` and pidfd exit observations establish terminal state. Sending a signal
is not sufficient. Unexpected child-wait ownership loss remains a failed result
with unavailable status, rather than becoming success through a `Popen` fallback.
No unrelated process, service or workspace is stopped or cleaned.

## Bounds and preserved evidence

Fixed limits:

- 120 seconds per child invocation, including the controlled launcher.
- 1,800 seconds for suite scheduling; no later case starts after that bound.
- Two seconds of SIGTERM grace before SIGKILL of owned processes.
- 8 MiB per-invocation and 128 MiB total runtime-log thresholds, including
  stdout, stderr and observation samples.
- At most 2 GiB per input executable; free space for both copies plus 1 GiB;
  at least 256 MiB of fixture space before each case.

Log limits trigger termination rather than silent truncation. Buffered bytes
are retained, so a finite pipe/sample spill can exceed a threshold and is
counted. Periodic observations stop at the log bound. A log-limit intervention
prevents qualification. Each failure retains its raw output, original exit
status and termination reason.

SIGKILL cannot force an immediate return from a kernel-uninterruptible syscall.
After 15 seconds, `terminal-pending.json` records cleanup still pending.
The driver waits for actual owned-process exit and starts no further case.
This exceptional cleanup can exceed the scheduling budget; it cannot fabricate
terminal or successful timeout receipts. The outer operator job must also
reach its confirmed terminal state.

Per-invocation evidence includes:

- Actual test argv, launcher argv, explicit environment and observed child data.
- Raw stdout/stderr, byte counts and SHA256.
- Exit code or negative terminating-signal encoding, timeout/interruption reason,
  wait-ownership state, pidfd terminal observations and adopted-child reaps.
- Launch, execution, process-custody and record-completion wall times, with raw
  `wait4` CPU, RSS, I/O and context-switch values.
- Host PSI/load; child status/I/O; readable cgroup limits/statistics and ancestors.
  Sampling occurs once per second within the log bound. Unavailable or bounded
  observations are marked explicitly.
- Fixture mount/device and source/executable identity checks.

Execution wall time starts when the parent releases the shim and ends when it
observes the leader's actual exit, including the small exec transition.
Raw child CPU includes that same Python shim for both variants; it is not
presented as pure Rust CPU time.

Baseline `metadata_drain` starts after `ready()`. Candidate
`metadata_snapshot` starts at initial admission and includes hot/ready work
and actual reacquisitions. **The timing scopes differ.** The driver does not
subtract the fields or compute a percentage gain. The existing 100 ms trace
emission threshold also means traces are not a complete query enumeration.
The unchanged Rust assertions and complete-case outcomes establish the
functional result; pressure/timing data provide context.

`summary.json`, per-run receipts, preserved provenance and `SHA256SUMS` remain
in the independent output directory. Fixed binaries stay under `pins/`, are
recorded by `binary-pins.json` and are excluded from the text-evidence hash
inventory. They must not be published into repository documentation.

Qualification requires successful outer driver exit, `qualified=true`,
the complete fixed schedule, matching identities and complete evidence hashes.
The result covers these artifacts, named cases and observed main ext4 resource
window. It does not qualify production capacity, physical power-loss durability,
all Hepta tools, other filesystems or a comparison of unlike trace phases.

## Static preparation verification

- Python AST parse and bytecode compilation passed; no driver or test was executed.
- Baseline identity cross-check: all 42 selected source/configuration files match the recorded 23246 blobs.
- Historical fingerprint features are `default` and `remote-fs`, with empty rustflags.
- Driver SHA256 at this preparation: `c62bc491ed6a1046e59a82784fd535b4f48cd7149bd54cfe042134fa15183f82`.
- The three frozen audit Rust file SHA256 values were unchanged before and after documentation preparation.

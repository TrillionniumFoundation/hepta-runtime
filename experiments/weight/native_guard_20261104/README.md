# Native weight subsystem: software qualification record

**Status: FAILED_R8_COMPLETE. The complete local all-features gate did not pass.**

The final r8 command returned Cargo **101**. Its complete library harness
reported **1,694 passed, 2 failed and 36 ignored**, in **3,855.71 seconds**.
The command took **3,856.177191562 seconds** including a reported 0.37-second
warm build. Later harnesses and the planned formatting check were not reached.
The supervisor ended normally with the command failure; it was neither cancelled
nor timed out.

All **12 Rust source hashes** were rechecked unchanged after the command and
independently after its terminal state. The final run used a 16-byte external
private temporary path, NOFILE soft limit 1,024, one test harness worker and
the original 7,200-second outer limit. No automatic r9 was performed.

The r7 test-only repair and its targeted checks remain valid scoped evidence.
All eight focused validation, format and strict Clippy commands returned zero;
the four SSH test paths passed and the server module reported 16 passed and
4 ignored. Those checks do not clear the two failures in the later full run.

This receipt covers software builds, runtime invariants, reference forward and
ridge checks, and the all-features test attempt. Model task value, trading
outcomes and unseen-data generalization require their own evidence.

## Complete history

| Round | Work performed | Recorded outcome | Recorded wall time |
| --- | --- | --- | --- |
| r1 | Initial dependency/build plus six guard unit tests | Cargo 0; 6 passed, 0 failed | 910.954 s |
| r2 | Formatting, formatting check, default-concurrency all-features command | Cargo test 101; library harness 1,421 passed, 275 failed, 36 ignored | 1,359.923 s across all three commands |
| r3 | Formatting and strict all-targets Clippy | Both commands 0 | 145.020 s |
| r4 | Focused weight checks, owner inventory, explicit private-fixture/NumPy and PyTorch checks; then serial full suite | Focused commands 0; full suite had a known failure and was cancelled | 1,772.871 s supervisor lifetime |
| r5 | Repaired fixture quiet and perturbed checks, strict Clippy; then two-worker full suite | Completed checks 0; full suite failed because the qualification TMPDIR was inside the worktree, then was cancelled | 572.410 s supervisor lifetime |
| r6 | Corrected external TMPDIR; shell exact check and two-worker full suite | Shell check 0; existing shared-store test failed; full suite cancelled | 1,110.448 s supervisor lifetime |
| r7 | Identical source, external private TMPDIR, one-worker full suite | Cargo 101; library 1,682 passed, 14 failed, 36 ignored; later harnesses/fmt not reached | 3,694.771 s completed command |
| r7 followup | Test-only subprocess isolation repair, short TMPDIR, four SSH paths, server tests, strict Clippy and format | All 8 commands returned 0; 20 tests passed, 4 ignored across the focused commands | 397.133 s |
| r8 | Fixed 12-source identity, 16-byte external TMPDIR, one-worker full suite; formatting planned afterward | **Cargo 101; library 1,694 passed, 2 failed, 36 ignored; later harnesses/fmt not reached** | 3,856.177 s completed command |

The recorded r1–r8 wall-time sum, including the targeted followup, is **13,819.707 seconds (230.328 minutes)**.
This accounts for failed and cancelled attempts. It is not CPU/GPU consumption,
an API bill, elapsed project time, or a model-training benchmark. The completed
rounds use their command timers; cancelled rounds use the whole durable
supervisor lifetime because no final timer for their interrupted Cargo command
was produced. Diagnostic runs and between-round work are not added.

The first Cargo run reports a 15m 04s build and 0.65s of actual test execution.
The r2 all-features command reports a 9m 05s build and an 808.20s library harness.
Warm-cache later timings do not replace these initial costs. Suite timings are
not compared as performance benchmarks: failed and cancelled runs executed
different amounts of work.

## The default-concurrency failure remains a failure

The complete r2 library summary is preserved exactly:

```text
test result: FAILED. 1421 passed; 275 failed; 36 ignored; 0 measured; 0 filtered out; finished in 808.20s
```

Cargo returned 101, so later integration and documentation harnesses were not
qualified by that invocation. The receipt includes all 275 failed test names,
not only a selected sample:

| Module group | Failed tests |
| --- | ---: |
| Request audit | 229 |
| Request results | 33 |
| MCP server | 10 |
| Owner fence inventory | 1 |
| Pending-publication start I/O | 1 |
| Operation async | 1 |

One newly added mutating tool was missing from the expected owner-fence inventory
in the test. That test expectation was corrected before r4; the subsequent owner
inventory test passed. A bounded independent diagnosis reran five existing
failures in fresh processes and all five passed. That observation does not
explain or clear all 275 failures. Later runs use documented narrower harness
concurrency and do not retroactively turn the original default-concurrency run
green.

## What was repaired after r4

The pending-publication success test created a flat temporary-root/audit.jsonl.
AuditBinding derives the audit directory from the file's parent and the state
directory from that directory's parent. The fixture therefore included the shared
temporary parent in a production directory-publication integrity fence.

On a frozen r4 test executable, exactly two controlled runs used the same private
temporary parent, one test worker and NOFILE 1,024. The quiet run passed. Creating
and deleting a single unrelated marker in that parent reproduced the same panic.
The perturbation was bounded to 5,000 pairs and three seconds; the actual run
completed 770 pairs with at most one marker present and no errors.

The audit file and its immediate directory kept their identities. The state
directory kept its inode but changed mtime/ctime between the initial stamp and
validation. The traced refusal occurs during the initial AuditBinding validation,
before audit write or synchronization; there are no fdatasync/fsync calls and no
EMFILE in the perturbed case. Source and syscall evidence identify the directory
publication check. The original full r4 process was untraced, so its exact external
trigger cannot be established retrospectively.

The repair changes only this test fixture to root/audit/events.jsonl. Both checked
directories now belong to the fixture, matching the production layout. Its
original durable-intent-before-recoverable-identity assertion is preserved.
All ten previously recorded source hashes remain identical; the eleventh file is
the repaired jobs_start_io_tests.rs.

In r5, the repaired exact test passed quietly and under 451 create/unlink pairs
in its unrelated parent, with zero perturbation errors. The frozen repaired
binary stayed unchanged. The quiet Cargo command's 225.374s includes a rebuild;
the perturbed binary command took 0.115s. Those durations are diagnostic,
not a comparative performance claim. Strict all-targets Clippy also returned 0.

## The r5 qualification environment error

The task owner placed r5's private TMPDIR below the source worktree. The shell
scratch test uses tempfile and writes to that generated absolute path.
The existing shell gate permits scratch redirects outside the workdir; the
inside-worktree placement changed the test into a worktree write and correctly
triggered rejection.

The shell gate and its test were not weakened. r6 changed only the qualification
TMPDIR to a new owner-only directory outside the worktree. The previously failing
shell exact check then returned Cargo 0 in 2.417s. The final r5 full-suite stream
contains 867 directly observed ok lines and one known failed test, with no
complete main-harness result. It remains PARTIAL/FAIL.

## The r6 bounded-concurrency failure

With unchanged source, external TMPDIR and two test harness workers, r6 reproduced
the existing shared_preflight_leaves_a_missing_store_for_the_original_exclusive_path
failure. Process-global store coordination and incomplete participation of older
tests in serial_test isolation were identified in the source review. The
specific final panic was not printed before the owner cancelled the run, so its
exact internal failure branch is not claimed as observed.

The final retained stream contains 1,045 directly observed ok lines and one known
failed test. Two nested single-test subprocesses passed in 155.11s and 333.48s.
Those summaries are not full-suite results and are not added to a parent total.

r7 changes only harness concurrency from two to one, preserving the source,
external private TMPDIR and NOFILE. It exercises the same test assertions, test timeouts,
and production checks.

## Successful scoped evidence that remains independently valid

Before its interrupted full suite, r4 completed:

- Focused weight tests: 35 passed, 0 failed, 1 ignored.
- Owner-fence inventory: 1 passed, 0 failed.
- Explicit ignored private-head fixture versus independent NumPy weights:
  1 passed, 0 failed.
- Explicit ignored external PyTorch forward comparison: 1 passed, 0 failed.

Each of these commands returned its own Cargo 0. Their logs and hashes are
recorded separately. A reference-equivalence test passing is software evidence;
the predictive effect of an edit still requires a valid independent experiment.
The ordinary ignored tests are not counted as passed.

## Source, environment and evidence custody

The base commit is 1f2d3d782e8803e769989234e7902ca5c04eff97.
qualification.json records the final 12 source-file SHA-256 values and sizes,
plus the historical 11-file identity and the test-only transitions. The r5, r6
and r7 identities are identical. Targeted followup and r8 add the repaired
maintenance test file; all preceding 11 files remain byte-identical.

The recorded build environment is Linux x86_64, rustc 1.95.0 and cargo 1.95.0.
Cargo.toml and Cargo.lock hashes are retained. The host reports 48 logical CPUs
at the observation time; that value is not treated as evidence of the exact
unrecorded r2 harness worker count. A harness worker limit also does not constrain
the internal threads of the runtime fixtures.

Raw logs remain on the authorized validation host. The public receipt stores
their exact SHA-256 values and byte counts, plus bounded summaries. It excludes
private host paths, durable process identifiers, account data, checkpoint weights
and individual fixture rows. The package retains the complete failed history, including the final failed r7 and r8 commands.

## Reading the final receipt

Every command_exit_code belongs to that command, not to an enclosing Python
process or the durable supervisor. An interrupted full-suite Cargo command has
an unknown final command return code and unknown complete main-harness result.
A supervisor signal exit of -15 documents cancellation only.

The r7 and r8 Cargo commands, source revalidation and final log hashing are complete. Both commands failed and did not reach later harnesses or their planned formatting checks. The original failures, cancelled attempts and narrow successful checks are retained separately. The final receipt is FAILED_R8_COMPLETE.

## Recorded r7 failures and the bounded repair

The full final failure list contains 14 tests. Four SSH observation-pool tests
report an underlying socket-path-length refusal, including three subprocess
wrapper failures. Nine server shell-dispatch tests report a shared request-audit
unavailable refusal. The remaining server schema test observes 82 tools where
its fixture expects 10. These signatures are preserved without treating the 14
tests as 14 independent root causes. Source review ties these to two shared conditions; no failure is waived.

The r7 library summary is:

```text
test result: FAILED. 1682 passed; 14 failed; 36 ignored; 0 measured; 0 filtered out; finished in 3694.10s
```

The main Cargo command took 3,694.770761747 seconds, with a reported 0.48-second
warm build. Its two nested single-test successes (85.94s and 36.24s) are not added
to the parent totals. Full log SHA-256:
f002dc8fab04397d5ef88d5a97f3494568ef373794a8602b8e25b92db422aca9.

### Source-supported failure chain and bounded repair

The r7 temporary-root recipe produced a 40-byte outer path. The unchanged SSH
fixture creates another directory beneath it, then PrivateRoot constructs a
name containing six PID digits and 32 hexadecimal entropy characters. Even a
one-byte fixture directory name makes the ControlPath at least 91 bytes.
The existing guard permits at most 90 bytes so OpenSSH can append its temporary
publication suffix. The observed refusal is therefore consistent with a
deterministic qualification-path error. The targeted followup and r8 used a short
external private root; the production limit is unchanged.

The ordinary background-notification maintenance test calls the shared SSH
fixture, which installs RUNTIME_CONFIG in a process-global OnceLock. Its
recorded panic occurs after that installation. Dropping its TempDir does not
remove the immutable configuration. Later server tests create a fresh workdir
but assume runtime-disabled mode. Their expanded tool count proves runtime mode
was enabled, and their shell calls enter audit admission against that retained
configuration. The audit wrapper normalizes internal errors, so no specific
underlying errno is claimed from the r7 log.

The maintenance test now invokes its original assertion body through the
existing bounded subprocess helper. A parent assertion verifies that runtime
configuration presence is unchanged after the child exits. The async assertion
body is byte-identical, no new ignored test is added, and the previous 11 source
hashes remain unchanged. Only the maintenance test file changes. Targeted
validation passed all four SSH parent tests and all 16 active server tests,
including the ten prior server failures. Four existing server tests remain
ignored. Strict Clippy and format checks passed. The eight command timers sum
to 397.132646468 seconds, including a reported 4m 58s rebuild and 0.14s for the
repaired background-notification test. The separate r8 full suite completed with two index-test failures;
the targeted successes do not replace that failed gate.

## Final r8 failures and observability limits

The final main library result is:

```text
test result: FAILED. 1694 passed; 2 failed; 36 ignored; 0 measured; 0 filtered out; finished in 3855.71s
```

| Failed test in request_audit::index::tests | Original source location | Original panic |
| --- | --- | --- |
| bounded_index_capacity_waits_without_retiring_live_callers_or_blocking_writers | request_archive_index_tests.rs:2223:5 | assertion failed: status.success() |
| large_pending_view_remains_exact_while_continuous_publications_progress | request_archive_index_tests.rs:2963:5 | assertion failed: Instant::now() < deadline |

The first test already runs its capacity case in a fresh child process. The
parent discards child stdout and does not request nocapture. The retained
original log therefore exposes the unsuccessful child status without the
child's failing assertion. That inner branch remains **UNKNOWN**. It is not
assigned a timing, file-descriptor, poison or global-state cause.

The second failure is the test's final wall-clock deadline assertion. Its
underlying cause remains unresolved. No timeout or production assertion was
weakened, and no diagnostic test replay is counted as part of the original r8.

A read-only historical CI comparison found both tests passing on the exact
base commit under nextest: 0.103s and 0.213s respectively. The test and production
index source files are byte-identical to that base. The historical job used
separate per-test processes; the local Cargo invocation uses a shared library
process with one harness worker. The capacity test itself still has a fresh child,
so this contrast alone does not prove a global-state explanation. The old job
also failed on two separate external REA tests and is not an all-green baseline.

The [historical CI job](https://github.com/TrillionniumFoundation/hepta-runtime/actions/runs/41692021906/job/126112746047)
and its decoded-log hash, workflow hash, command and comparison limits are
recorded in qualification.json. Historical CI success on these two tests does
not waive the current failures or establish the cause.

Full r8 log: 196,063 bytes, SHA-256
82c863537186873e096afae0b3929e9113ac4e6e0b2d3bcfad806ff8f684ad25.
Receipt: 2,818 bytes, SHA-256
b35ec6c1c373882f99456adbc00e3638ab7491d5af0bd1044a23bf885e8df592.

The two nested one-test summaries (112.44s and 60.50s) are excluded from the main
totals. Controlled/injected panics printed by passing SSH recovery fixtures are
also distinguished from the two actual failures. Raw logs remain private.

## Companion diagnostics

[The bounded five-case isolation record](isolation/README.md) retains the r2
negative full-suite result and its limited isolated reruns.
[The parent-directory binding diagnosis](parent_binding/README.md) contains the
controlled r4 fixture contrast and test-only repair.
[The maintenance isolation patch](maintenance_isolation.patch) preserves the
original async assertion body and adds the parent runtime-presence check.
These records support the distinctions in this qualification history; they do
not replace a complete successful all-features invocation.

## Reproducing the final tested configuration

Use the final source files identified in qualification.json on Linux, with the
locked dependencies already available in the offline Cargo cache. Create the
temporary directory outside the source checkout and preserve the recorded
NOFILE soft limit:

```sh
qualification_tmp="$(mktemp -d /tmp/hw-XXXXXXXX)"
chmod 700 "$qualification_tmp"
export TMPDIR="$qualification_tmp"
export CARGO_BUILD_JOBS=2
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
ulimit -Sn 1024
cargo test --locked --offline --all-features -- --test-threads=1
cargo fmt --all -- --check
cargo clippy --locked --offline --all-features --all-targets -- -D warnings
```

Each command must return zero independently. Do not substitute the exit status
of a wrapper or a nested single-test subprocess. The one-worker harness setting
does not serialize the internal concurrency deliberately exercised by individual
tests. Retain each command's output and its source identity.

The explicit ignored private-head and external PyTorch checks are separate from
the ordinary all-features invocation; see docs/native-weight-guard.md for their
inputs and commands. Private fixture rows and weights are not distributed in
this package. Ignored checks remain ignored unless separately executed.

The reproduction command above records the final configuration; it is not a promise of a passing suite. The recorded original run failed. Any future targeted diagnosis or official CI result must remain a separate receipt and must not overwrite r8.

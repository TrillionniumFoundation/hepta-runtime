# Runtime test strategy

## Correctness gate

Both exact-HEAD and prospective-merge jobs in `.github/workflows/ci.yml` use
Cargo-nextest 0.9.137, installed with its locked dependency resolution:

```sh
cargo install --locked --version '=0.9.137' cargo-nextest
cargo nextest --version
cargo nextest run --locked --all-targets --all-features \
  --test-threads 1 --retries 0 --no-fail-fast
```

Each test runs in a separate process. Only one test process runs at a time;
concurrency deliberately created inside an individual test remains enabled.
There are no automatic retries, test-name filters or added ignored tests. A
test failure fails the gate, while `--no-fail-fast` retains the remaining test
diagnostics. The workflow keeps the original checkout identity checks, format,
Cargo check, strict Clippy, release build and merge-job Python regressions.

This policy isolates unrelated fixtures that otherwise share process-global
runtime state. It does not remove actual contention or deadline assertions from
the tests, add a production timeout exemption, or qualify a concurrent-load SLA.

## Why process isolation is necessary

The [audit store lock](../src/mcp/runtime/request_audit.rs) is process-global,
and the [archive index registry](../src/mcp/runtime/request_archive_index.rs)
holds a bounded global cache with background workers. Different fixture directories do
not isolate those owners. The three-second archive metadata query budget
includes lock admission and index readiness. The legacy shared-process Cargo
harness can therefore combine one test's deliberate concurrency with unrelated
tests and index workers in the same executable. Setting Cargo's test thread
count to one alone does not reset those owners between tests.

During qualification of the combined runtime, a warm shared-process run under
a two-CPU quota with other isolated builds active recorded 1,142 passed, seven
failed and 21 ignored in 2,595.71 seconds. Two failures exposed semantic defects
in the strict FinalUse decoder and an inherited hard-link fixture; both were
repaired without weakening the execution or audit policy. The remaining five
failures involved archive metadata deadline contention. Two initially failing
archive tests passed independently with unchanged source and the same
three-second production deadline. These failed runs remain evidence; they are
not retried until green or relabelled as successes.

After the semantic repairs, the full nextest run on
`dd7bf97f4cbe9b77d35c117ef1584e541129f041` passed all 1,177 runnable tests, with
21 existing opt-in tests skipped and no retries. It used a two-CPU quota, 8 GiB
memory ceiling and nice 10, with no other owned qualification builds at start;
the host was not exclusive. Its test summary took 1,790.418 seconds and its
process wall time was 1,792.076 seconds. The complete 1,188-line log SHA256 is
`086ba439c7079203527990811dd31076ebb64ec059561579e218a3fa6ac04c3c`.
The exact timestamps, source and native canary evidence are recorded in
[Native process boundary and qualification](NATIVE_LIBRARY_BOUNDARY.md).

## Coverage and budgets

The qualified inventory contained 1,198 tests across five Rust binaries, with
1,177 runnable and 21 existing opt-in skips. The corresponding entry points are
the library, runtime executable, `hepta-effect-ownerctl`, `jobctl` and
`examples/native_process_driver.rs`. At this source, `Cargo.toml` declares no
feature table, optional dependencies or custom `harness = false` test targets.
Consequently `--all-features` does not expand the current inventory. Adding
features or a custom harness requires a fresh coverage review; a custom harness
must not silently disappear from the gate.

Nextest does not run Rust doctests. The previous `cargo test --all-targets` gate
also did not establish doctest coverage. If executable documentation examples
become a required contract, qualify a separate `cargo test --doc` gate. The
controlled localhost-SSH native process canary remains a separate opt-in
integration check; the unit inventory does not replace its real crash, recovery
and cancellation evidence.

Each CI job now has a 90-minute budget. This allows for the observed roughly
30-minute warm test run, the earlier 13-minute-22-second cold compilation,
installing the pinned runner, and the remaining build and regression steps.
The hosted environment and its actual duration still need their own CI result.
The workflow budget is not a change to any production query, execution, lease
or cancellation deadline. Production archive metadata queries retain their
three-second bound.

The local full pass establishes correctness within its recorded envelope. It
does not establish a hosted CI pass, production throughput, memory advantage,
tail-latency SLA, native/Codex agent parity or arbitrary business exactly-once
effects. Retain load tests and end-to-end owner qualification as separate
experiments with their own measured conditions.

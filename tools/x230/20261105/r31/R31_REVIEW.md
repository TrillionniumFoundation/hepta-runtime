# R31 candidate review

## Scope and source custody

R31 starts from accepted R24 commit
`baab4def80be7af015b2e7a594cb302f66c4130e`. It changes only the embedded
cancellation helper's wait behavior and registers a sibling test module.
The production `jobs.rs` is frozen at
`d92b1dba53b2495a0146f242ad6455d6f2d87def19f01c1d831d2488a28eedaa`.

There are exactly three changed compilation inputs:

| Path | Change |
|---|---|
| `src/mcp/runtime/jobs.rs` | Held-pidfd readiness wait and test-module registration |
| `src/mcp/runtime/jobs_cancel_wait_tests.rs` | Eight new Rust regression tests |
| `src/mcp/runtime/jobs_cancel_wait_fixture.py` | Complete-helper Python boundary fixture |

The baseline map has 220 files and equals the accepted R24 map retained in the
R30 input manifest, byte for byte. The candidate map has 222 files: the same
baseline, one modified existing input, two additions and no deletions. Both
router files remain R24. R25/R26 admission changes, R28 command caching and R30
router sharing are absent.

`candidate.patch` passes `git apply --check`. Applying it to an independent
R24 preimage reproduces all three candidate files byte for byte. `input.json`
contains the complete baseline/candidate maps, patch hash and changed paths.
Its fields and sets were checked against the root agent's R31 preparation
script; the two added inputs match `ADDED`, and the full three-path delta
matches `CHANGED`.

## Production behavior

The Linux helper already uses a pidfd to signal the bound original supervisor.
R31 registers that same held descriptor before publishing cancellation intent,
then waits with a maximum 100 ms poll timeout, capped by the original remaining
grace budget. Interrupted waits continue against that original deadline.

Readiness does not become a successful workload-termination claim. The helper
keeps `termination_confirmed: false` and `reconcile_via: process_status`.
Invalid descriptor/event sets, POLLERR, POLLNVAL, unexpected mask bits and
non-EINTR syscall failures propagate as errors; there is no resend or sleep
fallback after such failures. Register/construction failure occurs before the
cancellation receipt and signal.

The final loop condition is:

```python
while supervisor_exited or time.monotonic() < deadline:
```

It ensures a readiness event causes one final original metadata/identity check
even if poll returns exactly at, or slightly after, the grace deadline. The
check then exits the loop; it cannot start another wait. This closes the older
draft's deadline boundary gap. Grace is the wait budget, not a hard deadline for
all file I/O and interpreter shutdown. Integer poll timeout conversion may add
one millisecond at a floating-point boundary.

Non-Linux retains the original PID signal and 100 ms sleep path. No select or
pidfd API is needed by that branch.

## Regression tests

Rust passes the actual `bound_remote_code(CANCEL_CODE)` into the Python fixture.
The fixture executes the entire helper, including real private-directory
validation, request binding, metadata reads, atomic writes and fsync. It does
not copy the wait loop or select AST fragments. Kernel `/proc`, pidfd, signals,
ps, time, waiting and stdout are controlled boundaries; the descriptor model is
an owned `/dev/null` fd. No real process is selected or signalled.

The eight Rust tests cover 25 parameterized cases:

- POLLIN, POLLHUP and their combination wake while the terminal file remains
  absent and the original process identity still matches.
- Corrupt real terminal metadata is reread and refused after readiness before,
  exactly at, and slightly beyond the deadline.
- Empty polls and repeated EINTR preserve the original deadline; a
  submillisecond grace neither busy-spins nor rounds down to zero.
- POLLERR, POLLNVAL, mixed readable/error masks, unexpected bits, zero masks,
  foreign descriptors and duplicate events refuse acknowledgment.
- Non-EINTR poll errors and stdout BrokenPipe failures retain unknown outcome
  without a second signal, fallback sleep or leaked descriptor.
- Poll construction/registration failure and missing pidfd support occur before
  receipt publication and signalling.
- A simulated non-Linux host has no pidfd APIs and cannot import select, yet
  keeps the old signal and metadata cadence.
- Already-exited and zero-grace requests enter no wait.

For actual helper failures after a signal, Rust feeds the captured error into
`retain_cancel_outcome` and checks `cancel_unknown`, unconfirmed termination and
`automatic_retry: false`. Python fake-clock budgets fail with AssertionError;
they cannot accidentally satisfy tests expecting a specific operational error.
The Rust subprocess uses file-backed standard streams and an owned-child reaper.

Independent read-only review found no blocking test-logic, descriptor-custody,
Rust type/trait or obvious Clippy issue. The toolchain must still confirm that
review through normal qualification.

## Validation status

- Complete Python boundary checks: **25 passed, 0 failed** in
  `python-boundaries-02/report.json`.
- Sensitivity checks: the R24 preimage fails the new early-readiness assertion;
  the older pidfd draft fails the deadline metadata-refusal assertion. Both
  intended defects were detected.
- The first local boundary run retained one overly strict timeout-rounding
  assertion failure in `python-boundaries-01/report.json`. The assertion now
  permits one millisecond of timeout quantization while still forbidding a new
  wait after the original deadline. Production source never changed for this.
- Earlier deterministic boundary review: 29 passed, including the two final
  deadline checks. These are not real-kernel performance measurements.
- Rust build, Rust tests, Clippy and rustfmt: **not run locally**. The unchanged
  x230 eight-stage qualifier remains required. rustfmt may reflow only the new
  Rust test source; no toolchain pass is claimed here.

Root reported the real x230 component run at
`/home/qian/hepta-runtime-pidfd-component-20261105-01/run-01`, original job
`1a1adfb2959-fc05-5c58`: 62/62 fixtures completed, 48 measured samples, both
lost-ACK/already-exited controls passed, all children reaped, zero cleanup kills.
That run used this exact frozen `jobs.rs` and the unchanged component script
SHA256 `77ab26a406490f05c036ba31d02c7cf5d72a02032916acabb8262addd18f4fe4`.

| Artificial fixture exit delay | R24 full-helper median | R31 full-helper median |
|---|---:|---:|
| 5 ms | 152.9234 ms | 66.1924 ms |
| 25 ms | 151.7009 ms | 88.2223 ms |
| 65 ms | 153.6736 ms | 137.1864 ms |

These are actual x230 Python-helper component measurements reported by root,
not runtime/SSH throughput, concurrency, multihost resource or adoption results.
No remote call or new remote load was submitted by this review task.

## Frozen deliverables

| File | SHA256 |
|---|---|
| `candidate.patch` | `743701d44a9cef52c6cb04115bd8a8d7671c32e7fc0e52459c38ca63ff70ea21` |
| `input.json` | `b54654aa5ea0a414b860a215d6bf0caef73c3b03adccdf7da83fc7f336003383` |
| `manifest.json` | `cb4ad29c420945e1d553a3d3f8151d4b201a25e4a9d94e96aa651a44d2c7aca3` |

The full candidate export is `source/`; accepted preimage is `baseline/`.
Compile-map identities, individual changed-file hashes, validation receipts and
component input binding are recorded in `manifest.json`.

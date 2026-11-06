# R26 lifecycle and cancellation admission gates

These tools are a separately frozen copy of the qualified R20/R21 lifecycle
harness. The original source directories and R23/R24 evidence are unchanged.
The source provenance receipt records the imported byte identities.

## Candidate scope

The accepted R24 throughput campaign measured completed-job status/read through
the observation pool. New `process_start`, confirmed same-key reconciliation and
`process_cancel` still use direct SSH. The previous C6 recovery canary proves
correctness for six new jobs, 12 same-key observations and 12 cancellations, but
does not prove cancellation can enter after ordinary direct admission is full.

R26 keeps ordinary direct limits at 16 admitted, 8 active and 2 per target. Only
the internal existing-job cancellation path can use a reserved lane after an
immediate ordinary allocation fails. The reserve has 8 admitted requests and
1 active child globally. The mixed upper bounds are consequently 24 admitted,
9 active direct children and 3 direct children to one target. All lanes use the
same original-child owner, freeze, submission commit and reap path. No effect is
resubmitted after transport submission. A cancellation acknowledgement still
does not prove termination; terminal state and output witnesses remain required.

This is a control-availability improvement with a declared resource tradeoff.
The prior public API did not promise cancellation admission under overload, and
returned `cancel_unknown` without automatic retry for unconfirmed transport
outcomes. Existing atomicity or exactly-once claims are not expanded.

## Required order

1. Complete exact-source Rust qualification and retain formatted-source hashes.
2. Run `run_lifecycle_tool_tests.py --out <fresh-tool-test-directory>` on X230.
   All 14 tests must pass with zero skips. The cloud executor's virtual PID
   namespace cannot perform three original-Child tests; this limitation is not
   a waiver on X230. These tests use local recorders and never contact SSH.
3. Complete normal observation ABBA with the parent's frozen nonregression gates.
4. Run the normal lifecycle ABBA and its independent per-round auditors.
5. Run the candidate-only saturation canary once, followed once by its independent
   verifier. All effects use fresh private fixtures and the original immutable
   job ID/key bindings. No automatic RPC or failed campaign retry exists.

The parent supervisor must bind the tools manifest, both actual runtime hashes,
the six-host topology, original fixture records, profile template and held agent.
It must also retain the owned stage PID/start identity, wait/reap result and
complete stdout/stderr. The saturation producer's existing controller cleanup
and 240-second target backstop remain in force. A failed effect is reconciled
using original evidence; the producer never issues an automatic replacement.

## Normal lifecycle ABBA

Baseline is the actual accepted R24 runtime:

`/home/qian/hepta-runtime-optimization-20261105-r24/qualification-01/hepta-runtime`

SHA-256: `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13`.

Candidate is `/home/qian/hepta-runtime-optimization-20261105-r28/qualification-01/hepta-runtime`.
Output must be the fresh `/home/qian/hepta-runtime-optimization-20261105-r28/lifecycle-abba-01`.
The runner requires explicit matching baseline/candidate SHA-256 values and the
tools manifest SHA-256. It creates four private socket directories from a fresh
short prefix directly under `/home/qian`.

```text
python3 -B run_lifecycle_abba_01.py
  --baseline <exact-baseline-path> --candidate <exact-candidate-path>
  --expected-baseline-sha256 <R24-hash>
  --expected-candidate-sha256 <qualified-R26-hash>
  --expected-tools-manifest-sha256 <frozen-manifest-hash>
  --profile-template <pinned-template> --topology <six-host-topology>
  --frozen-jobs <original-six-record-directory>
  --out /home/qian/hepta-runtime-optimization-20261105-r28/lifecycle-abba-01
  --socket-prefix /home/qian/r28lc1 --workers 2 --arena-max 1
```

Each round starts six finite jobs and retains the existing ROG private-master
interruption, owned controller crash/restart, same-key reuse, six concurrent
cancels, terminal proofs, another restart and terminal recancel. Total: 24 new
jobs, 48 same-key calls and 48 cancellation calls. Timing adds no effect calls.

The frozen policy is `lifecycle-gate-policy.json`. Aggregate normal operations
include launch, same-key after crash, live cancel, same-key after cancel, and
terminal recancel: 60 RPCs per arm. Aggregate, launch and live-cancel throughput
must each retain at least 95% of baseline; RPC p95 must each stay within 110%.
Launch and live-cancel each have only 12 observations per arm, so their nearest
rank p95 is their largest sample. These are finite comparison gates, not a
maximum concurrency or statistical-significance claim.

Controller CPU is bracketed by the original raw `/proc` counters around each
whole phase. Tiny phase totals often span only three to five clock ticks, so
the CPU gate uses the predeclared allowance of one clock tick per included
phase/round. It does not reinterpret quantization as an optimization gain.
Controller plus reaped local-child CPU is separately derived from the same raw
`utime/stime/cutime/cstime`; remote-host CPU is outside that measurement.
Sampled controller RSS must satisfy both `A + 512 KiB` and `A * 1.05`, across
all three controller generations in both rounds of each arm.

## Candidate-only direct saturation canary

The parent creates one fresh private socket directory, then invokes:

```text
python3 -B run_six_host_cancel_saturation.py
  --candidate <exact-qualified-R26-path>
  --profile-template <pinned-template> --topology <six-host-topology>
  --frozen-jobs <original-six-record-directory>
  --socket-parent /home/qian/r28sat1
  --out /home/qian/hepta-runtime-optimization-20261105-r28/cancel-saturation-01
  --workers 2 --candidate-arena-max 1 --interrupt-host rog

python3 -B verify_cancel_saturation.py
  --report /home/qian/hepta-runtime-optimization-20261105-r28/cancel-saturation-01/report.json
  --output /home/qian/hepta-runtime-optimization-20261105-r28/cancel-saturation-01/independent-summary.json
```

After the normal crash/recovery phase has confirmed all six original jobs, the
canary submits exactly 32 balanced same-key calls, each bound to an already
`launched` receipt. A private wrapper gates only the exact status command hash,
exact stored job ID/directory/unit/SHA-256 digest/wait value, configured SSH
target and original controller PID/birth. Starts, cancels and unrelated jobs
never match this predicate. The complete original status payload is forwarded
byte-for-byte through an anonymous stdin file after release.

The gate has an eight-second backstop and a three-second readiness budget. It
requires eight live original transport children and a 16/16 split between
still-pending and `status_unavailable` same-key calls. Six actual cancel calls,
one per physical host, must all return trusted acknowledgements before the
gate opens and while the original eight held Child identities remain live.
There is no repeated cancel attempt to obtain a better outcome.

The gate is then released once, all 32 same-key calls are drained, and the
active configuration is atomically renamed to `config.closed.json` and the gate
directory is synced. The original bytes remain available for audit; subsequent
controllers use the original SSH wrapper without inheriting the old gate. An
existing release file alone never bypasses an active gate's original-owner check.
Retirement must follow complete pressure drain and precede the next controller
startup. The
original six jobs must reach `cancelled` with their complete output witnesses
and single execution markers. Restart, same-key terminal reuse and terminal
recancel retain the original canary checks. Expected effect counts are still
six new starts and 12 cancels; same-key calls increase to 44. Normal and
saturation canaries have separate report schemas and separate auditors.

This artificial, status-only gate proves control-path availability under a
known admission condition. It is not a throughput workload. The independent
auditor rebinds every native DTO to raw stdout, verifies all gate identities and
clocks, requires cancellation inside the held interval, checks the full drain,
and retains every controller/resource/terminal audit from the old verifier.

## Remaining boundaries

Real host reboot, physical power loss, WAN partition, production owner transfer
and transactional exactly-once external effects remain outside this campaign.
The canary exercises operator fixtures on the six hosts. Both operator Python
and isolated jobctl cancellation routes are covered by the new public-path Rust
dispatch test, but this campaign does not switch production jobs or install a
new privileged jobctl service. macOS retains its documented non-pidfd identity
limit. These scope limits are not relabeled as completed reliability tests.

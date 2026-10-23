# x230 runtime optimization record — 2026-10-23

The qualified A20 candidate improves six-host native observation throughput and
controller CPU use while adding explicit output and terminal-publication
durability checks. Development, builds, benchmarks, and new canary state are
isolated on the x230. No production runtime binary or service was replaced or
restarted. The base for this work is the qualified A17 snapshot, not an unrelated
repository default-branch revision.

## Qualified iterations

| Iteration | Main change | Runtime tests | Auxiliary tests | Qualification |
| --- | --- | ---: | ---: | --- |
| A18 | Bounded observation backpressure; streamed full-file validation hashing; durable output completion and truthful post-spawn failure | 1,080 passed | 18 + 8 passed | [Receipt](evidence/x230-a18-qualification-20261023.json) |
| A19 | Synchronized input and supervisor staging; correct OpenSSH temporary socket-path bound | 1,084 passed | 18 + 8 passed | [Receipt](evidence/x230-a19-qualification-20261023.json) |
| A20 | Bound witness of completed exit-publication barriers; conservative unconfirmed terminal states | 1,088 passed | 18 + 8 passed | [Receipt](evidence/x230-a20-qualification-20261023.json) |

Each qualification used Rust 1.95.0, formatting, strict all-target/all-feature
Clippy, all-feature tests, and a fresh all-feature release build. The 21 existing
ignored tests remain reported; they include environment-dependent integration
cases, manual benchmarks, and an isolated helper. Nested helper result lines
are not counted twice.

The A20 tested source map contains 149 files and is unchanged across tests and
the release build:

- Source-map SHA256: `ad734d2154e5e329467ba3d4c0f48d415ae3c4594a490a7aa1c7721ae780d8bc`.
- Release-binary SHA256: `727c4661450fdb2a2a44b63f7f9442a5cd20ad854f1c26b043ac710b6fa2ea06`.
- Qualified source commit: `7da3a7ebaded8214bc65e69046b74e6251e21767`.
- Baseline A17 binary SHA256: `721b4108569f90374086da71966b57f2e13a7351ac44f7f19775cbc93a9c9917`.

## A17 → A20 six-host comparison

The frozen native stdio MCP driver compared the same six original completed
operator jobs on ai395, mac, main, pocket4, rog, and x230. The order was ABBA,
with 96 calls in each concurrency cell per round. Every version therefore has
192 measured calls per concurrency. Rates divide all successful calls by the
sum of complete cell durations; latency percentiles use all call rows and the
nearest-rank rule.

| Concurrent calls | A17 calls/s | A20 calls/s | Throughput change | A17 p95 ms | A20 p95 ms | A17 CPU ms/call | A20 CPU ms/call |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5.0967 | 5.7650 | +13.11% | 258.12 | 230.69 | 93.91 | 68.91 |
| 4 | 19.5000 | 22.9732 | +17.81% | 272.74 | 235.84 | 45.83 | 33.75 |
| 8 | 22.4725 | 28.4661 | +26.67% | 421.83 | 353.29 | 45.83 | 33.44 |

Controller CPU per call decreased by 26.62%, 26.36%, and 27.05%, respectively.
Across the six timed cells per version, controller CPU was 35.63 seconds for
A17 and 26.13 seconds for A20. These measurements include network and host
effects; ABBA counterbalancing is not a statistical confidence interval.

All 1,152 timed calls succeeded. The 24 initial full-output checks and 48
same-job checks after normal controller restart also succeeded. All eight
controller shutdowns used stdin EOF and returned zero, with no reader errors,
unmatched replies, or observed descendant survivors. The source records and
both binary hashes remained unchanged.

| Measurement-controller lifetime sampled peak | A17 | A20 |
| --- | ---: | ---: |
| Controller RSS, KiB | 17,592 | 16,164 |
| Controller file descriptors | 94 | 85 |
| Controller plus observed descendant RSS, KiB | 123,284 | 101,004 |
| Observed descendants | 14 | 11 |

Resource peaks are 100 ms sampled lower bounds. The complete experiment retains
seven `/proc` permission errors, including restart controllers. Descendant
processes are not classified into SSH-only executables, and their CPU sampling
can miss short-lived processes. These numbers are not remote-host total memory
or process counts.

The workload reads small, already completed outputs. It does not establish
new-job launch TPS, HTTP-session capacity, or large-stream transfer bandwidth.
The full call rows, resource sampling errors, source hashes, and restart results
are in the [A20 comparison evidence](evidence/x230-a20-observation-20261023.json).
The earlier independently measured [A18 comparison](evidence/x230-a18-observation-20261023.json)
is retained as a separate experiment, not mixed into A20's statistics.

## Why the adopted changes help

The A18 actor reserves its global execution/output budget before dequeuing a
request. A response that has finished SSH execution still holds that budget
until its original caller finishes parsing it. Saturation therefore remains in
the bounded channel instead of producing a premature capacity refusal after a
request has already been removed from that channel.

Pinned policy, configuration, credential, and executable files still receive
complete SHA256 validation. The steady-state file hashing path now streams
through one 16 KiB buffer using the existing ring implementation. It retains
file identity, ownership, permissions, link-count, capability, and before/after
stamp checks. There is no hash cache, partial-file sampling, or skipped
authority boundary.

A19 reserves space for OpenSSH's temporary ControlPath suffix and terminating
NUL. It rejects a final Linux path longer than 90 bytes before creating an
unusable initial private directory and checks every subsequent generation.
Actual Unix-socket binding tests cover ASCII and UTF-8 byte boundaries.

## Execution persistence and recovery

The persistence sequence now synchronizes exclusive input and supervisor
staging before launch submission, synchronizes completed logs before recording
durable output, and confirms terminal publication through a witness that binds
the original request identity, launch nonce, and exact exit-receipt bytes.

The exit witness is published only after the exit file synchronization, rename,
and pinned job-directory synchronization have succeeded. A visible exit file
without a valid matching witness is insufficient for a new-protocol terminal
confirmation. Missing or invalid evidence remains `finalizing`,
nonauthoritative, and nonretryable. Existing unmarked legacy jobs remain
readable; they are not retroactively assigned new durability guarantees.

If a workload exited zero but log synchronization failed, its real exit code
stays zero while the confirmed runtime outcome is failed. If a child was
created but publication of its child receipt failed, that is an uncertain
post-spawn effect, not a false claim that nothing was launched. Only the still
owned child group is terminated and reaped; the original identity is retained
without automatic replay.

The [durability design](RUNTIME_DURABILITY_BOUNDARIES.md) states the exact
ordering, validation, legacy compatibility, and witness limitations.

### Running workload after controller SIGKILL

The [A20 lifecycle canary](evidence/x230-a20-lifecycle-20261023.json) made seven
successful native calls around one private x230 workload:

1. Persist 4,096 input bytes, launch once, and observe `running` plus `BEGIN`.
2. SIGKILL only the directly owned test controller using a pidfd.
3. Restart with the original state and observe the same job still running.
4. Repeat the identical request with the same key: reuse the same ID with
   `retried_launch=false` and no new launcher submission.
5. Release the original workload and verify exactly one execution marker,
   75 stdout bytes, 20 stderr bytes, unchanged input and original metadata,
   synchronized logs, and a confirmed exact-byte publication witness.

The canary retained one resource-sampling permission error. Its success does
not depend on ignoring that error or inferring target durability from the
controller's exit code.

### Six-host observation after controller SIGKILL

The [separate read-only recovery check](evidence/x230-a20-recovery-20261023.json)
verified 12 status/read observations before and 12 after controller death. All
14 sampled descendant process generations exited. It created no replacement
remote workload and preserved all six original job records.

One old private directory containing six socket entries remained visible.
Accordingly, `read_only_recovery_passed=true` and
`abrupt_cleanup_complete=false` are separate outcomes. The test did not delete
uncertain artifacts to make the result appear cleaner. Three resource-sampling
permission errors remain in the evidence.

These tests do not prove recovery from physical power loss, a target reboot,
a WAN partition, production ownership transfer, or transactional exactly-once
business effects. They establish controller recovery and the specifically
tested publication/failure boundaries.

## Optimization rejected by measurement

Replacing the request-serialization SHA256 writer unconditionally with ring
was rejected. Six ABBA cycles retained all 72 timing cells and checked complete
256-bit digest equality before measurement.

| Request case | Original median CPU µs | Candidate median CPU µs | Change |
| --- | ---: | ---: | ---: |
| Small request, 176 serialized bytes | 1.4607 | 1.6474 | +12.78%, slower |
| 1 MiB plain input | 6,099.65 | 4,213.70 | −30.92% |
| 1 MiB heavily escaped input | 23,610.92 | 20,970.40 | −11.18% |

The small-request regression appeared in all six cycles. Large-input gains did
not justify slowing the common small path. The request writer therefore keeps
its original implementation. This result is separate from the beneficial
full-file validation hash change. See the
[decision receipt](evidence/x230-request-hash-decision-20261023.json) and its
retained raw JSONL; no native launch-throughput improvement is claimed from
this microbenchmark.

## Reproduction and evidence integrity

The [x230 helper guide](../tools/x230/README.md) documents source qualification,
the frozen comparison, sustained observation, and controller recovery. The
publication manifest distinguishes measured originals from the few portable
copies whose private path constants or comments were changed. Their hashes
must not be presented as byte-identical.

Public evidence retains all call outcomes and sampling errors while replacing
private paths, hostnames, network addresses, and process identities. Compact
reports bind the original raw report and actual measurement helper by SHA256.
Failed qualification attempts are retained, and neither a candidate's presence
nor a helper's inclusion in this repository implies adoption or a passing run.

A bounded optimization session cannot establish that no further improvement is
possible. Remaining candidates must preserve authority checks, workload
identity, bounded output retention, and truthful failure states, and must earn
adoption through complete correctness and representative performance evidence.

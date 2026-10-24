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

The [crash-cleanup design](OBSERVATION_CRASH_CLEANUP_DESIGN.md) documents why
recovered read access does not authorize deleting a dead controller's old
directory or sockets. It identifies the durable ownership and generation
records a future cleaner would need, the gaps before a spawned process or
OpenSSH socket can be durably identified, and the leaf-replacement race that
path checks alone cannot close. It is a design boundary and fault matrix, not
an implemented cleaner or permission to adopt the existing residues.

These tests do not prove recovery from physical power loss, a target reboot,
a WAN partition, production ownership transfer, or transactional exactly-once
business effects. They establish controller recovery and the specifically
tested publication/failure boundaries.

## Experiments and adoption decisions

### A21 early host gating

A21 completed formatting, strict Clippy, all 1,088 runtime tests and 26 auxiliary
tests, and a source-pinned release build. It added seven scheduling scenarios
inside existing isolated tests. Qualification alone did not establish that its
scheduling tradeoff was useful.

The complete A20/A21 fairness experiment retained 960 timed calls across balanced,
hot-only, and skew workloads in ABBA order. Each wave submitted eight head calls,
observed their native admission while they remained unfinished, and submitted two
tail calls. All 96 admission gates, 292 wave metadata observations, four initial
cursor receipts, and 48 complete-output checks were valid. This observes native
admission, not exact pool-permit ownership.

| Workload | A20 attempts/s | A21 attempts/s | Throughput change | CPU per call change |
| --- | ---: | ---: | ---: | ---: |
| Balanced six hosts | 24.0028 | 25.0581 | +4.40% | +0.73% |
| One hot host | 11.9875 | 9.4192 | −21.42% | +18.83% |
| Eight hot calls, two cold probes | 14.7479 | 12.1165 | −17.84% | +16.19% |

The cold-host p95 in the skew case improved from 448.10 to 169.23 ms, but the
hot-only p95 worsened from 852.18 to 1,059.96 ms. Both adjacent AB/BA hot-only
comparisons showed the throughput regression. A21 is therefore **not adopted**.
Its early per-host gate also serialized initial validation and response validation,
reducing the overlap available to a hot host.

A20 completed 479 of 480 timed calls and A21 completed 480 of 480. The baseline's
single native capacity refusal in the balanced case remains in every relevant
count and latency distribution; its balanced-cell successful rate was 23.8528/s.
There were no client timeouts or automatic retries. All four EOF shutdowns were
clean. Ten resource-sampling permission errors remain recorded (three for A20,
seven for A21).

The [full comparison](evidence/x230-a21-fairness-20261023.json),
[qualification receipt](evidence/x230-a21-qualification-20261023.json), and
[rejection decision](evidence/x230-a21-decision-20261023.json) preserve these
separate outcomes. Applying the [exact source patch](experiments/x230-a21-scheduling.patch)
to A20 commit `7da3a7ebaded8214bc65e69046b74e6251e21767` reproduces all 149 files in
the qualified A21 source map. The adopted runtime source remains A20 until a
successor independently passes qualification and workload comparisons.

### A22 phased scheduling and remaining C16 refusals

A22 keeps one global execution/output budget of eight but acquires it in two
phases: initial full validation, then remote execution and response validation.
It releases the first-phase permit before waiting for a host's existing
two-slot admission, preserving overlap without holding all global slots behind
one hot host. Sixteen logical admission permits bound requests throughout queue
waiting, execution, captured responses and child cleanup. The channel remains
eight slots. Stop-on-drop coverage also freezes admission after dispatcher or
request-task failure, including an unpolled aborted task.

The [A22 qualification](evidence/x230-a22-qualification-20261023.json) passed
1,089 runtime tests plus 26 auxiliary tests, strict Clippy, formatting and a
source-pinned release build. Its complete [fairness comparison](evidence/x230-a22-fairness-20261023.json)
passed all 960 calls, 96 admission gates, 288 wave metadata observations, four
initial cursors, 48 full-output checks and four clean EOF shutdowns.

| Workload | A20 successful calls/s | A22 successful calls/s | Throughput change | CPU per call change |
| --- | ---: | ---: | ---: | ---: |
| Balanced six hosts | 22.9685 | 24.0954 | +4.91% | −2.13% |
| One hot host | 11.0864 | 11.3468 | +2.35% | −1.64% |
| Eight hot calls, two cold probes | 13.7884 | 13.3344 | −3.29% | +5.69% |

Cold-host p95 fell from 469.52 to 226.21 ms, a 51.82% decrease. Both adjacent
AB/BA pairs improved cold p95 by more than 51%, but both also showed lower whole
skew throughput and higher CPU cost. The hot-only pairs differed in direction;
the small combined hot-only improvement is not evidence of a stable speedup.
Seven resource-sampling permission errors remain recorded. These observations
avoid A21's large hot-host regression while retaining a real fairness tradeoff.

A separate [C16 ABBA capacity comparison](evidence/x230-a22-capacity-20261023.json)
retained all 384 timed calls. A20 succeeded in 47/96 and 42/96 calls; A22 in
89/96 and 96/96. Thus both versions failed this workload's zero-refusal gate.
A20 had 103 refusals and A22 had seven. Successful throughput was 27.6914/s and
29.3286/s, respectively. Fast failures are not useful completed observations:
their effect on attempt throughput, mixed latency and CPU per attempt is kept
separate from successful throughput. The shared capacity-error text does not
identify the internal gate that refused a particular call.

A22 is **not adopted** while bounded queue admission is corrected and rechecked.
The [decision receipt](evidence/x230-a22-decision-20261023.json) records both the
fairness benefit and remaining failures. Applying its [exact source patch](experiments/x230-a22-scheduling.patch)
to A20 commit `7da3a7ebaded8214bc65e69046b74e6251e21767` reproduces the qualified
149-file source map `dcc6197816f1d36b515626390f128b6826abd47da30710ab4917ca418ef5c29c`.
The qualified release binary is `f57b6bf92012de15b2ffe81daedcc69688c65f3b6c63b67c95d486664de6d076`.

### A23 bounded queue admission: qualified and measured candidate

A23 retains A22's phased global budget and adds bounded waiting for a channel
slot after acquiring one of the existing 16 logical admission permits. It uses
the original deadline and cancellation/stop signals. After reserve completes,
it rechecks health, stop, cancellation, expiry and channel closure without an
intervening await before the single send. It does not retry an RPC, enlarge the
eight-slot channel or release the logical identity while a request is waiting.

The [qualification receipt](evidence/x230-a23-qualification-20261024.json)
records 1,093 runtime tests and 26 auxiliary tests passed, 21 existing ignored
tests, strict Clippy, formatting and a successful release build. The qualified
149-file source map is `5cf2e5cf8fca60e845a2c8f997abfc28017085bc809086a3ddb42448569a2b4f`;
the release binary is `64416b53b63ffe7eac05b4d9eb6750092279b5f6e25dbad5a8cfd31067d206a1`.
The [exact source patch](experiments/x230-a23-scheduling.patch) applies to the
qualified A20 source commit and reproduces every tested file.

#### C16 capacity

In the [complete C16 ABBA experiment](evidence/x230-a23-capacity-20261024.json),
A20 succeeded in 48/96 and 44/96 calls; A23 succeeded in 96/96 in both rounds.
A20 therefore had 100 native refusals and A23 had none. All 24 initial-output
and 48 same-job restart checks passed, and all eight controllers exited cleanly
through EOF. Two sampling permission errors remain, both for A23 measurement
controllers.

Successful throughput was 27.8793/s for A20 and 29.4915/s for A23. Total
controller CPU divided by successful calls, including the cost of failed
attempts, was 36.3043 and 33.6458 ms. CPU per attempt was 17.3958 and 33.6458 ms:
fast baseline refusals must not be mistaken for efficient completed work.
The whole experiment remains `passed=false` because the baseline failed;
`candidate_passed=true` is recorded separately.

#### Fairness, including the failed first experiment

The [first complete experiment](evidence/x230-a23-fairness-r01-20261024.json)
retains all 960 timed calls and 48 full-output checks. Its first A20 controller
recorded one `pidfd or post-exec identity refused` response, 179 other timed
stopped/unavailable responses and six failed final-output checks. Five admission
gates were invalid. The final A20 round and both A23 rounds passed, but this
experiment emits **no performance comparison**.

The [incident record](evidence/x230-a23-fairness-r01-incident-20261024.json)
separates that branch evidence from its possible causes. A20 and A23 use the
same spawn/proof/cleanup code. The final refusal is emitted after the original
owned child has been reaped and released from the ledger, while the shared
stop token was already cancelled. The old error discarded pidfd errno and
identity-read substage details, and the controller stderr was empty. A short
exit race, resource failure or actual identity mismatch cannot be distinguished
from this record. A23 has not been credited with fixing that shared path.

A [second same-parameter experiment](evidence/x230-a23-fairness-r02-20261024.json)
is retained independently. All 960 calls, 96 admission gates, 290 wave metadata
queries, four initial cursors, 48 complete-output checks and four EOF shutdowns
passed. Ten sampling permission errors remain, five per version.

| Workload | A20 successful calls/s | A23 successful calls/s | Throughput change | CPU per call change |
| --- | ---: | ---: | ---: | ---: |
| Balanced six hosts | 22.0796 | 24.3656 | +10.35% | −0.53% |
| One hot host | 11.0055 | 11.3311 | +2.96% | −5.95% |
| Eight hot calls, two cold probes | 13.5452 | 13.0535 | −3.63% | +7.45% |

Cold-host p95 fell from 472.61 to 236.65 ms, a 49.93% decrease. Both adjacent
AB/BA pairs show the cold-tail benefit and the whole-skew throughput/CPU cost.
Balanced and hot-only CPU changes differ in direction between their two pairs;
the total controller CPU across all three cells is 20.53 seconds for each
version. Skew hot-head p95 rises 5.87%. This is a measured fairness tradeoff,
not a claim that every latency or resource measure improves. The successful
second experiment does not resolve the first experiment's shared identity risk.

#### A17 to A23 standard observation comparison

The [standard ABBA comparison](evidence/x230-a23-observation-20261024.json)
retains all 1,152 successful timed calls, 24 initial checks and 48 same-job
checks after normal restart. All eight EOF shutdowns passed. Each version has
192 calls per concurrency, with the same six original completed jobs and small
outputs as the earlier A20 comparison.

| Concurrent calls | A17 calls/s | A23 calls/s | Throughput change | A17 p95 ms | A23 p95 ms | A17 CPU ms/call | A23 CPU ms/call |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 5.0389 | 5.8497 | +16.09% | 257.75 | 231.29 | 96.04 | 67.86 |
| 4 | 19.3548 | 22.6367 | +16.96% | 268.36 | 241.24 | 46.30 | 33.18 |
| 8 | 22.4429 | 28.7461 | +28.09% | 423.43 | 344.68 | 46.09 | 33.70 |

CPU per call falls 29.34%, 28.35% and 26.89%, respectively. Total timed-cell
controller CPU is 36.18 seconds for A17 and 25.87 seconds for A23.

| Measurement-controller lifetime sampled peak | A17 | A23 |
| --- | ---: | ---: |
| Controller RSS/HWM, KiB | 17,352 | 16,284 |
| Controller file descriptors | 75 | 79 |
| Controller plus observed descendant RSS, KiB | 94,984 | 109,000 |
| Controller plus observed descendant file descriptors | 135 | 152 |
| Observed descendants | 11 | 12 |

These are 100 ms sampled lower bounds, with three A17 and two A23 sampling
permission errors. They do not establish lower total process-tree memory or
descriptor use: those observed peaks are higher in this experiment. No
per-window resource series or SSH-only classification exists. The earlier
A20 experiment's different resource peaks are not substituted into this one.

#### Sustained observation: failed, candidate not adopted

The [single-candidate sustained experiment](evidence/x230-a23-soak-r01-summary-20261024.json)
used 10,356 C8 calls, selected from the completed 28.7461/s measurement to target
360 seconds, with a 300-second minimum observed-span check. All planned calls
were recorded, but only **4,224 succeeded and 6,132 failed**. The timed cell
lasted 192.4369 seconds and did not meet the duration requirement. The complete
[sanitized report, compressed without dropping call rows](evidence/x230-a23-soak-r01-20261024.json.gz)
is retained alongside the readable summary and its source hashes.

| Timed-call error | Count |
| --- | ---: |
| `observation SSH agent deadline` | 1 |
| Pool stopped before response authority check | 3 |
| Pool stopped during admission profile check | 4 |
| Pool unavailable; no fallback or automatic retry | 6,124 |

The specific deadline error was returned by a `process_status` call after
2,040.44 ms. The existing profile-validation path cancels the shared stop token
on this error, explaining the subsequent stopped/unavailable refusals. This is
a different branch from the first fairness experiment's post-spawn proof
refusal. The evidence identifies the agent-query timer expiring; it does not
establish whether the agent service, forwarding, controller scheduling or
another delay was responsible. That timer is also bounded by the remaining
original request deadline.

Successful throughput was 21.9501 calls/s for this failed experiment. The
53.8151 attempts/s and low mixed-call CPU/latency values include thousands of
rapid refusals and are not evidence of useful throughput or efficiency. There
is no measured A version in this B-only experiment and no performance
comparison is emitted. Duration alone does not count master renewals, and the
sampler does not establish a leak-free resource trend.

**A23 is not adopted.** The [decision receipt](evidence/x230-a23-decision-20261024.json)
binds every completed experiment and the exact source patch. Its short-run capacity and fairness results remain
valid within their stated scope, but they do not override this stability
failure. Exact-binary recovery checks for A23 have not been run. Further work
must preserve full per-request authority validation, reject the timed-out
request without retry, and independently qualify any narrower timeout-failure
scope. The adopted runtime source remains A20 at this checkpoint.

### A24 request-local agent timeout: qualified, first comparison incomplete

A24 changes only the treatment of the exact typed agent-query timer at three
direct request validation points: initial admission, before taking a master
lease, and before accepting a response. A timed-out request still fails and
discards its output. It supplies no cached credential result, does not extend
the original deadline, and is never retried automatically. Other requests must
perform their own complete checks. Initialization, first-master creation and
renewal retain the original fatal policy for every profile-check error,
including this timer. Other identity, file, policy, frame and I/O errors retain
their existing failure policy.

The [actual qualification receipt](evidence/x230-a24-qualification-20261024.json)
records 1,094 runtime tests plus 18 ownerctl and eight jobctl tests passed, 21
existing ignored tests, all five qualification stages successful, and the exact
formatted 150-file source map. Fifteen new isolated scenarios execute inside an
existing parent test and are not counted as fifteen extra top-level tests. The
controlled postresponse fixture uses an owned `ssh -G` child; it is not an
authenticated multiplexing fault-injection test. The
[exact A23-to-A24 patch](experiments/x230-a24-agent-timeout-isolation.patch)
reproduces the actual tested source, including the two test files changed by
formatting.

The first planned series was C16 ABBA, followed by fairness ABBA and the A17/A24
standard comparison. The [complete partial C16 record](evidence/x230-a24-capacity-r01-20261024.json)
preserves the actual execution:

| Round | Version | Timed calls | Initial full-output checks | Restart checks |
| --- | --- | --- | --- | --- |
| 0 | A20 | 46/96 successful; 50 capacity refusals | 6/6 successful | 12/12 successful |
| 1 | A24 | 96/96 successful | 6/6 successful | 12/12 successful |
| 2 | A24 | Not started after preflight failure | 5/6 successful | Not started |
| 3 | A20 | Not run | Not run | Not run |

The second A24 controller's `pocket4` read returned
`observation control socket is not the owned master` after 438.84 ms. Its five
other preflight reads succeeded. This is a different branch from the earlier
agent deadline and does not establish a permanently stopped pool. Across the
partial experiment, all 234 observation rows remain: 183 successful and 51
failed. No complete A20/A24 performance comparison is emitted, and the completed
first candidate cell is not presented as a passing full candidate experiment.

The [incident record](evidence/x230-a24-capacity-r01-incident-20261024.json)
binds the source branch, all five exact controller stderr files, the series
plan/execution records, and a later read-only inventory. The failing master
readiness check is byte-identical in qualified A20 and A24. Its generic error
does not distinguish peer PID mismatch, peer UID mismatch, or unequal socket
stamps before and after the existing connect. A later socket snapshot cannot
recover those earlier values or establish why they differed. The original
owned-child stop/reap and ledger release returned before this error could reach
the RPC; that does not imply successful directory cleanup or no prior effect.

Four controllers completed EOF shutdown with exit zero. The interrupted fifth
controller exited one with `private root not empty; reconciliation required`
and `ENOTEMPTY`. All five receipts record no observed descendant survivors,
reader errors or unmatched replies; two resource-sampling permission errors
remain. The later inventory found no process at the original controller PID
and one matching-name directory containing one socket. Filename matching is
not durable ownership proof. No object was deleted or adopted, and this later
inventory does not prove an exhaustive absence of processes or restore missing
startup evidence.

The series stopped at this failure. Fairness, the standard comparison, a
sustained A24 run and exact-binary abrupt recovery were not executed. **A24 is
not adopted.** Its narrower timeout behavior has unit and qualification
evidence, while the shared master-readiness failure needs separate diagnosis.
The next diagnostic experiment records only already-observed failure details
and must preserve the original proof and cleanup decisions.

### D2 bounded diagnostics: qualified, calibrated, not adopted

The [D2 qualification receipt](evidence/x230-a23-d2-qualification-20261024.json)
binds the actual A23-based diagnostic source, release binary and all five
qualification stages. It records 1,116 runtime tests plus 18 ownerctl and eight
jobctl tests passed, with 21 existing ignored tests. Two nested isolated-helper
result lines are not added to that total. The
[first qualification failure](evidence/x230-a23-d2-r01-qualification-failure-20261024.json)
is retained: strict Clippy rejected one test assertion. The subsequent attempt
changed that assertion while preserving both the error variant and message.
The [exact diagnostic patch](experiments/x230-a23-d2-instrumentation.patch)
reproduces the qualified 151-file tree from the qualified A23 source.

D2 records 32 fixed phase counters on the existing controller owner thread.
Thread CPU is measured only around synchronous work; asynchronous agent queries
record wall time only. Diagnostics are disabled unless explicitly selected for
the experiment. Up to 16 post-spawn proof-failure events can retain the original
pidfd and identity-check substage results without changing the proof predicate,
cleanup, stop decision or retry policy. These counters and failure records are
diagnostic work, not an adopted runtime change.

The [calibration summary](evidence/x230-a23-d2-calibration-r01-summary-20261024.json)
and [complete sanitized experiment](evidence/x230-a23-d2-calibration-r01-20261024.json.gz)
retain four C8 runs of the same qualified D2 binary in off/on/on/off order. Each
run has 384 timed calls against the same six original completed jobs. All
1,536 timed calls, 24 initial-output checks, 48 restart checks and eight EOF
shutdowns passed. Both first controllers and both restart controllers with
diagnostics enabled produced complete, internally consistent counter records.

| Pooled timed-cell measure | Diagnostics off | Diagnostics on | Change |
| --- | ---: | ---: | ---: |
| Controller CPU per attempt, ms | 35.7682 | 36.8880 | +3.13% |
| Successful calls/s | 27.8939 | 27.2554 | −2.29% |
| All-row p95, ms | 367.44 | 359.49 | −2.16% |

The frozen review required pooled CPU overhead at most 5%, useful-throughput
loss at most 5%, and p95 growth at most 10%; each adjacent off/on pair also had
its own predeclared limits. All passed. CPU, throughput and p95 changes each
reverse direction between the two pairs. This supports exploratory attribution
within those limits, not a precise or stable causal estimate of instrumentation
cost. It measures enabling D2 on one binary; it does not measure disabled D2
hooks against uninstrumented A23.

| First-controller diagnostic measure | First enabled run | Second enabled run |
| --- | ---: | ---: |
| Owner-thread lifetime CPU, seconds | 13.1992 | 13.2209 |
| Complete file-validation CPU, seconds | 12.1965 | 12.1912 |
| File validation / owner CPU | 92.40% | 92.21% |
| Read-and-hash / file-validation CPU | 89.64% | 89.61% |
| SSH executable validation / owner CPU | 70.74% | 70.57% |
| Complete file-validation intervals | 2,357 | 2,357 |
| Agent snapshot intervals | 1,179 | 1,179 |

These owner-thread denominators include initialization, observations and normal
drain; they are neither whole-controller CPU nor the timed-cell interval. Each
restart controller has a separate record, with 89 file-validation intervals
and 45 agent queries. Parent counters include their children and must not be
added together. Read-and-hash combines reads, buffering and digest updates; it
does not isolate pure SHA256 computation. Agent wall intervals overlap and
cannot be summed into CPU time. The full evidence preserves resource-sampling
errors and only supports sampled lifetime lower bounds for resource peaks.

No post-spawn proof-failure event occurred in these four runs. That absence
cannot explain the older fairness failure or prove it fixed. The phase results
justify an isolated experiment moving complete validation or its read/hash
work to bounded workers while preserving every authority check. They do not
establish the cause of A23's sustained agent deadline, guarantee a throughput
gain, or authorize adopting an unqualified worker implementation. The adopted
runtime source remains A20.

### Request-serialization hash replacement

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
copies whose private path constants or comments were changed, plus two
copyright-header-only changes. Their hashes
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

The x230's installed perf 6.8.12 could not measure even an own-process
`perf stat -e task-clock -- /bin/true` probe: it returned 255 with an access
denial while `perf_event_paranoid` was 4. The
[profiler-availability receipt](evidence/x230-profiler-availability-20261023.json)
records the original report hash. No runtime was attached and no host setting
was changed. Aggregate controller CPU measurements remain available, but this
probe provides no phase-level attribution to hashing, path validation, agent
queries, or child management. The separate D2 in-process diagnostic experiment
above provides the narrower, explicitly calibrated phase evidence without
changing the host's profiler permissions.

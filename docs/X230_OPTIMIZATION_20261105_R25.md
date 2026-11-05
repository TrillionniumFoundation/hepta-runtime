# X230 R25: qualified cancellation reserve, observation gate rejected

## Disposition

R25 is **not adopted**. Its complete qualification and supplementary external CI
passed, and the original six-host observation campaign completed every correctness
stage. The frozen C1 throughput and controller CPU gates failed. Accepted R24
commit `baab4def80be7af015b2e7a594cb302f66c4130e` remains the production source.
This evidence change does not install the rejected source into `src/`.

The observation was executed once. No first A round was discarded, no threshold
was changed, and no historical sample was pooled into the result. The campaign's
`passed=true` records successful evidence/correctness execution;
`observation_gate_passed=false` records the performance rejection. Neither value
establishes final candidate adoption.

The [evidence index](../tools/x230/20261105/r25/README.md) links exact reports,
the complete rejected patch and original native operation receipts. This companion
commit includes all four original X230 archives after lossless transfer and
independent archive verification, together with the complete transport recovery
chain. The two original qualification attempts, rejected observation and successful
external CI remain distinct. No workload was repeated to obtain these archives.

## Candidate and bounded cancellation contract

R25 adds an internal reserve for cancelling an existing, validated job when normal
direct SSH admission is saturated. Ordinary direct transports retain 16 admitted
requests, 8 active children and 2 children per target. A cancellation first tries
to obtain every ordinary permit immediately. If ordinary capacity is unavailable,
it drops partial permits before trying a reserve with 8 admitted requests and
1 active child. Start and same-key reuse cannot select that reserve.

Mixed direct traffic is consequently bounded by 24 admitted requests, 9 active
direct SSH children and 3 direct children to one target. These are direct transport
limits, not a bound on every SSH process used by the controller: observation
masters and their slaves belong to the separately bounded observation pool.
Both direct lanes share the original child registry, leases, freeze, reap and
quarantine handling. A closed or poisoned admission path fails. There is no
post-submission fallback or automatic replay of an effect.

Eight new tests cover ordinary saturation, immediate normal cancellation,
partial-permit release, reserve bounds, caller-drop reaping, queued deadlines,
freeze/quarantine and public routing through both supported job backends.
Full real-transport lifecycle ABBA and controlled cancellation under saturation
were prepared but **not executed**, because observation nonregression was their
prerequisite. Unit qualification alone does not close that real-transport blocker.

## Original qualification attempts

Attempt 01, native job `1a1aa7fa690-fc05-43af`, retained 1,652 passes, one failure,
34 ignored cases and zero retries. The new public-routing fixture omitted
`allow_job_network=true` on its operator host. The expected explicit policy check
rejected the fixture before its start/reuse/cancel assertions. The original
report, failed output and complete failed archive remain preserved.

Attempt 02 adds that exact 26-byte fixture field in a fresh source/cache/output
tree. It changes no production statement or test assertion from attempt 01.
Native job `1a1aaa6552d-fc05-459f` passed all eight original qualification stages:
format, format check, harness tests, Clippy, test build, isolated tests, independent
test audit and release build. The result is **1,653 passed, 0 failed, 34 ignored,
1,687 selected, 0 retries**. All 221 tested source inputs match the final inputs.

The complete qualification report is 83,748 bytes, SHA-256
`72a4001ed303d565f5c3300ea8786acf1c4e9d7991e0a1f0486fabc140900e3c`.
The actual R25 runtime is 14,378,216 bytes, SHA-256
`c8c1fc3a38923e240bcc18bd8c79bb1f3e9831beb8e59067c6ea41f86878b811`.
The accepted R24 comparison binary is bound by SHA-256
`bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13`.

## Original six-host observation result

Original Mac holder job `1a1aacd207e-fc05-4774` completed successfully with durable,
complete native output. Its original SSH child returned zero, its own agent was
reaped, and the private agent socket and directory were absent afterwards. The
X230 campaign retained unchanged candidate and baseline source, inputs and
actual binary identities.

The fixed protocol used ABBA order at C1/C8/C16, 192 measured and 24 warmup calls
per cell, two validation workers and allocator arena 1. Across all cells it
retained 2,304 measured calls, 288 warmup calls and 72 preflight/restart calls:
**2,664 total calls, zero failures**. These are completed-job observation RPCs,
not newly launched jobs per second.

| Concurrency | A → B successful RPC/s | Change | A → B controller CPU ms/call | Change | A → B p95 ms |
|---|---:|---:|---:|---:|---:|
| C1 | 8.647139 → 8.065996 | −6.72% | 26.041667 → 30.781250 | +18.20% | 181.185631 → 181.918892 |
| C8 | 48.878830 → 53.464521 | +9.38% | 20.234375 → 19.661458 | −2.83% | 230.670986 → 211.066565 |
| C16 | 49.075360 → 56.047915 | +14.21% | 20.911458 → 20.182292 | −3.49% | 452.681100 → 345.545032 |

Every concurrency level independently requires throughput B/A ≥0.95, p95 B/A
≤1.10 and controller CPU/call B/A ≤1.10. C1 fails throughput (0.932794) and CPU
(1.182000); its p95 passes. C8 and C16 pass all three gates.

Maximum sampled controller RSS was A=18,932 KiB, B=19,124 KiB: an increase of
192 KiB. It passes both A+512 KiB and A×1.05 limits. RSS is a sampled process
peak, not a whole-cluster allocation bound. Controller CPU excludes the Python
harness, local child CPU and remote machine CPU.

The two original C32 bursts produced 32 successful responses, 32 separately
reported capacity refusals and no other error; drain and recovery passed. The
unchanged C6 recovery canary retained 90 native calls, 36 independent SSH checks,
6 starts, 12 same-key lookups and 12 cancellations, with original ROG master
interruption, controller crash/restart, execution-once and terminal witnesses.
That canary is correctness evidence, not a lifecycle performance ABBA.

## Interpretation and next work

The first and last A-arm C1 rounds differ materially: 9.766759/7.757815 RPC/s and
21.145833/30.937500 CPU ms/call. B's two rounds are 8.151902/7.981882 RPC/s and
30.416667/31.145833 CPU ms/call. This finite campaign does not identify the cause
of the difference. Its rejection remains in force.

Source review confirms that measured status/read requests use the enabled
observation pool. R25's new direct admission helpers are not executed on that
route. The pool bodies themselves match R24. A possible effect of cold direct
branches on containing async future layout is unmeasured and is not a causal
claim. The subsequent R26 proposal separately removes an unused JSON construction
in pooled reads; that redundant construction existed in R24 too.

Remaining work is recorded explicitly: phase attribution of the capacity plateau,
qualification and measurement of any new candidate, matched lifecycle performance,
real cancellation under direct saturation and exact Git integration. Publication
of this experiment's complete raw evidence is closed by the companion archives.
This report does not assert that every optimization blocker
is closed or that hardware/software performance has reached a global optimum.

## External CI and hosted Actions

The supplementary native Rust CI job `1a1aac67f44-fc05-471d` ran the unchanged
workflow `cargo check` and pinned nextest 0.9.137 commands against the qualified
R25 source. Its full structured inventory and progress audit retained 1,653 PASS,
34 ignored cases, zero failure and zero retries, including the zero-case example
target. Original stage children were reaped; no cleanup signal was required.

Native Python CI job `1a1aaa69a3d-fc05-45a1` passed all 18 original workflow
commands, with all 85 bound Python/workflow dependency files unchanged. Its
dependency scope is recorded against published head
`1aa98d3c94d0253999a491c967ccc94b314e87c8`; it is not a claim about future Rust
changes.

These are external native CI results. At that original Git head, hosted push and
PR runs ended cancelled, not passed; the exact-head PR job had completed its
Rust test step before a later cancellation. The only supported log error was
`The operation was canceled.` Its actor/cause was not established. External CI
does not substitute a fabricated hosted check status.

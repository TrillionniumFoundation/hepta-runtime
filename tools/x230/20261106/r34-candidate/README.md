# R34: ordinary-first reserve for cancellation of existing jobs

**Status: independent candidate, statically prepared; not compiled, tested, benchmarked, or adopted.** This package is a new implementation authored from accepted R24. It is not a recovery of the earlier unavailable private reserve patch. No runtime API, SSH connection, Rust compiler, Rust formatter, test process, or benchmark was invoked while preparing it.

The candidate uses accepted R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e` as its Git parent and compilation baseline. It does not include R31 pidfd waiting, R32/R33 profile changes, the shared router, JSON deferral, or an increase to ordinary/global observation capacity. Any later combination with R33 requires a separately frozen source map and patch.

## Intended behavior

An existing job cancellation first tries the ordinary transport admission, target, and global execution permits without waiting. If all three are immediately acquired, it uses the ordinary owner path. If any ordinary permit is unavailable, all partially acquired ordinary permits are released before trying the cancellation reserve. The reserve has eight admission permits and one global execution permit. It waits only for that execution permit, using the caller's original absolute deadline and the existing owner stop fence.

| Transport resource | Ordinary | Cancellation reserve | Combined bound |
|---|---:|---:|---:|
| Admitted identities, including waiters and original children | 16 | 8 | 24 |
| Global execution permits, including ready/queued requests and unreaped children | 8 | 1 | 9 |
| Execution permits for one configured SSH target | 2 | At most the one global reserve | 3 |
| Shared owner channel entries | Existing shared owner | Same shared owner | 9 |

The target key remains the existing `host.ssh_target` string. These are limits for that configured SSH target, not a new claim that different target strings or separate controller processes share one physical-host quota. Other existing job preparation/publication admission limits remain unchanged. The 24-identity bound applies to direct transport admission; it does not redefine all upstream request memory as admitted transport work.

The reserve can be selected only by the two internal existing-job cancellation wrappers. `jobs::cancel_job` still verifies the full original operation receipt and publishes cancellation intent before selecting either wrapper. The system-job wrapper constructs the same fixed `{"op":"cancel","job_id":...}` request; the Python wrapper receives the same bound `CANCEL_CODE`, request fields, and 45-second timeout. The ordinary public SSH/Python/jobctl entry points continue to use ordinary admission. No request schema, user-selected admission mode, raw command capability, or new public MCP tool is added.

### Deliberate waiting tradeoff

Ordinary-first is a single initial decision. A cancellation already waiting for the reserve does not switch back if ordinary capacity later becomes free. This keeps admission and ownership simple, but can leave a cancellation waiting behind the reserved child while ordinary capacity is available. It may affect latency or throughput under changing load. Neither faster cancellation nor higher aggregate throughput is claimed by this static package. Saturation and ordinary-load measurements must decide whether this policy is useful.

## Ownership and bound arguments

`try_ordinary_cancel` is synchronous: it acquires ordinary admission before looking up a target and then attempts the target and global permits. A `NoPermits` return exits the function, dropping all earlier locals. Only after it has returned does `acquire_job_cancel` acquire reserve admission. Therefore one request never waits in the reserve while holding ordinary admission or an ordinary target/global permit. An encountered closed ordinary semaphore is an error, not a reserve fallback. Production shutdown continues to use the existing Core stop fence; the test for closed capacity covers the encountered global-closed branch.

The reserved `Leases` has no ordinary target permit. This does not add an unbounded target lane: the same single reserved global permit is required for every target, so at most one extra child can exist anywhere. Together with the original two ordinary permits for a target, that gives a maximum of three. A reserved child retains its admission and global permits in the same `OwnedChild` that holds ordinary permits. No second reserve semaphore, second owner, replacement registry, or untracked child is introduced.

Every request admitted to the owner channel already owns one of the eight ordinary or one reserved global execution permits. At most nine such requests can exist in the channel, in an owner task, or in the original-child registry together. With channel capacity nine, a legitimate request that holds one execution permit cannot be refused merely because eight other ready requests filled the old ordinary-only queue. A closed/stopped owner can still reject it. No production caller reserves channel entries separately from execution permits.

The existing `capture` body after admission is factored into `capture_admitted` without changing its bytes. The request retains the same cancellation token, queued/committed CAS, pre-submission and reply deadline checks, copied input, one-shot reply, no-automatic-retry errors, and drop cancellation behavior. The owner still commits and spawns the original `Child` under its existing registry and acceptance protocol. `Core`, `ChildState`, `OwnedChild`, reap logic, owner runtime, shutdown join, and quarantine logic remain unchanged. If an original wait becomes uncertain, both admission and execution capacity stay in original-child custody and shutdown remains failed; there is no release based on an ACK or a guessed PID.

The reserve waits with the original absolute deadline, never a new timeout. It checks the existing stop/deadline fence before acquisition and after the reserve permit becomes ready. The unchanged submission path checks again before sending and before spawn. This covers the race where capacity becomes available at the same time as expiry or stop. The original bounded cleanup deadline remains separate and unchanged.

At the job layer, receipt checks, cancellation intent, retained record ownership, `retain_cancel_outcome`, and completion audit are unchanged. A cancellation acknowledgement still does not establish a job terminal state. All six embedded Python helper literals, including `CANCEL_CODE`, are byte-identical to R24; this candidate does not alter remote cancellation signaling or acknowledgement semantics.

## Changed compilation inputs

| Path | Change |
|---|---|
| `src/mcp/runtime/ssh_direct.rs` | Two bounded reserve semaphores, ordinary nonwaiting attempt, optional ordinary target lease for the single reserve, channel capacity nine, shared post-admission capture body. |
| `src/mcp/runtime/ssh.rs` | Internal admission selection and two existing-job cancellation wrappers; ordinary APIs, commands, serializers, decoder/error paths, and deadlines retained. |
| `src/mcp/runtime/jobs.rs` | Exactly two existing `cancel_job` transport call substitutions. |
| `src/mcp/runtime/ssh_direct_tests.rs` | Eight sibling boundary tests and reserve-capacity checks in existing successful owner cleanup. |

No compilation input is added or removed: 220 baseline entries become 220 candidate entries, with 216 identical hashes. `source/` contains the four complete changed files. `candidate.patch` applies to the accepted R24 source and reconstructs those exact bytes. This is the pre-qualification, manually formatted source; no Rust formatter was invoked. Any later qualification formatter output must be bound by its actual final source map rather than silently substituted for this frozen map.

## New tests prepared for the original qualification workflow

The eight tests use the existing private local Python-child fixture, owner thread, original wait receipts, and scoped temporary directories. They are source only in this package. No fixture or test has been executed here.

1. **Ordinary preference while the reserve is busy.** A real cancellation child must run with ordinary permits even when the reserve execution permit is held. Ordinary and reserve counters identify the selected path.
2. **Partial ordinary release before reserve waiting.** Separately exhaust ordinary target and global capacity, then hold the reserve. Verify all acquired ordinary permits have returned before the cancellation waits, and that aborting the waiting caller returns reserve admission without a child.
3. **Encountered closed ordinary capacity.** Close ordinary global capacity while admission and target capacity remain available. Verify rejection, returned partial permits, an unused reserve, and no child.
4. **Full ordinary and reserve bounds.** Establish eight ordinary children, then eight ordinary waiters; reject an ordinary overflow call. Add eight reserve identities, observe exactly one extra child and 24 admitted identities, and reject a ninth reserve identity. Real serialized fixture start/end events must peak at nine globally and three for the selected target. Initial eight-child readiness is established before adding waiters so scheduler order cannot change the expected ready identities.
5. **Actual production owner queue capacity.** Acquire eight ordinary execution lease sets and one reserved set, then reserve nine entries on the real production `Sender` before publishing any request. The ninth entry must succeed and a tenth must fail. A running receiver cannot mask an eight-entry bug because no request has been published yet. Publish those nine real requests, check both output streams and successful owner cleanup.
6. **Readiness versus expiry/stop.** Poll a reserve waiter once, then make the original deadline or stop fence ready before returning the reserved permit. Re-poll only when both are ready. Verify an error, no spawn, and all reserve capacity returned.
7. **Caller cancellation before confirmed reap.** Abort a running reserved caller and block the original owner's reap with the existing fixture gate. The registry and reserve permits must remain occupied; another cancellation must expire without spawning. Release the original gate and verify capacity returns only after reap.
8. **Unconfirmed wait quarantine.** Use the existing injected-unconfirmed-wait hook on a real reserved child. Repeated shutdown stays failed; the original registry and reserve remain occupied. Test teardown uses only that original child's cached real wait status, matching the existing ordinary fault fixture, and cannot turn the persisted shutdown result into success.

All pre-existing direct-owner test code is preserved except for two additional successful-cleanup assertions covering reserve permits. Existing job cancellation tests remain unchanged and continue to cover outcome/ACK identity semantics. These assertions supplement the original suite; they are not a replacement for it.

## Static evidence and reproducibility

`reference-r33-input.json` is the exact published R33 preparation input blob `86c91524ab994accb647e900220361b2505e31ba`, 52,436 bytes, SHA256 `3753078ae1fa3dd7c9b2582d2d5a6e01335937b6651c5094314955e16b1af48d`. Only its `baseline_compile_inputs` is used: that is the accepted R24 220-entry map, not R33 candidate source. `baseline-compile-inputs.json` records that map. The accepted Git root tree is `b74e40052e275abe99c51df460e94622d516af34` and its `src` subtree is `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`, as separately verified by the parent task.

Nine relevant baseline files were fetched as exact GitHub content at the accepted R24 commit and independently checked against the map before source work. They are retained under `baseline/`. The full map is inherited from the identified reference artifact; this package does not claim that it independently fetched all 220 files. The changed-source overlay and all preserved map entries are checked locally.

The actual executed local command was:

```sh
python3 -B /tmp/hepta-runtime-recovery-20261106/r34/verify_candidate.py --write
```

It returned exit 0. This command only reads source, compares exact text, calculates SHA256, generates the unified diff, and reconstructs each changed file from its exact diff context. It does not parse or compile Rust, run application code, or execute fixtures. `static-checks.json` records the preserved source-region and helper hashes, exact two-call job change, original test preservation, eight new test names, 220-entry map, and patch reconstruction. A subsequent non-writing verification is available as:

```sh
python3 -B /path/to/r34-candidate/verify_candidate.py
```

`input.json` and `manifest.json` identify the frozen artifacts. They contain no fabricated future qualification, CI, benchmark, or adoption result. Independent source review may identify issues, but only the later original qualification and measured workload can establish build correctness or performance.

## Resource costs and remaining risk

This direction deliberately permits one additional local SSH transport child and up to eight additional admitted cancellation identities. It adds two semaphore `Arc`s and one logical owner-channel slot, and adds ordinary try-acquisition plus stop/deadline checks on cancellation. The request/child lease also uses an optional host permit; no Rust layout or RSS measurement is claimed. Existing JSON/script preparation before direct admission remains in its original place; the post-admission direct transport copy remains after lease acquisition.

Those costs can outweigh any benefit if cancellation is rarely blocked or if the reserve becomes a bottleneck. Ordinary calls cannot borrow spare reserve capacity, and waiting cancellations do not reselect the ordinary lane. Queue and child bounds are safety arguments, not throughput results. The candidate has no allocation, CPU, RSS, latency, concurrency, or multi-machine throughput measurements. Subsequent adoption must use the unchanged original verification and workload criteria on the actual frozen version.

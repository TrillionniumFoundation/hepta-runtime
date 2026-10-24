## Problem
The trusted native library boundary, adopted A20 recovery owner and canonical shadow contract were spread across branches. This composition lets them build and run together through the original durable process owner.

## Composition and behavior
Combined source: `dd7bf97f4cbe9b77d35c117ef1584e541129f041`. Base `ceae1b86f705e413a28948385bf57c684651c298`; merged A20 `7da3a7ebaded8214bc65e69046b74e6251e21767`; imported/adapted native donor `f4ff86681ead2c538b69ce9bdea86e79e3bb94a7` and shadow donor `55ea025817a0d864024c42a9f155a1f3ae59af2c`. Source import is not claimed as merge ancestry.

`native::{execute_or_observe,status,read,cancel}` retains original job identity, stable idempotency key, full payload binding, path/owner/link checks and terminal-publication witnesses. The shadow ABI remains non-executable. A strict private decoder fixes extra-field acceptance without changing canonical wire bytes; the relink fixture now respects the no-hardlink policy and has a separate refusal regression. Canonical counterpart #3666 passed its own 19 scoped tests, separately from this runtime.

## Qualification
- Format, all-target/all-feature strict Clippy and the native example build passed in job `1a16cc27e56-1b6abb-46bd`.
- Real localhost-SSH native canary passed: original controller killed with SIGKILL; original job remained running; same key reused the same job without retry; changed payload refused; exact output and terminal witness observed. One original worker entry was recorded.
- A separate owned job received a cancellation request, followed by authoritative cancelled status and a publication witness; one worker entry was recorded. A stop-request acknowledgement is not itself terminal proof.
- Binary SHA256: `c792efcaa3a712acbaeb61e20d99fdf408e5df5c7cad15374cd5a700fb40717a`. Raw canary report SHA256: `4868644068756417162a40e4e3e316dbcecf3561ea4d93568c15bd2a75889d33`.
- Full nextest correctness gate: **passed**. Summary [1790.418s] 1177 tests run: 1177 passed (4 slow), 21 skipped. Job `1a16ce06214-1b6abb-4714`; one test process at a time, retries 0, two CPUs/8 GiB, nice 10, nonexclusive host.
- Earlier warm Cargo result remains recorded: 1,142 passed / seven failed / 21 ignored in 2,595.71 seconds. Two semantic issues were repaired; five failures involved the unchanged three-second metadata budget under shared-process contention. The initial cold attempt exceeded 1,800 seconds.
- Existing hosted CI success is not inferred from the local gate. Historical A20 evidence bytes remain unchanged.

## Scope
This qualifies the trusted native process boundary over owned temporary workloads. It does not establish production FinalUse, Codex sandbox parity, target-reboot recovery, arbitrary business exactly-once, whole-agent memory savings or task-quality gains. Existing services and production deadlines are unchanged.

Source and protocol details: [native boundary](https://github.com/TrillionniumFoundation/hepta-runtime/blob/dd7bf97f4cbe9b77d35c117ef1584e541129f041/docs/NATIVE_LIBRARY_BOUNDARY.md), [canary](https://github.com/TrillionniumFoundation/hepta-runtime/blob/dd7bf97f4cbe9b77d35c117ef1584e541129f041/tests/native_library_process_canary.py). The compact evidence, retained full nextest log and exact run receipts are in tests/evidence/20261024-native-process/.

## CI change
Both existing exact-head and prospective-merge jobs now install pinned cargo-nextest 0.9.137 and run the same process-isolated inventory with one active test and zero retries. The job budget is 90 minutes for the measured 30-minute warm suite plus cold build/install variance; production deadlines and all existing non-test gates are retained. Hosted execution at this new head remains a separate gate.

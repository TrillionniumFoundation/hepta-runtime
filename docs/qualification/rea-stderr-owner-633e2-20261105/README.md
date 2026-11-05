# Native analysis stderr owner regression

The frozen source baseline is ce246a57cdc6299fb7291fa03fb8eca0f44b1716.
Four real-child library tests were introduced before changing supervision.
They all fail against the old implementation and all pass after the fix.
The separate ten existing ELF worker/ownership regressions also pass.

| Run | Executed result | Meaning |
| --- | --- | --- |
| First CLI-target attempt | 0 selected | Discarded; exit 0 is not test evidence |
| Old transport, correct library target | 0 passed, 4 failed | Deadline, late cancellation, overflow, and slot drainage defects reproduced |
| Corrected transport | 4 passed, 0 failed | The four regressions pass; no ignored cases |
| Existing worker regressions | 10 passed, 0 failed | Pipe, framing, diagnostics, large output and owner/drop cases remain passing |

A fixture retains an independent write descriptor while the actual worker exits.
It does not launch or signal an unrelated process. Successful cleanup means the
sole native child was reaped and both owned reader tasks ended before its slot
was released. It does not prove an arbitrary external engine process tree was
terminated. Cancellation preserves the bounded diagnostics already received and
explicitly reports a reader cancelled before EOF.

The stderr completion signal is now part of the same provider deadline as stdin,
stdout and child wait. Overflow triggers kill/reap promptly. Cancellation closes
the owned reader even if another descriptor still holds the write endpoint.
An aborted caller leaves its private owner responsible for drainage.

The red-source directory preserves the exact negative-control transport and test source.
Raw stdout/stderr logs and machine-readable command receipts are kept unchanged.
The first CLI attempt is preserved as a nonqualifying observation. All runs use
Rust library tests on the development Linux host with offline locked dependencies,
4 Cargo build jobs, one test thread, and dev/test debug information disabled.
These are component/real-child regressions, not complete original-REA operation,
full-runtime, release, multi-host, or production qualification.

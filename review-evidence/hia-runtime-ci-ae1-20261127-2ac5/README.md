# Original ae1 Runtime CI evidence

Source: ae1c7ea593da45f7299c692a2acd44605c35be09.
Original workflow run: 46006012612; exact-source job: 140529232000.

The complete original job log is retained as deterministic gzip. It reports
2,658/2,658 nextest tests passed with 44 original skips in the default feature
configuration, and 2,616/2,616 passed with 32 original skips without remote
filesystem support. No nextest failure, flaky outcome, or retry record occurs.
The original format, locked checks, clippy, release build, descriptor safety,
control-plane, REA, ingress, real JavaScript cancellation/recovery and independent
Python ZIP/shipped Rust worker checks all completed successfully.

The two original Actions artifact ZIP files are retained byte-for-byte with
their platform SHA256 digests checked. The manifest also records every original
ZIP member's actual byte count and SHA256. The job log's cancellation observation
was 0.021174585 seconds; the preserved artifact contains the rest of that run.

This record qualifies the original hosted Runtime CI for the source above.
The actual installed nineteen-role HIA public START/STATUS/read/witness gate is
separate and was still waiting for the repaired native release package when
this evidence was captured. Original skips and that open gate are not reported
as passed. This commit changes evidence only; it changes no Runtime source.

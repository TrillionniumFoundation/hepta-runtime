# Original blocking capture file oracle

This private test executable calls the fixed linked Rust 1.95.0 standard
library `std::fs::File::create`, `std::fs::remove_file`, and the original owned
file destructor. It contains transport and ownership plumbing, not a rewritten
file algorithm. It is built directly with the admitted Rust compiler and its
complete standard-library dependency inventory. No Cargo dependency or
original test is added by this small blocking reference.

The complete original Tokio file, open-options, and remove-file sources are
retained as provenance. The runtime call spans and reviewed standard-library
sources are pinned in `source_manifest.json`. Tokio scheduling, asynchronous
cancellation, `into_std` inflight work, registry ownership and complete capture
preparation are outside this reference.

## Input

No command-line arguments are admitted. Stdin is one complete frame: eight
little-endian u64 words followed by the exact raw Unix pathname bytes.

| Word | Meaning |
|---:|---|
| 0 | ASCII `HSHCFRQ1` |
| 1 | Version 1 |
| 2 | Operation: 1 CREATE, 2 UNLINK |
| 3 | Exact path length |
| 4 | CREATE disposition: 1 DROP, 2 TAKE; UNLINK requires 0 |
| 5..7 | Zero |

The input has no file descriptor or capability field. It neither replaces the
original CString conversion nor normalizes pathname bytes. CREATE failure
does not apply a disposition. Successful DROP is the original `drop(file)`.
Successful TAKE moves the same `File` into the fixture consumer. The consumer
keeps the descriptor until `std::process::exit(0)`, which bypasses local Rust
destructors; actual process termination releases it in the kernel. This matches
the native fixture's receiver boundary and does not qualify a production
receiver cleanup policy.

The two exact stderr markers `HSHCFRUST-BEGIN\n` and `HSHCFRUST-END\n` enclose
the original operation and the optional DROP or TAKE. Complete actual syscall
traces bind those markers, input, arguments, environment, raw results and both
captured output streams. Infrastructure failures are not semantic file errors.

## Output

Stdout is exactly 48 bytes: ASCII `HSHCFO01`, operation, result kind, errno,
applied disposition, and the actual original descriptor. Result kind is 0 for
success, 1 for a positive raw OS errno, or 2 for original local `InvalidInput`
with a NUL pathname. The descriptor is `u64::MAX` when no descriptor was
created. A successful descriptor is the original process's observed number;
it must not be equated with a descriptor number in a separate native process.

Only genuine original calls are counted. Native START/RESUME replay and invalid
old-arena lifecycle requests remain native-state checks; they are not mapped
to invented Rust operations. A comparison may align the original CREATE and
owned DROP with the native actual open and close while retaining every native
request and complete result independently.

All production, full-runtime, asynchronous cancellation, and old-stack-removal
scope flags remain false. The reference is qualification infrastructure only.

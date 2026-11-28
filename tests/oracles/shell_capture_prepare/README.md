# Blocking projection of original capture preparation

This fixture qualifies a bounded projection of the original
`src/mcp/fs/background.rs` capture creation block. The reference builder checks
the complete original file, Cargo manifest and lock bytes, then reconstructs
`crate/src/projection.rs` from the exact recorded spans and six explicit edits.
It retains every compiled source byte and the exact before/after edit bytes.

The unchanged `JOB_SEQ` declaration, `jobs_dir` and `next_id` functions are
compiled. The original sequence allocation still happens only after successful
directory creation. The stdout creation, stderr creation, stdout drop and
ignored cleanup unlink stay in their original order and branches. The only
body edits select the underlying `std::fs` operations and remove Tokio awaits
and `into_std` conversion. The error macro is a test carrier that records the
real `io::Error`, its raw errno and the original format arguments. It is not the
production `anyhow` type.

The full original Tokio `create_dir_all`, `file`, `open_options` and
`remove_file` sources remain referenced from the existing frozen leaf fixtures;
they are not duplicated here. `review/tokio_fs_mod.rs` records the complete
pinned `asyncify` source. Its blocking task failure and runtime scheduling
paths are outside this projection. The `into_std` inflight wait and Arc unwrap
are also outside this projection. This is not an execution of the complete
async `prepare` function or a Tokio runtime.

## Actual operations and ownership

Every semantic case runs a fresh fixed Rust 1.95 executable, with the production
edition and release profile, under the actual unprivileged account, controlled
cwd, environment and umask. The executable gets its real PID and the real
Linux `std::env::temp_dir` value. A private per-process sequence is seeded by
the fixture and advanced by the unchanged `AtomicU64::fetch_add` expression.
No raw FD, syscall result, native token, expected errno or statx cache state is
accepted as input.

On success both `File` values are moved into a receiver and physically retained
until the controller observes their actual FD/inode ownership. The final
constant acknowledgement ends the receiver process using `process::exit(0)`;
kernel exit cleanup is not a further semantic Rust drop or native close.
On stderr creation failure the original explicit stdout drop and cleanup unlink
run before the original error is returned. Failed cleanup cannot replace the
saved stderr error.

The comparison pairs the fourteen natural native cases. The native controlled
directory replacement race is independently retained and verified, but does
not become an ordinary original case. Other synthetic native errno and invalid
lifecycle controls are never replayed as if they were actual Rust calls.

## Transport

Before reading a request, stdout emits 32 bytes:
`HSPPORD1`, actual PID, version 1 and reserved zero, all integers u64 LE.
The controller may now set up paths containing that PID while the child blocks
on stdin. The request is exactly 64 bytes: `HSPPORQ1`, version 1, sequence seed,
and five zero words. TMPDIR and cwd are actual process launch observations.

Stderr emits exactly `HSPPORUST-BEGIN\n` and `HSPPORUST-END\n` around the projected
capture call. The complete `strace -ff` files retain loader operations, both
markers and all actual mkdir/statx/newfstatat/openat/close/unlink operations.
The comparison reads full paths, actual flags, results and descriptor custody;
it does not infer effects from an error message.

The response begins with 160 bytes, twenty u64 LE words:

| Word | Meaning |
| --- | --- |
| 0 | `HSPPOR01` |
| 1 | Complete response extent |
| 2 | Result: 0 success, 1 error |
| 3 | Stage: 0 success, 1 directory, 2 stdout, 3 stderr |
| 4, 5 | Error kind (0 none, 1 raw OS, 2 local InvalidInput), raw errno |
| 6 | Sequence increment observed |
| 7, 8 | Actual private sequence before and after the projected call |
| 9 | Actual process PID |
| 10, 11 | Actual successful stdout/stderr FDs, otherwise u64 maximum |
| 12..15 | Directory, id, stdout path, stderr path byte lengths |
| 16 | Original error-format message byte length |
| 17 | Successful receiver owns both Files |
| 18, 19 | Reserved zero |

The five complete byte strings follow. Error metadata reuses only the original
pure path formatting statements; it performs no additional filesystem call or
fetch-add. For a directory failure only the directory is present. The controller
finishes with the eight constant bytes `HSPPOEND` after its custody observation.

Original and native PID, inode and FD numbers belong to different actual
processes and fixtures. The comparison retains them unmodified and establishes
explicit path/component and ownership relationships; it never compares these
numbers as if they were the same identity. Message text is retained without
claiming native error Display equivalence.

There are zero imported original tests. Duplicate registry admission, global
counter concurrency, ambient-observation replacement, Tokio scheduling and
cancellation, `Job`/Arc/Mutex/time construction, public integration, production
activation, whole-runtime replacement and old-stack removal remain unqualified.

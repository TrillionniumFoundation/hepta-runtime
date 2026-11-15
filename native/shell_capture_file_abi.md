# Shell capture file: blocking Linux leaf ABI

This HIA owner implements the fixed file operations needed by capture preparation:
write-only create/truncate, remove_file, and dropping an owned file. An explicit
TAKE transition transfers the existing capability to the caller. This is a
serial blocking leaf. Tokio scheduling/cancellation, glibc thread cancellation,
the complete prepare sequence, registries, and production activation are
separate qualifications.

Target: Linux x86_64, Rust 1.95.0 release behavior, Tokio 1.53.1's standard file
backend, GNU libc 2.43 primitives, pinned d3 HIA version 8. Every extent and
private capacity is u64. There is no public path-size or EINTR-retry quota.

## Entry and return

f0(readbuf request, mutbuf output, mutbuf workspace) -> u32

The three complete buffers are disjoint and initialized. One workspace belongs
to one CREATE or UNLINK invocation and its later DROP or TAKE lifecycle. The
input and unused output/workspace tails are unchanged.

| Return | Meaning |
|---:|---|
| 48 | A complete fixed 48-byte result was published |
| 0xfffffffd | PENDING: one private effect is issued or awaiting completion |
| 0xfffffffe | CAPACITY: private output or workspace storage is insufficient |
| 0xffffffff | INVALID: malformed request, lifecycle, state, or completion |

Every non-48 return leaves the complete output unchanged. INVALID and CAPACITY
also leave the complete workspace unchanged. A ready-zero RESUME leaves the
workspace unchanged and does not issue another effect. Issuing or consuming a
valid effect can change private state while returning PENDING.

The u32 success return is a fixed descriptor length, not a variable payload
extent. The descriptor contains its complete u64 extent. Raw path extents are
never narrowed to u32.

## Request

The exact request is a 64-byte header followed by N raw Unix path bytes. All
integer fields are little-endian u64.

| Offset | Meaning |
|---:|---|
| 0 | ASCII HSHCFQ01 |
| 8 | Entry operation: 1 START, 2 RESUME |
| 16 | File operation: 1 CREATE, 2 UNLINK, 3 DROP, 4 TAKE |
| 24 | Raw path length N |
| 32..63 | Four reserved zero words |
| 64 | N complete raw path bytes |

CREATE/UNLINK START require a fresh workspace whose word at zero differs from
HSHCFW01. A live or completed workspace cannot restart with another path; use
an independent arena. Each CREATE/UNLINK RESUME repeats exactly its original
file operation and path.

DROP/TAKE requests have N=0 and no payload. Their START requires this arena's
own successful CREATE capability to remain held. Their RESUME retains the
same file operation and empty payload. The bridge's mechanical continuation
changes only START to RESUME.

No request accepts a raw FD, PID, or caller-supplied token. Paths are not
decoded as UTF-8, normalized, or converted lossily. An empty path is passed
as an empty C string to the syscall, not treated as success.

## Result descriptor

| Offset | Meaning |
|---:|---|
| 0 | ASCII HSHCFR01 |
| 8 | Complete u64 extent, always 48 |
| 16 | Completed file operation, 1..4 |
| 24 | Result kind: 0 Ok, 1 raw OS error, 2 local NUL InvalidInput |
| 32 | Positive errno 1..4095 for kind 1; otherwise zero |
| 40 | Nonzero capability for successful CREATE/TAKE; otherwise zero |

Kind 2 is Rust's non-OS error
InvalidInput("file name contained an unexpected NUL byte").
It has no raw errno and must not be converted into EINVAL.

CREATE reports the capability identity while HIA still holds it. The caller
can observe the identity but does not yet have transfer authority. TAKE clears
HIA's held capability and transfers that same identity to the next owner. It
does not duplicate an FD or perform a syscall. This arena cannot DROP after
TAKE; the receiver owns subsequent resource management.

DROP commits the held capability to one pending close. It publishes Ok after
one actual close completion regardless of errno, and never retries. A completed
RESUME republishes the same descriptor without another effect or transfer.
Repeating a descriptor does not mint another capability.

A failed CREATE cannot DROP or TAKE. UNLINK has no held file and cannot DROP
or TAKE. After DROP, another DROP/TAKE START is INVALID.

## Workspace

Required capacity is 513 + original_N, checked for u64 addition overflow.
This same capacity remains required throughout DROP/TAKE, despite their empty
request payload. Extra workspace capacity is retained unchanged. Allocation or
transport failure is not a semantic io::Error.

| Offset | Meaning |
|---:|---|
| 0 | State magic HSHCFW01 |
| 8 | Current file operation 1..4 |
| 16 | Phase: 1 effect pending, 2 created and held, 3 completed |
| 24 | Last effect sequence, wrapping u64 |
| 32 | Original CREATE/UNLINK path length |
| 40 | Required capacity, 513 + original_N |
| 48 | HIA held capability, nonzero only in phase 2 |
| 56 | Capability committed to pending DROP; otherwise zero |
| 64 | Result kind |
| 72 | Result errno |
| 80 | Result capability identity |
| 88 | Original operation: CREATE=1 or UNLINK=2 |
| 96..127 | Reserved zero bytes |
| 128..223 | 96-byte private effect slot |
| 224..511 | Reserved zero bytes |
| 512 | Original raw path, followed by one NUL terminator |

Only a local-NUL result can retain embedded NUL bytes; it issues no effects.
CREATE/UNLINK RESUME compares its full path with the retained bytes.

Initial sequence is zero, first issue one. Increment wraps modulo 2^64 without
an artificial retry limit. Exactly-once dispatch belongs to the private
controller: ready-zero polling does not authorize dispatching a job twice.
Typed tests can exercise counter wrap without claiming 2^64 kernel calls.

## Fixed private effect slot

The slot starts at workspace offset 128.

| Relative offset | Meaning |
|---:|---|
| 0 | ASCII HSHCFFX1 |
| 8 | Current effect sequence |
| 16 | Action: 1 OPENAT, 2 UNLINK, 3 CLOSE |
| 24 | Argument 0 |
| 32 | Argument 1 |
| 40 | Argument 2 |
| 48 | Argument 3 |
| 56 | Ready flag: 0 issued, 1 complete |
| 64 | Exact signed 64-bit raw syscall result bits |
| 72 | Errno, zero or positive Linux error 1..4095 |
| 80 | Minted capability on successful OPENAT; otherwise zero |
| 88 | Reserved zero |

Only the four completion words at relative offsets 56..87 may be published by
the bridge, as one complete observation. All four are zero on issue. Every
other workspace byte belongs to HIA.

| Action | Arguments 0..3 | One fixed syscall |
|---:|---|---|
| 1 | 512, original_N, 524865 (0x80241), 438 (0666) | openat(AT_FDCWD=-100, owned C string, supplied flags, supplied mode), syscall 257 |
| 2 | 512, original_N, 0, 0 | unlink(owned C string), syscall 87 |
| 3 | Committed owned capability, 0, 0, 0 | close(mapped owned FD), syscall 3 |

Flags 0x80241 are O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC. GNU x86_64
O_LARGEFILE is zero. Kernel umask and filesystem behavior apply; the bridge
does not choose creation policy or change errors.

Successful OPENAT has a raw FD in 0..i32::MAX and a nonzero minted capability.
The raw FD is private evidence, not the public handle. Successful UNLINK/CLOSE
have raw result zero and capability zero. Failure has raw -errno and capability
zero. HIA checks the full slot, sequence, arguments, owned bounds, C string,
readiness, and result domains.

The bridge maps capabilities only to FDs it actually owns. A token is never
interpreted as a raw FD. Broken mapping is a private contract failure, not
permission to fabricate semantic EBADF. CLOSE consumes the mapping once,
regardless of its result. The bridge never retries or chooses lifecycle steps.

## Original behavior and limits

HIA forms the C string and rejects embedded NUL locally. CREATE emits the fixed
flags/mode, retries only OPENAT errno EINTR=4, and preserves every other error.
UNLINK makes one attempt, including EINTR. DROP ignores all close results and
does not retry EINTR.

Rust OwnedFd::drop contains a debug/library-UB validity check before libc close.
This release leaf's domain has that check inactive; actual original OS traces
must establish the profile behavior. No behavior is claimed for an externally
invalidated OwnedFd or an enabled IO-safety abort check. Typed close errors test
post-close return handling, not actual production of each error from a valid FD.

Tokio's standard File::create selects write/create/truncate OpenOptions and
uses asyncify around std open. remove_file uses asyncify around
std::fs::remove_file. into_std waits for in-flight operations and moves the
same file. This leaf owns blocking operations and explicit capability transfer;
it does not implement those async waits, task cancellation, JoinError handling,
or glibc thread-cancellation machinery.

A fixture can observe TAKE leaving its FD open and subsequent old-arena DROP
refusing with no close. Kernel process-exit cleanup of that transferred FD is
receiver cleanup, not HIA DROP or production composition.

Rust CString allocator-abort behavior is separate from private native capacity
refusal. Qualification of this leaf does not activate production, complete
capture prepare/registries, replace the runtime, or authorize old-stack removal.

## Exact helper reuse

Three complete functions from frozen shell_capture_path.hepta are retained:
f16 (read request u64), f17 (read workspace u64), f18 (write mutable u64).
Only function declaration IDs and call target IDs are relocated.
shell_capture_file_reuse.json retains complete original/new bodies and hashes.
There are no derived wrappers or partially copied helper bodies. The new
lifecycle, NUL handling, and syscall decisions are expressed in HIA.

## Pinned source identities

| Original | Git blob |
|---|---|
| Rust 1.95.0 library/std/src/fs.rs | cf6f9594c0027af9755a4518b1460a7db92a36ff |
| Rust 1.95.0 library/std/src/sys/fs/unix.rs | 7db474544f04abc75e2d66ec007ebe4799a491d3 |
| Rust 1.95.0 library/std/src/sys/fs/mod.rs | 0c297c5766b82a21ab31def05ccbb877a02a243b |
| Rust 1.95.0 library/std/src/os/fd/owned.rs | 8a39fe073bf95f9f7c216d354eecc818e325811c |
| Rust 1.95.0 library/std/src/sys/fd/unix.rs | bb6c0ac9e18e66c272dd8d132c23bbf0ce7cd2c4 |
| Rust 1.95.0 library/std/src/sys/helpers/small_c_string.rs | f54505a856e05cca952669988b47a88663607507 |
| Tokio tokio-1.53.1 tokio/src/fs/file.rs | 3829b609d4d5edf5f14780ad921ca06a3cf00375 |
| Tokio tokio-1.53.1 tokio/src/fs/open_options.rs | 99073a9d185cd97a12722b3aa6974d2b36491fcb |
| Tokio tokio-1.53.1 tokio/src/fs/remove_file.rs | 4018802547eeadb41c130f1fdb1920cb8a28bd8a |

Rust: https://github.com/rust-lang/rust/tree/1.95.0/library/std/src/
Tokio: https://github.com/tokio-rs/tokio/tree/tokio-1.53.1/tokio/src/fs/

GNU libc tag upstream/glibc-2.43 full sources were retrieved using format=TEXT
from https://android.googlesource.com/toolchain/glibc/+/refs/tags/upstream/glibc-2.43/

| Relative path | Bytes | SHA256 |
|---|---:|---|
| sysdeps/unix/sysv/linux/open64.c | 1792 | 5340aa674a446f71e94d22382179e2b42687096ba0fa842ebb37fdcc3abfe0bc |
| sysdeps/unix/sysv/linux/unlink.c | 1158 | 3680932674a246664df9cdcba7ee5d814bcee441c0299f0cadf0c7b00a5929fb |
| sysdeps/unix/sysv/linux/close.c | 1091 | eb96884c93506922ee82072032337a7b80888c8c75b1346b871c955477d43c5d |
| sysdeps/unix/sysv/linux/x86/bits/fcntl.h | 2246 | 385d7a9118790e783bb2c6273602faca25ffe71046606d1e3afbe19d5d67d4a8 |

Source observations do not substitute for actual kernel traces or original
comparison on the qualification host.

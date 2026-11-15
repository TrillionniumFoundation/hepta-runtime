# Capture file native Linux fixture

This executable contains the unchanged flat HIA capture-file owner and a fixed
Linux x86-64 syscall adapter. It is a private blocking-leaf qualification
fixture. It does not complete Tokio cancellation, full capture preparation,
registry publication, production activation, or old-stack retirement.

## Authority and original behavior

The owner chooses CREATE, UNLINK, DROP, TAKE, the C string, flags, mode, retry,
semantic result, and ownership transition. The adapter executes each issued
primitive once. It never interprets the published 48-byte HSHCFR01 result.

The admitted operations correspond to Rust 1.95.0 File::create,
std::fs::remove_file, and OwnedFd::drop on Linux x86-64 with GNU libc 2.43.
CREATE's flags are 0x80241 and mode is 0666. The actual syscall is
openat(AT_FDCWD, path, supplied_flags, supplied_mode), number 257. GNU x86-64
O_LARGEFILE is zero. Existing ordinary files are truncated and symlinks are
followed. The adapter adds neither O_EXCL nor O_NOFOLLOW to capture creation.
Only HIA retries OPENAT on EINTR. UNLINK uses syscall 87 once. CLOSE uses
syscall 3 once and HIA discards its error. NUL is the original local InvalidInput
domain, with no fabricated EINVAL syscall. Umask and filesystem errors are real
kernel behavior.

The precise Rust debug/library-UB descriptor check and glibc thread-cancellation
machinery are outside this blocking release profile. Actual original traces
must establish that the pinned release close path has no preliminary UB-check
fcntl. No invalid externally closed OwnedFd is admitted.

## Invocation and transport

```
shell-capture-file.elf --capture-file-fixture TRACE_DIRECTORY
```

The caller owns TRACE_DIRECTORY and the working directory. The fixture opens
the trace directory without following its final symlink and creates exclusive,
CLOEXEC, no-follow ordinary files `effects.bin` and `entries.bin`. Only audit
descriptors are normalized above 2. Successful CREATE's actual descriptor is
not duplicated or numerically changed.

The first stdout item is 64 bytes, eight little-endian u64 words:

| Word | Value |
|---:|---|
| 0 | ASCII HSCFRDY1 |
| 1 | Actual PID |
| 2 | Actual TID |
| 3 | Actual effects.bin FD |
| 4 | Actual entries.bin FD |
| 5 | Fixture protocol version 1 |
| 6..7 | Zero |

Each stdin item is an envelope `u64 request_len, u64 workspace_capacity`, then
the complete HSHCFQ01 request. The workspace is allocated on the first item and
persists unchanged between calls except for HIA operations and admitted effect
completion. Later items must state the same capacity. The fixture does not
choose an application quota. Capacity is a caller buffer extent, not a semantic
file error. Allocation/transport failure exits as infrastructure failure.

Input is reallocated to its exact current extent with sixteen-byte guards on
each side. Output capacity is 64. Workspace starts zeroed. Output starts 0xA7
for each external request. Guard pairs are input 0xC1/0xC2, output 0xA5/0xA6,
workspace 0x5A/0x5B. All guards are sixteen repetitions of the byte.

Each external request receives `u64 actual_return, u64 body_extent`, followed
by the result bytes. Extent is 48 exactly when the actual return is 48; for
INVALID or CAPACITY it is zero. The adapter does not inspect the result's
operation, kind, errno, or capability. PENDING is internal: dispatch one admitted
effect, publish the actual completion, mechanically change request op from
START to RESUME, and call the same owner again. The path and all other request
bytes remain unchanged.

EOF is accepted only at a complete envelope boundary. The fixture writes one
identical 128-byte footer to both audit files and stdout, then exits. A partial
envelope or body is an infrastructure error. Exit codes: 0 complete transport,
64 invalid command line, 74 infrastructure error, 78 private contract failure.
A complete semantic file error still has exit code zero.

## Owned capability mapping

An OPENAT success has an actual nonnegative i32 FD. The adapter creates a
private token mapping only for that descriptor. Tokens are nonzero monotonically
minted identities; they are never interpreted as raw FDs. Mapping allocation
failure is infrastructure failure, not an invented open errno. The fixture has
no caller-provided raw FD or token input. CLOSE looks up the token issued by HIA
and rejects an absent or consumed mapping before invoking any kernel call.
It consumes a mapping once even if CLOSE returns an error.

CREATE's published capability remains held by HIA. TAKE is a HIA transition
with no syscall; it clears the owner and transfers the same identity. The
fixture consumer retains physical custody of that already-created descriptor
until its process exits. A later old-arena DROP must be refused by HIA without
issuing CLOSE. Kernel cleanup of a transferred descriptor on fixture exit is
receiver cleanup; it is not HIA DROP and not proof of production composition.

No bridge branch examines operation/result kind to select CREATE, DROP, TAKE,
UNLINK or error precedence. The only syscall selection is the action number in
the HIA-issued fixed capability slot. The adapter writes only slot completion
words at workspace offsets 184..215 (slot-relative 56..87), with ready published
last. It does not write policy state.

## Complete effect records

Every issued/completed effect has a 128-byte header followed by the complete
96-byte HSHCFFX1 slot and exactly `path_len` raw borrowed path bytes. Header
fields are sixteen little-endian u64 words:

| Word | Value |
|---:|---|
| 0 | ASCII HSCFTR01 |
| 1 | External request index, starting at 1 |
| 2 | Native entry index that issued the effect |
| 3 | HIA effect sequence |
| 4..5 | Actual PID and TID |
| 6 | Phase: 0 issue, 1 completion |
| 7 | Actual syscall number 257, 87, or 3 |
| 8 | OPENAT dirfd=-100; CLOSE actual owned FD; UNLINK zero |
| 9..10 | Actual OPENAT flags and mode; otherwise zero |
| 11 | Actual raw syscall result bits; zero on issue |
| 12 | Positive errno or zero; zero on issue |
| 13 | Minted capability on successful OPENAT; otherwise zero |
| 14 | Complete raw borrowed path length; zero for CLOSE |
| 15 | Zero |

No errno is injected. File-operation EINTR is not forced. Typed state cases
qualify retry and ignored-close-error decisions separately from real kernel
observations. Additional audit/transport/memory syscalls are fixture operations,
not evidence that the original std file call made those operations.

## Complete native entry records

Before and after every actual call, entries.bin retains a 128-byte header, then
the complete input, output and workspace allocations, each including both
guards. Header fields are:

| Word | Value |
|---:|---|
| 0 | ASCII HSCFEN01 |
| 1..2 | External request index and native entry index |
| 3 | Phase: 0 before, 1 after |
| 4..5 | Actual PID and TID |
| 6..8 | Input extent, output capacity 64, workspace capacity |
| 9 | Actual return after call; zero before |
| 10 | Actual CLOCK_MONOTONIC nanoseconds |
| 11..12 | Cumulative issued and completed effect counts |
| 13..15 | Minted, consumed and physically live capability counts |

The independent reader checks input immutability within each call, complete
refusal nonmutation, output-tail preservation, every guard, every between-call
completion write, exact START-to-RESUME request change, lifecycle state,
canonical path borrow, and complete kernel-effect/result causality. It does
not load a native image or execute a producer while reading historical evidence.

## Footer

The exact 128-byte HSCFAUD1 footer has sixteen words:

```
magic, pid, requests, entries, issues, completions, minted, consumed,
physically_live, transport_error, contract_error, last_return,
workspace_capacity, effects_fd, entries_fd, reserved_zero
```

Success requires all three footer copies identical, counts reconstructed from
raw records, no transport/contract error, and owned-FD observations consistent
with the exact explicit request sequence. Physical custody after TAKE is
retained and observed; no unrequested semantic close is inferred from exit.

## ELF packer and source binding

The flat HIA packer request is ASCII HSCFPK01, u64 nonzero image length, then
the exact unchanged capture-file owner image. It writes a canonical 176-byte
ELF64 executable header (RX PT_LOAD and RW GNU_STACK), the fixed adapter bytes,
and the exact HIA image. Entry is 0x4000B0, base 0x400000. The adapter ends on a
sixteen-byte zero alignment boundary. Its one-byte local sentinel is removed
and replaced by the first owner image byte; it is never a runtime fallback.

`shell_capture_file_layout.json` binds source SHA, actual assembler .text SHA,
text length, entry offset zero, empty relocation inventory, header size, image
offset and base. Only actual as/objcopy produce the adapter object/raw prefix.
The final executable is produced by actual HIA packer calls with complete
before/after guarded arrays and refusal controls. It has no loader, shared
library, Python, Rust or interpreter dependency.

## Fixture retirement and scope

The OS producer owns all tested targets. It retains exact raw path bytes,
before/after object types, device/inode/mode/UID/GID/link counts and complete
ordinary-file payload or symlink target, plus actual PID/starttime, descriptor
link/stat/fdinfo and syscall/entry bytes. After validation it retires only the
explicit known owned objects with fresh identity/type checks. Evidence contains
only ordinary files and directories. It neither follows fixture symlinks during
retirement nor changes permissions to erase an unknown object.

Named physical tamper tests preserve complete changed bytes and actual reader
process receipts, reconstruct each exact mutation recipe, and restore the
complete positive baseline. The final read-only audit blocks process launch,
FFI, filesystem writes, signals, network access and live /proc reads. These
qualification mechanisms do not grant production or deletion authority.

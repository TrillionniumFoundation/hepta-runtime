# Descriptor-relative retained Record IO

`request_record_io.hepta` owns the existing `read_record`,
`cleanup_target_staging`, `cleanup_staging`, and `save_inner` decisions. Its
caller supplies a directory descriptor whose authority and namespace binding
have already been established. The static qualification executable opens one
explicit directory with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and retains that
descriptor across its framed requests. Ancestor traversal, archive anchors,
audit authorization, per-request locking, intent descriptor retention, and
public dispatch remain separate caller responsibilities.

The four embedded HIA images are the IO owner, Record validator, typed storage
JSON, and binary codec. The codec performs real Base64 and SHA256 work. The
fixed Linux x86-64 adapter translates the owner's checked descriptor actions
into syscalls. No Rust, Python, libc, dynamic linker, or interpreter is needed
to run the resulting executable. Qualification and authoring scripts are
development tools.

## Request and response

All words are little-endian `u64`. The private borrowed ABI reserves
`0xffffffff` for invalid input, `0xfffffffe` for capacity, and `0xfffffff0` for
a pending action. Input is at most 1 MiB, output at most 256 KiB, and the owner
requires 8 MiB of workspace. The static executable accepts exactly one
directory argument, reads a `u64` frame length followed by the frame, and
writes a `u32` return code followed by the returned bytes when the code is a
normal length. It supports multiple requests in one process with persistent
action sequence numbers and separate child state.

| Request offset | Meaning |
| --- | --- |
| 0 | `HRRFQ001` |
| 8 | Operation: 1 read, 2 save new, 3 replace, 4 cleanup target staging |
| 16 | Filename length, exactly 69 |
| 24 | JSON byte length |
| 32, 40 | Zero |
| 48 | 64 lowercase hexadecimal digits followed by `.json` |
| 117 | JSON bytes, present only for operations 2 and 3 |

Save requests carry at most 98,304 JSON bytes and must pass the actual Record
validator before any filesystem operation. This is the private caller's
valid-Record precondition: a failed new Record validation returns the private
invalid code. The next request may then proceed. The owner serializes valid
typed Records using the existing field order; maps, sequences, reordered keys,
escaped field names, and omitted optional values that decode to the same typed
Record produce the same persisted bytes.

| Response offset | Meaning |
| --- | --- |
| 0 | `HRRFO001` |
| 8 | Diagnostic class |
| 16 | Raw OS errno for class 23; otherwise zero |
| 24 | Result bytes following the 48-byte header |
| 32, 40 | Zero |
| 48 | For successful reads, the complete `HRRCV001` validator response |

Diagnostic 0 is success. Classes 1 through 8 retain the Record validator's
filename, typed decode, identity, missing Base64, Base64 data, length/digest,
nonstored payload, and size refusals. Additional classes are 16 directory
metadata, 17 Record inode metadata, 18 staging inode metadata, 19 staging
hard-link binding, 20 replacement binding, 21 completed Record immutability,
22 Record size, 23 OS error, and 24 write-zero. Exact serde error prose and
source positions are not represented by this private ABI.

## Descriptor actions and state

The pending action is 96 bytes at workspace offset 256. Its words are magic
`HRFSA001`, sequence, kind, slot, span, count, argument, capacity,
acknowledgement, result, errno, and zero. The adapter acknowledges the exact
sequence. The owner checks the immutable action fields and retained request
bytes before resuming. Child calls also retain and verify their input bytes.
The sequence cannot wrap. Private malformed input and capacity failures do
not publish partial response bytes.

| Kind | Effect |
| --- | --- |
| 1 | `fstat` and effective UID into the fixed metadata span |
| 2 | Descriptor-relative open into owned slot 1 or 2 |
| 3 | Read into the fixed retained Record buffer |
| 4 | Write the remaining canonical Record bytes |
| 5 | Synchronize the directory or owned file |
| 6 | Publish a new Record with `linkat` |
| 7 | Replace with `renameat` |
| 8 | Remove the exact target staging name with `unlinkat` |
| 9 | Close an owned file slot once |
| 100 | Call the pinned native Record validator |

Slot 0 is the caller's directory. Slots 1 and 2 are held only while the
corresponding original `File` is alive. The adapter checks role, fixed spans,
mode and flags, and the filename/staging-name binding before issuing effects.
The deterministic staging name is `.<id>-<id>.tmp`. Cleanup opens and drops
the existence probe, then reopens the staging file as the original does.
A two-link staging file is removed only when the published name resolves to
the same device/inode. Three or more links are refused.

Save first checks directory metadata and performs target staging cleanup.
Replacing also reads and verifies the current Record, retaining the original
owner, tool, acceptance timestamp, and policy binding. A completed Record is
immutable except for an identical typed replacement. New staging is created
exclusively with mode 0600 and validated before entering the persistence
closure. The write loop handles `EINTR`, actual short writes, and write-zero.
File and directory synchronization retry `EINTR`. Other original operations
preserve their observed error behavior. File closure precedes publication and
best-effort failure cleanup. Validation outside the original persistence
closure leaves the invalid staging inode in place. Publication followed by a
directory-sync failure returns an error even when the final name exists.

## Executed qualification

On ai395, Rust 1.95.0 compiled the 22 exact original source blocks against
22 original-version locked packages. Every package archive checksum and all
1,131 packaged source files were checked against the installed sources before
and after the run. Five HIA images were freshly compiled, including the HIA
ELF packer. The executable is 440,410 bytes with SHA256
`e300724ea5d8078eeeb639afcbfb54d74c45326c4cd5f7c7798ede411835b106`.

The final v4 run executed 239 baseline cases with 577 requests and 239
processes per implementation. It compared complete response bytes and actual
filesystem contents, modes, owners, hard links, symlinks, and inode changes.
Initial inodes stayed pinned with `O_PATH` descriptors during the comparison,
so immediate inode-number reuse could not masquerade as preserved identity.

The same fresh executable pair then ran 40 kernel-fault cases, with 89 entered
requests and 43 processes per implementation. Three requests per implementation
were deliberately killed before completion; their subsequent recovery requests
were executed in fresh processes. Four short-write cases used actual
`RLIMIT_FSIZE` behavior with limits of 1, 7, 31, and 127 bytes and verified the
written prefix before the following `EFBIG`. Other cases covered `EIO`,
`EINTR`, write-zero, growth after metadata inspection, replacement of a path
while its original inode remained open, competing target/staging names, and
death before write, link, and unlink. Complete output and observed filesystem
state matched in every final case.

The unprivileged test observer continues ordinary effects in the kernel; it
does not implement storage semantics. When killing its own child before an
effect, it withholds the pending syscall continuation until the child is
reaped. The earlier v3 observer incorrectly continued that syscall after
signaling death, creating a scheduling race; the full failed evidence remains
preserved. The first v1 original-fixture build failure and v2 successful
baseline are also retained. No close-error behavior or general future
cancellation is inferred from these tests.

The complete v1–v4 evidence archive is 3,574,144 bytes, SHA256
`460aca783af7fc150da041b54b3c3d409d41df40643d101e4941ea3eeba5a140`.
All 8,342 archive members were verified remotely and again after retrieval.
Nonregular filesystem objects are represented by metadata, never recreated
as archive symlinks or special files. Eighteen unreadable, zero-length fixture
files are explicitly identified as stable empty extents established by
`lstat`; the record does not claim their content was read.

This qualification establishes the stated descriptor-relative Record
operations in the exercised domain. Whole-runtime replacement, production
activation, old-stack removal, archive anchoring, audit storage, and public
request dispatch remain unqualified.

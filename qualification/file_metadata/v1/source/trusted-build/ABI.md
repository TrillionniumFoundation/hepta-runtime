# Borrowed file descriptor metadata owner

This is an authoring candidate, with no native execution or original comparison yet.
The target is the complete Linux branch of the frozen Python file_metadata.py.
The HIA owner contains every state transition, comparison, ordering decision,
retry decision, xattr ordering, exception selection and summary construction.
The native capability pump will only move complete buffers and execute the
requested descriptor syscall or the actual binary_codec HIA child.

## Packet and completion

All scalars are little-endian u64 unless stated. Entry is
f0(readbuf, mutbuf, mutbuf) -> u32; 0xffffffff is invalid protocol,
0xfffffffe is a response capacity below 64. Successful calls return 64,
with the actual response payload extent in header word 56.

HMDTQ001 has a 96-byte header:
command at 8 (1 start / 2 resume), sequence at 16, mode or signed syscall
result at 24, borrowed source FD at 32, borrowed target FD at 40,
owned-snapshot length at 48, zero words at 56/64/72/80, payload extent at 88.
Start modes are 1 capture, 2 summary of a previously owned Linux snapshot,
3 preserve. Start sequence is zero. Mode 2 has both FDs zero; mode 1 has
target zero. Modes 1 and 3 have no payload. Mode 2 payload is HMTSS001.
FDs are injected by the private callable from its externally bound capability
registers after the packet's two FD fields have been checked to be zero.
This envelope confers no public FD authority. The eventual native gate must
never duplicate, reopen or close either borrowed FD.

Resume is the outstanding sequence, signed syscall result or child byte
count at 24, zero words 32 through 80 and exact reply bytes. A negative
result has no payload; replies are at most 65536 bytes. A repeated resume
following output growth must match the complete accepted reply byte for
byte. There is exactly one outstanding request.

HMDSR001 has a 64-byte header: kind 8, sequence 16, operation 24,
arguments a/b/c at 32/40/48, payload extent 56.
Kind 0 is completion; operation is the start mode. Capture returns HMTSS001.
Summary and preserve return compact ASCII JSON of the original summary value.
Kind 1 requests a syscall, kind 2 requests the actual codec HIA child.
Kind 3 is a structured target exception; kind 4 requests workspace capacity;
kind 5 requests output capacity. Growth size is at 32. Summary start requests
at least 65624 output bytes before touching workspace or issuing a child.
Subsequent growth leaves the already accepted request and result intact.

Syscall requests: 1 fstat(a), 2 flistxattr(a, capacity=b),
3 fgetxattr(a, NUL name payload, capacity=b), 4 fchown(a,b,c),
5 fchmod(a,b), 6 fremovexattr(a, NUL name payload),
7 fsetxattr(a, name-length=b, value-length=c, name+NUL+value payload, flags=0),
8 fsync(a). A successful fstat reply is the full 144-byte x86_64 Linux stat;
list/get reply result equals payload length; other success replies are zero.
The pump must reject a write syscall unless mode 3 owns target permission
and a is exactly the borrowed target; read operations accept only the
bound source/target. It must not synthesize business errors or retry syscalls.
The HIA owner retries EINTR for fstat, fchown, fchmod, fsync. It retries only
ERANGE for xattrs, following CPython's 256/65536 list and 128/65536 get buffers.

Child operation 1 is the actual qualified binary_codec HIA op2, with full
HRCODEC1 payload. Its 64 lowercase SHA-256 bytes are validated. No Python or
native replacement for hashing is part of the implementation.

Exception kind 3: class at 24, errno at 32, literal message byte length at 40,
filename kind at 48 (0 absent / 2 borrowed integer FD). Payload is the
literal ValueError string followed, when present, by the integer FD as 8 bytes.
OS strerror formatting belongs to the outer established diagnostic owner.
Classes follow the existing binary owner: ValueError=1, PermissionError=2,
OSError=3, FileNotFound=4, NotADirectory=5, IsADirectory=6, FileExists=7,
Interrupted=8, BlockingIO=9, BrokenPipe=10, Timeout=11, ConnectionReset=12,
ConnectionAborted=13, ConnectionRefused=14. Xattr errors retain the integer
FD filename; fstat/chown/chmod/fsync errors have no filename.

## Owned snapshot

HMTSS001 is a private Linux capture representation, not a public wire schema.
Header 128 bytes: version 1 at 8; uid/gid/mode/nlink/flags at 16/24/32/40/48;
distinct attribute count at 56; complete listed-name bytes at 64;
total distinct value bytes at 72; extent at 80; ACL kind zero (None) at 88;
record/name/value bases 128/8320/73856 at 96/104/112; reserved 120 zero.
There are at most 256 records of 32 bytes: relative name offset, name length,
relative value offset, value length. Names preserve kernel list order and
NUL separators; repeated names update the value without changing dictionary
insertion order. Values total at most 4194304 bytes and each at most 65536,
as admitted by the actual Linux getxattr interface. Capture checks the
distinct count and total only after each successful get, as the target does.
Summary validates all record ranges before checking dictionary uniqueness.

The workspace has an 8192-byte control header; each snapshot arena is
4268160 bytes. Capture/summary use one arena; preserve uses three.
Scratch is sized from the frozen layout. Initialization zeros only the
control header and the used snapshot header/name regions, not all value arenas.
Every transferred reply, snapshot, output and child buffer must be retained
in subsequent actual qualification, including seeded and capacity paths.

## Target order and limits of this source checkpoint

Capture: fstat, regular-file check, list/get every xattr, Linux ACL None,
fstat, compare dev/ino/size/mtime_ns/ctime_ns. Summary sorts names by Python
Unicode scalar order with UTF-8 surrogateescape; hash dictionary order
remains the original insertion order.

Preserve: capture source; reject nlink != 1, special mode/flags, capability;
fstat target; conditional fchown; fchmod; list/remove extras in actual list
order; stable ACL-last source insertion order; capture target and verify
uid/gid/mode/xattrs/ACL in that order; capture source and compare the entire
snapshot; fsync target; return the original source summary.
Neither target content nor source/target timestamps are copied.

This source contains the Linux path only. Darwin, Python memory allocation
failures and asynchronous Python signal-handler behavior are not qualified.
The v3.12.3 CPython source is pinned study evidence; the actual reference
interpreter, FS encoding and OS must be recorded and compared in the later
real filesystem domain. The root's borrowed-parent capability is separately
closed at 3703e980; this owner will receive the already-open borrowed file FD.

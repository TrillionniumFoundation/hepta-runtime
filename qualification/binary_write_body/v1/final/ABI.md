# Qualified locked borrowed-parent binary write owner

The immutable 43-function HIA implementation and mechanical callable were compiled
in CI and compared with the actual locked CPython implementation on 101 input
cases, 103 semantic invocations per implementation, in 202 isolated processes.
The 35 complete uploaded capture archives were then independently restored and
read without executing either application again. All 101 comparisons passed.
This is a private borrowed-parent component, pending public caller integration.

## Scope and effect ordering

The trusted graph supplies one held parent directory FD and a basename. Parent
path authorization/acquisition and the original outer parent close belong to the
caller. This owner neither duplicates nor closes its borrowed parent. It owns the
lock/current/temp descriptors it actually opens, and receives the graph's one
process-wide orphan pool and serialized process-wide entropy context.

The owner executes SHA256(name UTF-8), opens the private .hepta-lock- sidecar,
constructs the original append-mode FileIO/BufferedWriter/TextIOWrapper behavior,
takes LOCK_EX, checks expected destination version, strictly decodes Base64,
applies the decoded 1 MiB bound, gets one UUID4, creates a private exclusive temp,
writes every byte with partial-write/EINTR handling, fsyncs and closes the temp,
invokes the qualified publish_at owner, invokes read67 fingerprint mode 2, then
unlinks the temp and closes the lock. Result JSON contains written plus the
actual fingerprint object's fields. Child values are never supplied by a fixture
expectation. Success does not require the destination to retain the just-written
bytes against a writer outside this cooperative lock; the original fingerprint
behavior and race windows are preserved.

The temporary cleanup try begins only after UUID generation succeeds. Any error
after that point, including failed exclusive temp open, still attempts unlink.
Only ENOENT is suppressed at that unlink. Temp close, cleanup unlink and lock
close can replace a preceding error in that order. The borrowed parent's later
close can replace this result in the outer caller. There is no explicit flock
unlock; consuming the actual lock FD releases its kernel lock.

## Original append-wrapper details

regular opens use O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC. Current opens are read-only;
lock opens additionally O_RDWR|O_CREAT, temp O_WRONLY|O_CREAT|O_EXCL; all use 0600.
regular retries EINTR for open/fstat. A non-EINTR first-fstat failure happens
before the caller assignment and transfers the actual FD into the unchanged
append-only process-lifetime pool without close/dup. Invalid file type or
private uid/link-count/permission validation closes once before raising; that
close's error replaces the ValueError.

The lock's os.fdopen(existing_fd, 'a') does not set O_APPEND on the supplied FD.
Its FileIO constructor performs a single fstat, rejects EBADF and directory
type (whose exception filename is the integer FD), and otherwise tolerates a
fstat error. It performs a single lseek(SEEK_END), tolerates ESPIPE while caching
nonseekability, and leaves the supplied FD unclosed if FileIO initialization
fails. Such failures transfer that descriptor to the same pool. Subsequent
isatty/TCGETS and BufferedWriter initial tell errors are ignored. A cached
seekable file reaches TextIOWrapper's tell; failure there closes the wrapper.
The lock contains no buffered writes. flock retries EINTR. Close is single-call
and consumes ownership even on an error.

## Request and response

f0(readbuf, mutbuf output, mutbuf work) returns u32. Invalid protocol returns
0xffffffff; output below the 64-byte response header returns 0xfffffffe.
Normal responses return 64, with complete payload extent at response word 56.

HBWTQ001 has a 96-byte header, with little-endian u64 words:

| Offset | Start command 1 |
| --- | --- |
| 0 | HBWTQ001 |
| 8 | 1 |
| 16 | 0 |
| 24 | mode 1 |
| 32 | trusted borrowed parent, 0..INT_MAX |
| 40 | basename byte length |
| 48 | prior-version byte length |
| 56 | Base64 string byte length |
| 64 | prior present: 0 or 1 |
| 72, 80 | 0 |
| 88 | total payload length |

Payload is basename, prior, Base64. All are valid UTF-8. Basename has no slash;
embedded NUL is preserved until its actual original open boundary. Absent prior
has zero prior length. The native exported invocation requires packet word32=0
and injects only the graph's parent register. The prior is checked after taking
the lock, before Base64 decoding. No decoding or UUID generation precedes it.

Resume command2 has sequence16, raw signed syscall result or complete child
extent24, zero32..80, and full reply payload88. A negative syscall return is in
-4095..-1 and has no payload. There is one outstanding request. Repeating an
accepted resume for output growth must reproduce sequence, result and every
saved payload byte; the separate child request arena cannot overwrite it.

HBWTR001 is 64 bytes: magic, kind, sequence, operation, a, b, c, payload length.
Kinds0/3 are final JSON/complete nested structured exception. Kinds4/5 request
work/output capacity with required extent32 and other nonmagic/type words zero.
Kind1 selects a fixed effect, kind2 a fixed child. Final unused fields are zero.
A new start is admitted only when idle or terminal; the native output loan must
also have been released. Every complete work/output/input extent is observable.

## Fixed effect capabilities

| op | Authority and arguments | Effect |
| --- | --- | --- |
| 1 | borrowed parent, basename + NUL | openat read-only, flags657408 |
| 2 | actual owned FD | single fstat, full144-byte Linux x86-64 stat |
| 3 | actual owned FD | close once; consume ownership even on error |
| 4 | actual owned FD | process-orphan append; retire token only after ACK0 |
| 5 | no caller-selected argument | geteuid |
| 6 | borrowed parent, exact lock name + NUL | openat RDWR/CREAT, flags657474 |
| 7 | borrowed parent, exact temp name + NUL | openat WRONLY/CREAT/EXCL, flags657601 |
| 8 | actual lock FD, b=1 CUR or2 END | lseek(fd,0,whence), one call |
| 9 | actual lock FD | isatty-equivalent TCGETS, ignored errno |
| 10 | actual lock FD | flock LOCK_EX |
| 11 | actual temp FD, b=count, exact payload | write every requested byte |
| 12 | actual temp FD | fsync |
| 13 | same borrowed parent, exact temp name + NUL | unlinkat flags0 |

No supplied number authorizes an arbitrary FD. The native boundary must verify
the current real ownership token and fixed operation arguments. geteuid private
validation, retry decisions, errors, child selection and all cleanup order remain
in HIA. No native response may stand in for a requested kernel operation.

## Fixed children

| op | Input and authority | Output |
| --- | --- | --- |
| 1 | 72-byte HSTVER01 actual saved stat | complete version bytes, <=122 |
| 2 | HRCODEC1 cmd2/reserved0 plus basename | 64 lowercase SHA256 bytes |
| 3 | HRCODEC1 cmd4/reserved0 plus Base64 UTF-8 | full HBRDS001, including new Error class15 |
| 4 | HENTQ001 cmd1/mode2 | full HENTR001, UUID hex or nested error |
| 5 | HPUBQ001 cmd1/mode1/name/temp/prior | same parent, full HPUBR001 |
| 6 | HBRDFD01 cmd1/mode2 plus basename | same parent, full read67 HBRDS001 fingerprint |

Children1..3 are unchanged HIA leaves. Child4 uses the single serialized entropy
context for the entire process, retaining getrandom availability/cache state.
Children5/6 use private owned contexts with the same process orphan pool. Every
nested result is copied before its borrow is released. No file_info metadata
inspection is inserted after publication. Error formatting uses the qualified
34-function formatter and preserves HBRDS001/HMDSR001/HOSER001, including literal
classes15/16/17 and integer-FD filenames.

## Arena layout and caller integration obligations

Work has at least8192 fixed bytes. 512 lock name, 640 temp name, 768 stat and
4096 final JSON precede the basename at8192. Dynamic arenas hold prior, Base64
with its24-byte request prefix, decoded bytes, nested error, child request and
saved reply. Saved reply capacity is max(name+Base64+1024,2097152). Whole required
capacity is checked before initialization; all extents remain below4294901760.

The frozen Linux x86-64/CPython3.12.3 comparison includes empty, 1 MiB and over-bound
writes; Base64 errors and destination-error precedence; files, sidecars and real
filesystem changes at effect boundaries; complete metadata, staged publication
and post-publication fingerprints; actual kernel errno injection and RLIMIT
partial writes; FD 0 and closed parents; two contexts sharing process entropy;
append-only orphan retention, live pre-exit descriptor inspection and all cleanup
error precedence. It retains 17,064,539,195 full journal buffer bytes and
382,933,630 kernel trace bytes. All 3,679 journaled HIA owner, leaf and formatter calls were read, with 2,312
observed native effect requests bound to their actual kernel returns. Six cases
intentionally disable observer journals, while retaining real context, result,
filesystem, full kernel trace and process-lifetime evidence.

The immutable original source failure (builtin binascii had no __file__) preceded
all applications. The initial pure reader failed three completed captures because
fcntl F_DUPFD_CLOEXEC was missing from its pipe-relocation recognition and one
self /proc/PID path was not normalized. Both historical failures are retained.
Only the read logic changed; no production byte or completed application changed.
The corrected independent reading passed all 101 cases with 385 read-only guards.
Eight physical evidence corruptions were refused and two complete relocations
admitted; independent reading consumed their retained outcomes without replay.

Parent path authorization and final parent close, typed requests and responses,
real cooperative-lock contention with async cancellation, Remote/SSH transport,
namespace/cache updates and default public routing must be established by the
owning caller. These are not claimed by this private component. Read HANDOFF.json
and INSTALL.json for exact production bytes and complete evidence bindings.

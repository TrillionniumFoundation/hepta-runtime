# Binary write fixed native composition

The qualified fixed composition has nine runtime images: write, metadata, codec, stat,
literal-error34, publication, read67, strict Base64 decode and process entropy.
Every shared HIA/native dependency is byte-identical to its qualified source.
The locked write controller and its mechanical boundary are new production
components. The private carrier is qualification-only and is excluded from the
production installation. Actual application and independent archive results are
bound in HANDOFF.json.

## Exports and lifetime

binary_write_body_create(callback, callback_context, process_orphans_pool,
process_entropy_context) creates one guarded write context, one read67 context
and one publish_at context (which owns its unchanged metadata context).
The graph supplies one HPORP001 pool and one serialized HENTCI01 entropy context
for this OS process. Create verifies both identities and creator PID; null,
foreign-pool and non-idle entropy contexts are refused. It never creates or
destroys an entropy context or pool. The shared entropy context stays live across
write context release/destroy and across all writes.

binary_write_body_invoke(ctx, borrowed_parent_fd, HBWTQ001, length) admits an idle
context, nonnegative int parent and external zero FD word. It copies the request
and injects that exact parent. Creator PID and all child idle states are checked
before work begins. The graph serializes shared entropy use. No raw numeric FD
in a public input grants authority. On return64, ctx+104 points at HBWTR001 and
ctx+168 is its full extent. State2 holds a loan until binary_write_body_release.
Destroy rejects active or borrowed contexts; failed private states can be torn
down without closing the borrowed parent, orphan records or shared entropy.

Only actual openat results enter the eight-slot native ledger. Each slot also
records current/lock/temp role, and fixed capabilities restrict lseek/isatty/flock
to the lock and write/fsync to the temp. Open/unlink payloads must match the
HIA-owned basename or exact sidecar name. Single close consumes its token even
on error. ORPHAN_OWNED appends the real FD/context/generation before retiring
the operable token, and never closes or duplicates it.

## Memory and direct children

The 4096-byte context and every RW arena have a trailing inaccessible page.
Common offsets retain the established pump layout: entry16/stat24, callback40/
opaque48, state56, input64/72/80, work88/96, output104/112, resume120/128,
direct-child aliases136/144, loan168, last return176, owned count184, generation192,
current input200/208, sequence216/op224/result232/payload240, HIA count248,
FD slots256..319, direct entry320/output extent328/work extent336, parent344/
active352, nested context360/type368, pool376, read child384, publish child392,
orphan transfer count400. Shared entropy is408, codec entry416, decoder entry424,
direct-output pair448/456, direct-work pair464/472, creator PID480 and eight
parallel FD-role words512..575.

The existing fixed bridge resource profile remains input/output128MiB and
work256MiB. Allocation exhaustion or private protocol failure returns a private
resource/invalid result and does not impersonate an original Python exception.
These resource bounds are distinct from the HIA decoded-write bound of1MiB.

Direct children use actual immutable HIA entry bindings. Stat gets output128/
work256; SHA256 gets output64/work1184. Strict decode gets at least512 output
bytes, otherwise its full input extent plus64 rounded to eight bytes, and work4096.
These are complete supplied spans, with full before/after journals. Child results
are copied unchanged into the actual resume packet. Opaque entropy/publish/read
children own their own full journals; their complete output and4096-byte context
are captured before explicit release. No native code chooses decoding results,
UUID bytes, expected-version equality, metadata policy, JSON fields or errors.

## Fixed kernel operations

The bridge performs openat257, fstat5, close3, geteuid107, lseek8, ioctl16 with
TCGETS0x5401, flock73 with LOCK_EX2, write1, fsync74 and unlinkat263 flags0.
HIA controls retry and cleanup. A successful TCGETS returns all36 Linux kernel
termios bytes; an error returns no payload. Other than mmap/mprotect/munmap,
creator getpid and the shared pool primitive, no extra target operation is added.
Nested qualified pumps retain their unchanged fixed syscall capabilities.

## Private qualification carrier

HBWTFQ01 has a little-endian length prefix followed by64-byte header: operation8,
context slot16 (0/1), payload length24 and zero32..56. HBWTFR01 returns result8,
payload extent16, state24, generation32, owned count40, output capacity48 and work
capacity56, then all payload bytes. Parent slots encode FD+1 so FD0 is ordinary.

| Operation | Meaning |
| --- | --- |
| 1 | invoke current or automatically created observed write context |
| 2 / 3 | release / destroy selected write context |
| 4 / 5 / 6 / 7 | complete context / work / output / input arena |
| 8 / 9 | create observed / unobserved write context |
| 10 / 12 | fixture open / close its held parent |
| 11 | full HOPSN001 pool and every complete record page |
| 13 | actual error34 entry on unchanged nested final exception |
| 14 | actual fstat of still-held parent |
| 15 | HBWTCX01 plus complete read/publish/metadata/entropy contexts |
| 16 | close parent while retaining numeric slot for private failures |
| 17 | move only carrier pipe from FD0; never duplicate a target FD |
| 18 | install one to four ordered real-kernel fault plans |
| 19 / 20 | actual unowned orphan refusal / actual foreign-PID pool refusal |
| 21 / 22 | complete process entropy context / workspace |
| 23 | arm a live pre-exit custody witness after writer/parent cleanup |
| 24 | set actual RLIMIT_FSIZE (payload u64 <=1MiB) |
| 25 / 26 | actual null-pool / null-entropy constructor refusal |

The one entropy context uses a fixed observer gate for the currently invoked
writer. Turning observation off does not recreate or reset the context, pool,
cache or sticky getrandom selection. The carrier installs SIG_IGN for SIGPIPE and
SIGXFSZ to match the reference CPython process; application qualification must
verify that reference runtime profile before any application call.

Five complete128-byte journal families identify write/publish/read/entropy/
metadata contexts: HBWTJR01, HPUBJR01, HBRDJR01, HENTJR01 and HMDTJR01. Each actual
kernel effect has its corresponding HK01 notification, all arguments and a
required zero-only external ACK. Actors can perform frozen real filesystem
changes at these boundaries; they cannot substitute replies. HBWTER01 retains
every actual formatter input/work/output span and return.

Operation18 payload is N*56 bytes (1..4), each seven u64 values:
owner(1 write,2 publish,3 read,4 entropy,5 metadata), HIA response phase, fixed
capability op, matching ordinal, real syscall number, errno1..4095, match-FD0/1.
At the exact observed request the carrier installs a Linux seccomp errno filter.
When match-FD is1, the filter matches the real first FD argument. Syscall5 also
matches newfstatat262 for the reference libc's fstat family. Plans remain ordered,
are consumed once, and all installed filters remain active until process exit.
This is an observed-fixture fault mechanism, not an application response stub.
Observer-disabled real RLIMIT faults are independent of this mechanism.

An armed HBWTEOF1 witness reports pool count/pages and full entropy generation/
workspace-magic/cache-word/owned/orphan counts after actual writer destruction
and parent cleanup, before OS exit. The harness can inspect live /proc FD state
before its final zero ACK. Pool records, leaked descriptors and entropy cache
survive that cleanup and are reclaimed by OS process exit.

These protocols are private qualification surfaces. Parent/path authorization,
typed public input, Remote/SSH transport, Scope/cache effects, async lifetime and
public/default routing remain separate integrations.

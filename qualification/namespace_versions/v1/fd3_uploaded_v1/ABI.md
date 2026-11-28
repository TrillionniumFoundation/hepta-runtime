# Namespace global and content-set HIA policy

## Source and stage

This owner translates version, watched_version, content_version and all
ContentWatchSet construction/version/drop decisions from the complete unchanged
src/mcp/runtime/namespace_version.rs at d3d75c30719db966b004756f610007a7c723729e.
The private Watcher dependency is finalized at a9eff35bb951b262d730a21b16c8a5bf904f25b9;
the independent fingerprint fallback is finalized at 54b30ca1f97978b4c13b022c13d08a469523a801.

This source stage authors and compiles the policy without calling it. Actual
native mutex, atomic, watcher, fingerprint and lifetime composition remains to
be built and qualified against the complete original. No source/build result
counts as namespace or public-route qualification.

## Original decisions

Two distinct process-lifetime mutex states retain optional Watchers. The ordinary
state uses a 128-watch namespace stream. The content state uses a separate
128-watch content stream. Failed new ordinary Watchers remain absent and their
error reaches watched_version; version releases the mutex before fingerprint.
A content new failure leaves the Watcher absent and returns None, so a later call
retries initialization. A content version failure returns None while retaining
the actual Watcher's partially changed state. Poison produces the original
unavailable error for content_version/watched_version. version suppresses the
watched error and uses fingerprint after releasing the acquired poisoned guard.

A content set validates its entire slice length before allocating a serial.
The process-wide atomic NEXT begins at one; HIA computes checked increment and
requires the next value to remain below 2^63. Native mechanics perform actual
load/compare-and-exchange only, returning the observed value and success bit.
HIA retries contention. The original old serial is ORed with 2^63. A serial is
consumed even if Watcher creation or a later member fails.

The set uses the actual slice length as its Watcher limit and content=true.
Each member's existing shared File pin is cloned by the qualified child.
Duplicate identities are deliberately processed; a final count mismatch rejects
the set after the complete final drain. Any new/version/drain/incomplete/dead
failure drops the actual partial Watcher and returns None. Successful construction
publishes one immutable scope. Set version locks its state, returns None without
another drain once invalid, otherwise drains once and permanently invalidates
on an error or any dead Watch. A valid token uses the set ID and the actual
Watchers's next serial. Drop closes the actual event File and releases all pins
through the qualified child in its original order.

## Entry and trusted resources

f0(input, output, workspace) returns an unsigned 32-bit extent. Input is borrowed,
output is at least 192 bytes, and private workspace is at least 8192 bytes.
The three regions must be disjoint. Invalid frame/capacity returns 0xffffffff /
0xfffffffe without mutating valid owned regions. Each invocation has an exclusive
workspace; it is never the shared mutex state. A new command has an increasing
nonzero generation and no pending prior command.

The native caller retains the real borrowed directory and every supplied shared
File reference for the entire call. Request integer FDs and opaque pin pointers
are trusted private capabilities supplied by that native caller. They are not
public JSON fields. All ACK values must be copied from the actual corresponding
locked state, atomic operation or completed child; an observer has no authority
to produce them. Unexpected mechanical failure uses a separate poisoned
transport path and cannot be reported as an original source business result.

HNVSQ001 is a 96-byte initial header, followed by the complete list when needed:

| Offset | Field |
| --- | --- |
| 0 | HNVSQ001 |
| 8 | Command |
| 16 | Nonzero generation |
| 24 | Kind: ordinary 1, content 2, set 3 |
| 32 | Borrowed directory FD for commands 1, 2 and 6; otherwise zero |
| 40 | Complete member count for command 3; otherwise zero |
| 48, 56, 64, 72 | Zero |
| 80 | Exact payload byte count |
| 88 | Zero |

Commands 1/2 invoke ordinary version/content_version. Command 3 constructs a new
set; 4 observes an existing set; 5 disposes an exclusively owned final set.
Command 6 exposes the same private watched_version path without its caller's
fingerprint fallback. Kinds are fixed by the command.

For a valid 0..258 construction count, payload length is count*16. Each record
contains actual FD then positive shared pin capability, both u64. A count above
258 has zero payload: the original rejects the length before inspecting any
element, and no arbitrary-sized prefix is imported. FD zero is valid. A valid
constructor receives a new native set object whose locked state is empty;
observing or dropping requires a live constructed set.

HNVSW001 workspace is private call state. Scalars occupy 0..231, 512..575 holds
the exact locked shared state, and 2048..6175 holds up to 258 full FD/pin pairs.
Reserved ranges remain zero. The child workspace is read from complete borrowed
ACK payloads, not placed in a reduced synthetic snapshot.

## Shared state and mutex

A newly created native shared-state region is 64 zero bytes. The first admitted
ordinary/content operation creates HNVGS001 in that region. A set's region starts
empty and is published only after successful construction.

| Relative offset | Field |
| --- | --- |
| 0 | HNVGS001, or zero for the entirely zero initial region |
| 8 | Kind 1/2/3 |
| 16 | Actual owned child Watcher capability, or zero |
| 24 | Composite set ID, or zero for a global state |
| 32 | Permanent invalid flag for a set; zero for a global |
| 40 | Initialized global or successfully published set flag |
| 48, 56 | Zero |

The native object owns the actual mutex and its poison state outside these policy
bytes. Lock ACK copies all 64 protected bytes and the actual poison indication.
Unlock commits exactly the HIA-provided 64 bytes while still holding that same
mutex, then releases it. Ordinary fallback never runs under the Watcher mutex.
The two globals have no production reset/destructor. Scope objects and the atomic
counter must belong to the same runtime process; native PID and lifetime custody
are part of the forthcoming mechanical boundary, not user-supplied authority.

## Response and effects

HNVSR001 terminal output is exactly 128 bytes: kind at 8, generation at 16,
command at 24, total effect count at 32, error family/code at 40/48, version words
at 56/64, zero at 72, digest bytes 80..111, and zeros 112/120. Kinds are 0 None,
1 Watch, 2 Fingerprint, 3 original error, 4 constructed set and 5 disposed set.
A constructed set exposes its ID at 56; the native factory returns the actual
new owned object only for that kind.

Pending kind 6 uses operation at 40, arguments a/b/c/d at 48/56/64/72, payload
length at 80 and complete response extent at 88. Reserved 96..127 stay zero.
Only unlock has a 64-byte payload, so its extent is 192; other effects are 128.

| Operation | Actual mechanical effect | Arguments |
| --- | --- | --- |
| 1 | Acquire the actual target mutex, copying its complete protected state | All zero |
| 2 | Commit the complete state payload and release that mutex | All zero |
| 3 | Create/initialize a qualified child Watcher | Limit, content, zero, zero |
| 4 | Bind/invoke the same actual child | Child, child command, FD, shared pin |
| 5 | Drop/dispose the same child and release its native storage | Child, zero, zero, zero |
| 6 | Invoke the actual qualified fingerprint on the borrowed directory | FD, zero, zero, zero |
| 7 | Read the shared real NEXT atomic | All zero |
| 8 | Real compare-and-exchange of NEXT | Expected old, proposed next, zero, zero |

## Exact continuation data

HNVSAK01 header is 96 bytes: generation8, sequence16, operation24, status32,
zero40, value48, value2 56, payload length64, whole extent72, zeros80/88.

Lock status is the actual poison Boolean and its payload is all 64 protected
bytes. The lock remains acquired in either case. All other completed mechanical
operations use status zero; unlock has no payload or values.

Child operations retain the full 128-byte terminal HNWR0001 followed by the
complete 65536-byte HNWST001 workspace. ACK value is the actual child capability
(or zero after failed creation), and value2 is its actual private generation.
The total frame is 65760 bytes. A drop captures those completed child buffers
before its storage is released. HIA checks terminal command/error/token/state
and scans the actual complete Watch records for dead flags.

Fingerprint retains the complete 128-byte HNFRS001, giving a 224-byte ACK with
zero values. Its actual error family/code, including source-permitted errno zero,
or all 32 digest bytes become the terminal outcome.

Atomic load returns the real current u64 in value with zero value2. CAS returns
the observed old value and Boolean success. A successful ACK must match the
expected old value; failure must contain the conflicting value. The native
boundary uses strong CAS, so no unobserved spurious result is invented.

Watcher literal family2 codes 1..8 retain their qualified meanings. Additional
family2 codes are 9 namespace watcher unavailable, 10 archive content watcher
unavailable, and 11 archive content watch set unavailable. OS family1 values are
actual child errno. Normal constructor child failures are suppressed as None,
matching build().ok(), after complete owned cleanup.

## Qualification still required

The actual domain must retain complete parent/child input, output and workspace
bytes, state locks, real atomic attempts, original syscalls, every File pin and
resource close, both observed/off modes, concurrent calls and process lifetime.
It must compare complete original globals and ContentWatchSet, including all
original tests, 258 distinct members, duplicate/incomplete scopes, failed init,
partial construction, fallback ordering, poisoning, serial exhaustion and
permanent invalidation. Existing private dependencies do not substitute for that
new composition evidence.

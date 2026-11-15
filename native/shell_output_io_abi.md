# Shell foreground output IO: private HIA ABI v1

This module owns ordered foreground file reads and discard. It is a private
prepared-capture capability boundary, not capture preparation, job registry,
production Shell dispatch, or whole-runtime replacement. A trusted controller
begins it at the real shell_process kind-2 event after unregister. It does not wait
for the process arena's quiet orphan to retire. Outcome text/error priority is
owned by shell_outcome and is not selected by the syscall adapter.

## Entry and request

f0(readbuf request, mutbuf descriptor, mutbuf workspace) -> u32.

Request is exactly 40 bytes, five little-endian u64 words:
HSHOIQ01, operation, capture_token, wait_kind, wait_value.
operation 1 begins; 2 resumes; 3 latches outer-future cancellation.
A fresh workspace accepts operation 1 only. Token is nonzero, opaque and minted
by the actual native fixture/controller that owns both capture paths. A request
never supplies a path, raw FD, PID, or arbitrary syscall.
wait_kind 0 carries u32 raw wait-status bits. wait_kind 2 carries a
sign-extended i32 raw OS errno (including zero). These fields and the token remain
unchanged on every resume. Text errors belong only to separate pure projections.

Return 0xfffffff0 means a private effect remains pending; 0xffffffff invalid
request; 0xfffffffe initial buffer capacity refusal; 0xfffffff9 contract failure.
Pending and all refusals preserve the entire descriptor output.
A caller supplies at least 64 output bytes and an initially zero workspace of
at least 8192 bytes. There is no raw-log quota or 8 MiB input check.

## Completed descriptor and outcome loan

Success returns 64 and writes eight Q words:
HSHOID01, kind, capture_token, workspace_offset, span_length, 0, 0, 0.
kind 1 loans the complete HSHOUT01 foreground frame at workspace offset 4096;
kind 2 means the cancelled outer operation has stopped scheduling future awaits
and has finished its already-started file task, and has offset/length zero.
After either descriptor the module retires: later valid resumes return zero
without modifying output. A controller can acknowledge outer cancellation
independently while this private detached file task continues.

The outcome frame is exactly the agreed 112-byte HSHOUT01 header followed by
stdout then stderr successful bytes. op=1; wait_kind is retained, and normal u32 raw wait-status bits are sign-extended
to the canonical i32 representation required by HSHOUT01. Raw OS errno is already
canonical signed i32. The original request value remains bound on each resume.
Read Result kinds are 0=Ok, 2=raw OS errno, 3=OutOfMemory from a genuine
fallible initial/main-loop allocation failure. The infallible probe extension
is a separate fatal boundary and never publishes a read Err. An error contributes no payload, even if earlier reads returned bytes.
pid, wait-text length, command length and job-id length are zero.
All lengths and offsets are u64. f0's u32 return is the fixed descriptor size;
it does not impose a 4 GiB raw-log limit. The trusted coordinator lends the
workspace subspan to the HIA outcome owner; it must not dereference arbitrary
frame pointers. Workspace may move only at an admitted grow effect.

## Original operation order

For a live outer future:
stdout open -> metadata hint -> read to actual EOF/error -> close;
stderr open -> metadata hint -> read to actual EOF/error -> close;
unlink stdout; unlink stderr; only then loan both Results.
Both reads and both unlink attempts occur despite saved wait/read errors.
Unlink errors and File-drop close errors are retained in raw audit but ignored
semantically. Open retries EINTR. Read/probe retries EINTR. Unlink and close
are single attempts, including EINTR.

The HIA owner follows Rust 1.95 std::fs::read/default_read_to_end: metadata is an
optional reservation hint; errors are ignored; short read is not EOF; zero is EOF.
Initial Vec capacity is the successful file length. Unknown/zero-size reads use
the 32-byte probe. Exact initial-capacity fits probe once before growing.
Amortized u8 capacity growth preserves max(2*capacity, required, 8). Main-read
maximum begins at checked round_up(size_hint+1024,8192), otherwise 8192; the
unknown-hint short/full-read heuristics are retained. Only the actual filesystem
and original read loop determine the observed concurrent-growth/truncation bytes.

Linux GNU metadata tries statx on the open FD with an empty path,
AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT, STATX_BASIC_STATS | STATX_BTIME;
A successful statx records Present. On failure in Present state, the metadata
error is ignored. On failure in Unknown state, HIA requests the original
statx(0,NULL,0,STATX_BASIC_STATS|STATX_BTIME,NULL) availability probe. EFAULT
records Present and the original metadata error is ignored; any other probe
result records Unavailable and falls back to fstat. Unavailable skips statx.
Workspace metadata structures remain raw kernel bytes. This local flag
covers the one fresh-process IO transaction; Rust's availability cache is
process-global. The integrating HIA coordinator must propagate the shared
capability state between IO arenas before claiming cross-invocation syscall
identity. Standalone evidence does not claim that additional integration.

A cancelled outer future does not start the next read/unlink await.
An already-started std::fs::read equivalent completes its whole read loop and
close before quiet retirement; it is not prematurely cut off at one syscall.
The adapter must permit a blocking read effect to remain in flight while the
trusted coordinator advances other arenas. Cancellation is not a new read Err.

## Private effect mailbox

At workspace+256, 96 bytes / 12 Q:
HSHOIFX1, sequence, action, arg0, arg1, arg2, reserved0,
result, errno, aux0, ready, reserved0.
HIA emits ready=0 and zero result fields. An owned kernel dispatcher validates
the issued sequence, immutable arguments, stream/FD custody and destination
bounds, performs the primitive, then writes ready=1. errno is raw Linux errno
1..4095, result is zero on error. No host error text or priority is allowed.
Repeated f0 calls while ready=0 retain the same effect; dispatch exactly once.
Shadow request fields at 896..935 detect accidental completion changes.

| Action | Arguments | Successful result |
|---|---|---|
| 1 ADMIT_CAPTURE | capture token, 0, 0 | 0 |
| 2 OPEN_READ | capture token, stream 0/1, 0 | owned read-handle token |
| 3 STATX | read handle, workspace offset 384, 256 | 0, raw statx at destination |
| 4 FSTAT | read handle, workspace offset 640, 144 | 0, raw x86-64 stat at destination |
| 5 READ | read handle, workspace offset, byte count | actual byte count |
| 6 CLOSE | read handle, 0, 0 | 0; retires handle even when close errors |
| 7 GROW_WORKSPACE | minimum byte capacity, 0, 0 | new complete workspace length |
| 8 UNLINK_CAPTURE | capture token, stream 0/1, 0 | 0 |
| 9 STATX_AVAILABILITY | 0, 0, 0 | fixed null-argument original availability probe |
| 10 WRITE_FATAL_DIAGNOSTIC | workspace message offset, byte count, 0 | actual bytes written to fixed stderr FD2 |
| 11 ABORT_SELF | 0, 0, 0 | does not return; fixed self SIGABRT intrinsic |

OPEN_READ has ordinary std::fs::read path-following semantics: opening a
replacement path must not silently use the writer FD's old inode. READ uses the
owned opened descriptor, preserving its file offset and inode after path
replacement. Unlink also uses the current owned path, not the opened inode.

GROW is internal storage plumbing: the dispatcher admits, allocates and preserves
the entire old workspace before completing on the new mapping. A smaller public
buffer is not converted into a semantic read error. A real ENOMEM from the fallible initial reservation or
main-loop try_reserve is separately tagged OutOfMemory. A real ENOMEM while
extending the 32-byte probe invokes HIA's fatal diagnostic and ABORT_SELF; it must
not be transformed into a read error. The production release profile is
panic=abort, so probe capacity overflow is also fatal. The private fatal message
region is1024..1279 and decimal scratch is1280..1299. HIA owns diagnostic bytes,
write retry/partial progress and the choice to abort; the adapter selects none of
these policies. Action11 has an issued record followed by actual process death,
not a fabricated completion/footer.

The standalone fatal allocation diagnostic implements the pinned Rust default
OOM hook with BacktraceStyle::Off (including its backtrace hint). Custom alloc
hooks, enabled backtraces, concurrent diagnostic recursion and full Rust panic
source-location formatting are separate, unqualified process-wide facilities.
Probe capacity overflow preserves the fatal release decision and records the
panic payload; it does not claim byte-identical Rust panic-hook stderr. A later
process-wide panic owner must close that diagnostic boundary. Refusal/contract failures are fatal
qualification/infrastructure failures with trusted capability cleanup.

## Workspace map

0..255 HIA state; 256..351 private effect; 384..639 raw statx;
640..783 raw fstat; 800..831 probe bytes; 896..959 request shadow/result cache.
4096..4207 HSHOUT01 header; successful raw stream bytes begin at 4208.
State Q offsets: phase8, token16, sequence24, stream32, readhandle40,
stream-start48, Vec-length56, Vec-capacity64, initial-capacity72,
hint-present80, hint88, max-read96, short-count104,
stdout kind/errno/len112/120/128, stderr136/144/152,
wait-kind160/value168, grow-required200, cancelled208, probe-bytes224,
requested-read232, statx-availability240 (0 Unknown, 1 Present, 2 Unavailable).
Internal continuation at976 is used only by HIA to avoid recursive calls.
Fatal kind984, message length1000 and written bytes1008 belong to HIA.

## Required qualification scope

Keep complete input, descriptors, workspace loans, real capture bytes, syscall
results, paths, FD tokens/actual FDs and inode observations. Actual filesystem
tests and pure injected completion tests are distinct. The native fixture's
capture token is private and owned; it does not prove original preparation or
registry behavior. All production, whole-runtime and old-stack removal flags
remain false until their separate integration gates pass.

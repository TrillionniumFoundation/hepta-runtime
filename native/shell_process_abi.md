# Native shell process owner (development ABI)

This internal Linux x86-64 owner covers one prepared shell child: spawn, foreground
waiting, custody transfer to background, wait completion, cancellation and reaping.
It does not implement background::prepare job names/directories/duplicate registry,
MCP dispatch, resource text, or the complete foreground result formatter. Production
activation and whole-runtime replacement remain false until their own integration
and original-source/kernel qualification pass.

The entry is f0(readbuf input, mutbuf output, mutbuf private_work) -> u32.
The compiler pin is Hepta d3e2c90173cf733e42b299d0c4274df4b593a12f.
The private arena belongs to exactly one invocation and is never reused for another
child. The trusted controller prepares real stdout/stderr log files and binds one
nonzero opaque capture token to this arena. No request contains a raw FD or PID.

## Input

All integers are little-endian u64. The 40-byte header is:

| Offset | Field |
|---:|---|
| 0 | Eight bytes HSHPRQ01 |
| 8 | Operation: 1 start/resume, 2 continue, 3 cancel foreground caller, 4 shutdown tracked child |
| 16 | Prepared capture token; nonzero and unchanged for this arena |
| 24 | Command byte length |
| 32 | Raw Unix cwd byte length |
| 40 | Command bytes then cwd bytes, exact extent |

Operation 1 is required for a fresh arena. Its command is strict UTF-8; cwd is raw
Unix bytes. A NUL in either is an original spawn InvalidInput result, not invalid
transport. Operations 2/3/4 require both lengths zero and exactly 40 bytes.
Repeated operation 1 while an effect is pending uses the unchanged admitted input.
The owner copies the command/cwd before yielding; post-promotion operation 2 needs
no borrowed command bytes. Operation 3 after promotion cannot cancel the moved
background child. Operation 4 is a trusted controller lifecycle event, not an
authority-granting public MCP request.

The fixed production foreground interval is 10000000000 monotonic nanoseconds,
starting after successful spawn and tracking. A separately pinned short-duration
qualification image may be used; ordinary frames cannot select a duration.
Every poll checks the child before the timer, preserving Tokio Timeout's inner-
future-ready precedence. A child already observed ready is not rejected by a
later deadline check.

## Return and event

0xfffffff0 means one private effect pending. 0xffffffff refuses an invalid typed
request; 0xfffffffe is transport/workspace capacity; 0xfffffff9 is a private state,
completion or effect-contract violation. Pending/refusal leaves every output byte
unchanged. Return 0 means that this arena is retired and publishes no event.
Return 96 publishes exactly the following event; its output tail stays unchanged.

| Offset | Field |
|---:|---|
| 0 | Eight bytes HSHPRR01 |
| 8 | Kind: 1 spawn error, 2 foreground completion, 3 promoted, 4 background completion, 5 caller canceled, 6 shutdown signaled |
| 16 | Capture token |
| 24 | Private child token, zero before successful fork |
| 32 | Observed child PID, zero before successful fork; display only |
| 40 | Exit code as u64 two's-complement; -1 when unavailable or signaled |
| 48 | Raw wait status, zero when unavailable |
| 56 | Error kind: 0 none, 1 raw OS errno, 2 original NUL InvalidInput |
| 64 | Raw OS errno for error kind 1; otherwise zero. A retained libc errno of zero is representable. |
| 72 | Per-arena monotonically increasing event sequence |
| 80 | Original tracker membership, exactly 0 or 1 |
| 88 | Flags: bit 0 promoted; bit 1 reaped; bit 2 abandoned caller |

Kind 3 retains the same waiting background owner. The controller continues with
operation 2 after every event until return 0; other events may retain private
cleanup work. Kind 5 is an internal observation of future drop, not a successful
shell tool result. It follows direct SIGKILL and one nonblocking try_wait, without
waiting for the child to finish. A pending child is then maintained and reaped
quietly; no invented resource callback, log discard or tracker unregister is
added to that original cancellation path. Shutdown still drains and signals a
tracked, not-yet-retired orphan. Once kernel custody is lost or the child has
been reaped, the adapter must never signal a recycled numeric PID. This refusal
is an explicit safety distinction from the original stale-tracker bug. Kind 6 records
the shutdown signal operation; any existing waiter may still finish. Original
foreground log reads/discard occur after wait completion and unregister, in the
future caller/controller, and must not be moved before those operations.

## Private work layout

A fresh workspace is zeroed. At least 8192 bytes are required before any effect.
Data grows from offset 4096; exhaustion is a transport failure, not a new command
length limit. Header offsets are fixed for the adapter:

| Offset | Meaning |
|---:|---|
| 0 | HSHPRST1 after initialization |
| 8 | HIA continuation state |
| 16 | Last issued effect sequence |
| 24 | Role: 0 before fork, 1 parent, 2 child |
| 32 | Capture token |
| 40 | Private child token |
| 48 | PID |
| 56 | Original tracker membership |
| 64 | Promotion flag |
| 72 | Absolute monotonic foreground deadline |
| 80 | Pending event kind |
| 88 | Exit code (-1 initially) |
| 96 | Raw wait status |
| 104 | Saved errno |
| 112 | Saved error kind |
| 120 / 128 | NUL-terminated command offset / original byte length |
| 136 / 144 | NUL-terminated cwd offset / original byte length |
| 152 / 160 | Environment snapshot offset / total bytes |
| 168 / 176 | Final environment table offset / count |
| 184 | Environment table allocation count |
| 192 | Current data end |
| 200 / 208 / 216 | PATH bytes offset / length / scan cursor |
| 224 / 232 | Remembered EACCES / most recent exec errno |
| 240 / 248 | Current script candidate offset / length |
| 256..351 | Private effect slot |
| 352 | Last published event sequence |
| 360 / 368 | Expected pending action / continuation state |
| 376 | Original input length |
| 384 | Fixed foreground duration, 10000000000 |
| 392 | Deferred control: 0 none, 3 caller cancellation, 4 shutdown |
| 400 | Reaped marker |
| 408 | Abandoned caller marker |
| 416 | Shutdown signal operation completed |
| 424 | Original command/cwd NUL marker |
| 432 | Shutdown control already received |
| 440 | Fixed /bin/sh fallback string offset |
| 448 | Default PATH string offset |
| 456 | Candidate buffer capacity (4100) |
| 464 | ECHILD observed during wait-error drop cleanup; kernel custody is independently tracked by the adapter |
| 472 | Quiet orphan maintenance after a published wait error |
| 512..575 | Exec plan |
| 640..663 | Original emitted effect arguments for completion validation |
| 672..695 | Consumed result / errno / auxiliary scratch |
| 4096.. | Command, cwd, environment snapshot, environment table and strings |

Environment snapshot is u64 count followed by count records, each u64 length,
that many raw bytes and one terminal NUL. Length excludes NUL. Embedded NULs,
truncation and trailing bytes violate the private snapshot contract. HIA applies
Rust's Unix environment parsing (separator search starts at byte one), last-key-
wins collection, the five original overrides and raw-byte key sorting.

Final environment table entries are 32 bytes: string offset, string byte length,
key byte length, source ordinal. Each referenced string has a terminal NUL.
Only the first two fields are kernel arguments; key/ordinal are HIA bookkeeping.
The adapter bounds-checks all entries and creates its own temporary pointer array.

Exec plan at 512 is eight u64 words: argv mode, environment table offset,
environment count, command offset, command length, script-candidate offset,
script-candidate length, zero. Mode 0 is argv=[sh,-c,command]; mode 1 is
argv=[/bin/sh,script_candidate,-c,command]. The executable path is separately
provided by EXEC_ATTEMPT; HIA alone selects candidates and ENOEXEC fallback.

## Private effects

The 96-byte slot at 256 is twelve u64 words: HSHPRFX1, sequence, action, arg0,
arg1, arg2, zero, result, positive errno, auxiliary result, completed (0 then 1),
zero. Emission zeros all completion and reserved words. The adapter validates
the current arena, role, owned token/descriptor state, action, phase, spans and
sequence; it writes completion and reenters the same pinned HIA image. Ordinary
input cannot supply a completion. The HIA owner independently checks the slot
and its saved original arguments before consuming it.

| Action | Arguments | Completion / fixed kernel operation |
|---:|---|---|
| 1 CAPTURE_ADMIT | token,0,0 | Bind the pre-existing capture pair to this arena; result/errno/aux all zero |
| 2 ENV_SNAPSHOT | destination,available,0 | Copy inherited raw environ; result=complete bytes, errno=0. Insufficient space: no snapshot write, result=0, errno=ENOBUFS(105), aux=complete required bytes greater than available; HIA returns transport capacity. No env policy in adapter. |
| 3 OPEN_NULL | 0,0,0 | Open read-only /dev/null with CLOEXEC into a private slot; normalize source FD above 2; zero/errno |
| 4 EXEC_CHANNEL | 0,0,0 | socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0); fixed private endpoints |
| 5 FORK | 0,0,0 | result=PID in parent, 0 in child; aux=same private child token; positive errno on failure |
| 6 CLOSE_UNUSED | role(1 parent/2 child),0,0 | Close/retire the other exec-channel endpoint; close errors ignored as FileDesc drop |
| 7 DUP_STDIO | target(0/1/2),0,0 | dup2 from private null/stdout/stderr respectively; HIA retries EINTR |
| 8 CHDIR | cwd offset,cwd length,0 | chdir of admitted NUL-terminated raw bytes; zero/errno |
| 9 SIGPIPE_DEFAULT | 0,0,0 | Child SIGPIPE disposition default; preserve inherited mask and SIGCHLD disposition |
| 10 SETSID | 0,0,0 | setsid; result=new session ID or positive errno; no prior setpgid |
| 11 EXEC_ATTEMPT | executable offset,length,512 | execve with HIA-selected path/plan; success does not return; failure returns positive errno |
| 12 EXEC_FAILURE | errno,0,0 | Child writes errno(u32 BE)+NOEX, retry EINTR, then SYS_exit(1); never returns |
| 13 EXEC_HANDSHAKE | 0,0,0 | Parent reads channel; result=0 EOF success or 1 complete NOEX; NOEX errno in errno field; malformed/other IO is contract failure |
| 14 TRACK | child token,register(1)/remove(0),0 | Private tracker operation decided by HIA; no client-selected PID |
| 15 CLOCK | 0,0,0 | CLOCK_MONOTONIC; result=nanoseconds; private kernel failure remains distinct |
| 16 WAIT | child token,blocking(1)/WNOHANG(0),0 | result=1 reaped/0 pending; aux=raw wait status; errno is wait failure; blocking wait retries EINTR, WNOHANG try_wait preserves EINTR as an error |
| 17 WAIT_WAKEUP | child token,remaining ns,0 | Wait for readiness/control; u64-max is no foreground deadline; no promotion decision in adapter |
| 18 SIGNAL | child token,direct(1)/group(2),9 | Signal only this arena's owned child or session group; HIA chooses direct versus group; original ignored signal errors stay ignored |
| 19 CLOSE_SETUP | 0,0,0 | Close/retire private null/channel setup FDs; capture files stay under controller custody |

The child ordering is DUP_STDIN, DUP_STDOUT, DUP_STDERR, CHDIR, SIGPIPE_DEFAULT,
SETSID, then the HIA-selected exec plan. On spawn NOEX the parent reaps before
publishing the spawn error. Normal foreground wait and background wait remove
tracker membership before publishing completion. The foreground deadline causes
a promotion event, never a signal or second fork.

Native fixture: ELF --process-fixture OWNED_EMPTY_CAPTURE_DIRECTORY prepares
stdout.log/stderr.log and capture token 1. Input is u64 length plus the above
frame; output is full u64 return, u64 published extent, and actual event bytes.
The fixture forwards cancellation as operation 3 and EOF/shutdown as operation 4.
While waiting it may replace the retained request by a complete control frame
only at an effect completion boundary; command/cwd are already private copies.
After a promotion event it continues the same arena with operation 2 even if
the client sends no further request. No command, PATH, timeout or result decision
is made by that fixture.

## Qualification status

This document is the implementation contract, not proof of completed execution.
The new owner, adapter, original Rust comparison and real OS suites must produce
fresh matching artifacts and raw receipts before any passing claim. Linux/GNU
execvp behavior is pinned separately to observed libc identity; PATH overlong
segment behavior and inherited errno require explicit edge controls.

# Private publication blocking capability, native build v1

This package adds an independently owned blocking executor around the exact
qualified synchronous publication callable. HIA owns queue, generation,
completion, caller, borrow and retirement decisions. The assembly performs only
fixed native calls, guarded allocation, clone/wait4, copying and private
capability checks. The checked-in HIA is the actual generated output of
3fc3fc428d05fed64b61b7fc783906fad5cb3635 and is reauthored byte for byte here.

**This revision qualifies source and build custody only. Application execution,
native asynchronous semantics and public installation remain false.**

## Actual original boundary

The original current-target 30-case reference is frozen at
75ad10aa9ad9dfa893258135a89bd6aa7976bc6a. SDK notification cancellation does
not drop the handler future; normal input EOF also permits that handler to
finish and perform its post-await cache forget. Explicit direct future Drop
skips the handler's post-await work while its already enqueued blocking closure
continues. This capability does not process public cancellation or EOF itself.

Tokio 1.53.3 default blocking limit is 512 in the retained Builder source.
The private constructor accepts the runtime's trusted configured limit.
Private qualification can select 1 to observe queued work. No public JSON field
selects this limit. The implementation creates process-owned clone workers per
job, instead of retaining idle Tokio worker threads. The published original
domain does not establish every idle-worker shutdown race: Tokio's busy loop
drains queued work, while its idle shutdown path can discard nonmandatory tasks.
Do not promote the explicit drain capability into an all-Tokio-shutdown claim.

## Native exports

SysV x86-64 arguments and return values are used. All pointers are graph-owned
capabilities. The caller is the pool's creating process. Reentry is refused.
The HIA output buffer, where required, has at least 320 writable bytes.

| Export | Arguments after pool | Result |
| --- | --- | --- |
| publication_worker_create | limit, observer, observer_context (no pool input) | private pool or negative errno |
| publication_worker_submit | complete HTPBQ001 input, extent, nonzero private tag, output320 | HIA return; successful output assigns unique job |
| publication_worker_service | none | 0 after nonblocking reap/start/wake-drain |
| publication_worker_poll | job, output320 | 320; HIA status 2 means pending |
| publication_worker_take | job, output320, borrow64 | 320; HIA status 0 publishes complete borrow |
| publication_worker_drop | job | 0 or raw HIA refusal |
| publication_worker_release | job | 0 or raw HIA refusal |
| publication_worker_close | none | 0; stops admission, retains queued work |
| publication_worker_observe | output320 | 320; exact HIA state, no service |
| publication_worker_wake_fd | none | borrowed read descriptor or negative errno |
| publication_worker_destroy | none | 0 only after complete native/HIA retirement; BUSY otherwise |

Drop is actual handler-future destruction. It is never shorthand for
notifications/cancelled, input EOF or loss of the output transport. Public code
must retain the handler continuation and its issuing-session cache until that
handler really completes or is destroyed by the actual SDK lifecycle.

The observer is fixed at creation. It receives
(context, pool, event, complete_span, length) and returns zero. It runs inside
the pool's journal mutex, must not call the capability again, and cannot replace
a syscall or policy decision. Events 1/2/3/4 contain complete HIA input64,
output320, allocated state and raw return; events 5/6 record actual clone/wait4
job/tag/PID/outcome; events 7/8/9 contain a body event header, its whole span and
the complete 4096-byte body context. No slice or digest substitutes for bytes.

## HIA ABI

Input HPTWQ001 is 64 bytes: magic, command, job, now_ns, argument, three zero
words. Output HPTWR001 is 320 bytes. At offsets 16/24/32 it contains status,
command and job. Offsets 40..112 contain actual phase, caller state, reaped bit,
start/finish clocks, body raw return, infrastructure kind, record offset, begun
and admitted bits. Offset 120 is zero. The entire 192-byte pool header follows.

Commands are 0 initialize, 1 enqueue, 2 reserve oldest, 3 clone ACK, 4 BEGIN,
5 COMPLETE, 6 Drop, 7 poll, 8 take, 9 release, 10 actual reap, 11 close admission,
12 observe, 13 actual clone failure, 14 actual worker failure. No command
fabricates body completion or wait4. Invalid lifecycle returns raw 0xffffffff;
insufficient fixed header capacity returns 0xfffffffe. Successful op6/op9/op12
always have status zero; illegal Drop/release return raw INVALID, never a
successful-length nonzero-status record. Growth uses exact HGRWS002 minimum,
preserves all state and retries the same request after mechanical allocation.

Each live record is 128 bytes. A task retires only after phase COMPLETE,
actual OS reap and either Drop or explicit borrow release. Output storage stays
owned through delivery and release. No mapping is freed while a child can use
it. The HIA active count measures unfinished body work, not zombie OS PIDs;
the final instruction sequence after COMPLETE may overlap the next admitted
job. Full original physical idle-thread reuse is outside this boundary.

## Private binary fixture

Only the test ELF owns stdin, stdout and FD3. Input is u64 extent followed by
HPTWFQ01 and seven words: command, job, tag, payload length, argument, flags, zero.
Only submit has payload. Only create uses argument (trusted limit) and flags
(0 observer on, 1 observer off). Only submit uses nonzero private tag.
There is one pool and any number of HIA-issued jobs; a job ID is not a session
credential. All reserved fields and exact extents are checked.

Commands 0..9 mirror create, submit, service, poll, take, release, Drop, close,
destroy and observe. Private commands 10/11 copy the complete pool control/state
under the same mutex. Commands 12..17 observe actual task/body context,
workspace, output, body input and owned submitted input only while that task is
unstarted or complete. Running body memory cannot be read by these controls.

Response HPTWFR01 is 64 bytes: magic, actual raw return, following extent,
command, requested job, private pool address, exchange ordinal, zero.
Submit/poll/observe return all 320 HIA bytes. A successful take includes those
320 bytes, HPTWB001's 64-byte private borrow and all borrowed result bytes.
The borrow header contains job, body raw return, address, extent, tag and
infrastructure bit. Consumers must use the complete body extent.

FD3 records HPTWJR01 header64 followed by the entire event span. Header fields
are magic, event, actual HIA call ordinal, extent, pool address, creator PID,
callback PID and zero. Pool mutations and records serialize on one real mutex;
body filesystem waits never hold that mutex.

The fixture requires explicit pool destruction before stdin EOF. It never
silently equates EOF with Drop. The process manager must preserve all process
streams and actual child cleanup, with existing 60-second exchange and
180-second process limits. No application commands run during this build gate.

## Shared production integration

This build does not alter the unique 320862f0 production graph. Publisher
descriptors64..68, extractor59..63, SDK registry58 and existing worker57 remain
unchanged. Any later public attachment must retain the existing request-owned
fence27, Scope6 and Context10 mover, shared Lease7/cache8 and the SDK generation.
Publisher PN space is 1184..3584; the shared fence/Scope mover owns 3584..3888.
No new shared engine field is assigned by this package.

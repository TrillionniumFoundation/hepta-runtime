# Two-permit blocking-worker lifecycle

This private HIA owner implements the admission and lifetime required by the
current `weight_bellman::plan`: `try_acquire_owned` from one shared semaphore
of size two, with the acquired permit moved into the actual blocking closure.
A third call is rejected immediately. Dropping its awaiting caller does not
cancel that closure, release its permit, or retire memory still used by it.

The state is exclusively borrowed under the fixed bridge's shared mutex.
That mutex is mechanical serialization. HIA owns permit counts, job
generations, legal transitions, cancellation, completion and retirement.
The bridge supplies actual clone admission, worker entry, completion, wait/reap
and monotonic timestamps. Ordinary tool input cannot issue these private
events or choose a job generation.

## Entry

`f0(readbuf input, mutbuf output, mutbuf pool) -> u32`.

Every input is 64 bytes: eight little-endian words containing magic
`HBPWRQ01`, command, private job ID, monotonic nanoseconds, argument, and
three zeros. Output needs 128 bytes. Pool initialization needs 128 initially
zero bytes; each live record uses another 128 bytes. Dynamic growth is explicit.
Input/output/pool are disjoint. Unknown frames or illegal state transitions
return `0xffffffff` without changing output or pool. Initial insufficient
capacity returns `0xfffffffe` with the same atomicity.

| Command | Private event | Required fields |
| --- | --- | --- |
| 0 | Initialize this process-owned pool once | job/time/argument zero |
| 1 | First poll; try to acquire a permit | job/time/argument zero |
| 2 | Actual blocking worker admission acknowledged | job only |
| 3 | Worker enters solve; anchor its deadline | job and actual CLOCK_MONOTONIC ns |
| 4 | Poll this active caller's result | job only |
| 5 | Worker has completed its full owned work | job, actual finish ns, exact-u32 result |
| 6 | Drop/cancel the awaiting caller | job only |
| 7 | Take a ready result exactly once | job only |
| 8 | Acknowledge actual worker wait/reap | job only |
| 9 | EOF/shutdown drops callers, then drains | job/time/argument zero |
| 10 | Observe current pool counters | job/time/argument zero |
| 11 | Actual clone/submission resource failure | prepared job, positive Linux errno |
| 12 | Actual abnormal worker wait result | admitted/running job, finish ns, positive status |

Commands 11/12 are explicit mechanical infrastructure outcomes; arbitrary
process signals or clone allocation failure are not relabelled as a caught
Rust panic or an original application error. Their original parity domain is
separate from ordinary completion and cancellation.

First-poll admission and actual worker submission are one uninterrupted poll
turn. Cancellation or shutdown while HIA is in the prepared state is refused;
the fixed bridge must finish its admission acknowledgement or resource-error
cleanup before applying a pending caller cancellation. Creating an unpolled
caller does not enter this owner or acquire a permit.

## Results and ownership

Ordinary returns have code 128 and the following sixteen words:

`HBPWRS01`, extent 128, status, command, private job, phase, caller state,
permit-held, solve-start ns, deadline ns, result, flags, permits held,
live records, admitted workers, completed tickets.

Status is 0 ordinary completion, 1 both permits occupied, 2 closed pool,
3 pending result, or 5 infrastructure/resource refusal. Phases are 1 prepared,
2 admitted/queued, 3 running, and 4 worker complete. Caller state is 0 active,
1 dropped, or 2 result taken. Flags bit 0 records actual reap; bits 8..15 are
0 ordinary, 1 submission resource failure, or 2 abnormal worker termination.

On command 3, HIA fixes `deadline = start + 30,000,000,000`; queue wait is not
charged to solve. The timed numerical/commitment owners perform the actual
deadline comparisons at the original check sites. This pool does not substitute
a caller timeout for those checks or terminate a running worker at 30 seconds.

Command 5 releases the worker's permit before its result is consumed or its
OS worker mapping is reaped. A newly admitted third job may therefore coexist
with an older complete result. A dropped caller's running permit stays held
until command 5 or an actual terminal worker failure. Dropped/taken results
retire only after actual reap; active complete results remain until taken or
dropped. Recycled slots get fresh monotonically increasing IDs, and stale IDs
cannot affect another worker. The response retains its terminal job observation
while its aggregate live count reflects retirement at the end of the call.

If a new live record needs more workspace, code `0xffffffd0` returns a 32-byte
`HGRWS002` header: kind 1, exact required capacity, reserved zero. No permit,
ID or workspace state changes until the caller grows and retries. Growth does
not lower the two-permit limit, start work, or duplicate an admission.

## Mechanical integration and present scope

The actual adapter will reuse the registered local Create and effect-fence
clone/join/wakeup patterns, with a single shared HIA pool and private numerical
workspaces. It must retain all request/result mappings, observe actual worker
completion, reap before unmapping, and drain after caller cancellation or EOF.
Directory's different early-release permit policy is not imported.

The first concrete worker edge calls `bellman_timed_core` on the unchanged
`HIABELL1` input. Its CLOCK effects and actual commitment result lead to the
separately fixed `HBLMRQ01` renderer input. No Python policy or host numerical
fallback belongs in that executable.

Author checks, synthetic event tests, an actual native worker graph and fresh
unchanged Rust comparison are separate qualification stages. This ABI alone
does not qualify those stages, public MCP cancellation, HTTP, arbitrary runtime
shutdown configurations, or whole-runtime replacement.

# Current SDK request-task registry

This owner implements the incoming-request cancellation map and response claim
rules from RMCP 3.9.0 `src/service.rs::serve_inner`. It is a private component;
public JSON cannot select its operations, connection generation, task generation,
worker tag, job or clock. The source manifest binds the complete original files.
This private component does not implement outgoing requests, subscriptions,
the event pump, a worker executor, transport writes or public activation.

## Source decisions

`local_ct_pool` is separate from `local_responder_pool`. The server removes an
incoming request's cancellation token on `notifications/cancelled`, cancels that
token, and still dispatches the notification handler. An absent/unknown/completed
ID has no effect. Request IDs remain typed; numeric IDs and string IDs differ.
The HIA input is the complete output of the current G1 message owner, so its
integer/float normalization and typed notification extraction remain in G1.

When a handler's response reaches the sink, the SDK removes the incoming token
and cancels it before starting the response send. If the map entry is absent,
the response is discarded. Cancelling interest neither completes the handler
nor releases a worker permit. The host retains each task's complete frontend
input, workspace, output, descriptor and generation until actual completion.

EOF begins a five-second response drain without immediately cancelling the
service-loop token. Explicit cancellation already cancels that token and begins
a two-second drain. Both cases retain map entries for responses arriving during
the drain. Finishing or expiring the drain cancels the loop token and removes the
map. Running worker storage remains a separate lifetime after transport closure.

## Private input

`HRTKRQ02` is a 64-byte header of little-endian u64 words: magic, operation,
connection generation, request generation, argument 0, argument 1, payload bytes,
reserved zero. The complete input is the header followed by exactly the payload.
Generations are nonzero, process-private values. One workspace is one connection.
ADMIT allocates monotonic request generations and refuses wraparound.

| Operation | Input | Decision |
| --- | --- | --- |
| 1 ADMIT | G1 `HRCJR001` request payload; other controls zero | Store typed canonical ID and create one live handler |
| 2 NOTIFICATION | G1 `HRCJR001` notification payload | Select cancellation by typed request ID, or forward-only notification |
| 3 HANDLER_RESPONSE | Request generation | Mark handler complete and claim its response by the SDK's ID map |
| 4 SEND_ACK | Request generation; argument 0 is actual success 0/1 | Retire one actual send; failure of a send claimed during drain forces close |
| 5 HANDLER_DROPPED | Request generation | Retire an actually destroyed handler future, without a response |
| 6 BEGIN_DRAIN | Argument 0: EOF=1, service cancel=2; argument 1: observed monotonic ns | Begin the corresponding bounded drain |
| 7 DRAIN_PROGRESS | Argument 0: observed monotonic ns | Close only after all handlers/sends drain or the actual deadline passes |
| 8 RETIRE | Request generation | Remove storage only when map, handler, send and cancellation delivery are drained |
| 9 ATTACH_CALLER | Request generation; arguments: runtime tag, observed job | Attach the independently allocated private worker caller |
| 10 NEXT_CANCEL | No extra arguments | Borrow the next undelivered cancellation decision in task order |
| 11 CANCEL_ACK | Request generation | Acknowledge its actual host cancellation delivery |
| 12 INSPECT | Request generation, or zero for connection totals | Read owned state without changing sequence |
| 13 QUEUE_RESPONSE | Actually completed handler generation | Retain an HIA FIFO ordinal without claiming its SDK map |
| 14 CLAIM_NEXT | No extra arguments | Claim the oldest eligible queued response |

No operation starts or polls a worker. A normal notification cancels only
the SDK context; the actual Bellman handler ignores that token and continues
with command 2. Command 3 is limited to actual future destruction after
transport closure. Context cancellation delivery and future destruction are
different acknowledgements. No MCP ID becomes a private worker tag.

## Private output and storage

Successful entry return is 192 and the complete output is 192 bytes,
`HRTKRS02`, followed by: disposition, connection generation, selected request
generation, runtime tag, job, flags, phase, live map count, handler count,
pending send count, record count, workspace used, drain reason, deadline ns,
loop-token cancelled, outer-service-token cancelled, event sequence, zero, zero,
queued count, next queue ordinal, drain-send-failure flag, zero.

Flags are live map=1, context cancelled=2, handler done=4, response seen=8,
send pending=16, cancellation delivery pending=32. Phases are running=0,
draining=1 and closed=2. Dispositions are OK=0, admitted=1, cancelled=2,
cancel no-op=3, publish=4, drop=5, drain wait=6, closed=7, retired=8,
no cancel event=9, cancel event=10, other notification=11, queued=12,
no queued response=13, and wait for an existing drain send=14.

`0xffffffd0` returns the existing complete 32-byte `HGRWS002` growth frame.
Growth happens before the affected admission or decision commits. Invalid
private input is `0xffffffff`; an unavailable lifecycle transition is
`0xfffffff8`. None of these values is an invented public business error.

The workspace starts with a 256-byte header/scratch area. Packed task records
have a 112-byte fixed part followed by their canonical ID bytes, padded to eight
bytes. Retirement compacts live records and wipes the vacated tail; generations
never reuse retired values. The qualifier preserves the entire declared mutable
buffers at every call, including every growth request and retry.

## Frontend seam

The agreed pending frontend result is 64-byte `HRCMFR02` kind 4 with all response
length/error/close/reserved fields zero and sequence retained at 48. Its private
record at workspace 1280 is `[HBLFRS01, tag, job, 0, 0, seq, 0, 0]`; control at
1344 is `[HBLFRQ01, cmd 2/3, tag, job, seq, 0, 0, 0]`. These records are populated
only from the current owned CALL and the registry, never by parsing user-supplied
credentials or tags. Descriptor/continuation generation must match on resume.

Full async runtime, public cancellation timing, HTTP, all 136 handlers,
production activation and old-stack removal remain unqualified until the
actual event pump and full graph are compared with the current original SDK.


## Revision 2: actual handler-response queue

The response now returns 192 bytes: the previous 160-byte prefix plus queued
response count, next nonzero queue ordinal, drain-send-failure flag, and zero.
The registry has 112-byte row headers followed by the canonical ID; the two
new row words at 96 and 104 retain queue ordinal and send-origin phase. Header
words 112/120 hold queue count/next ordinal, and 152 holds the failure flag.
The scratch ID projection at 128–144 is unchanged. Header 160–255 is zero.

Operation 13 queues one actually completed handler response and returns
disposition 12. It marks the handler done, but leaves its SDK map/token state
unchanged. Operation 14 has no generation or arguments and claims the oldest
HIA-owned ordinal. It returns PUBLISH (4), DROP (5), NO_RESPONSE (13), or
SEND_WAIT (14). While draining it waits for all previously started sends,
then permits exactly one queued response send at a time. The host never
selects a queue entry. Running-state sends remain independently outstanding.

Operation 3 remains the combined compatibility turn only when no queued
response precedes it and no drain send is pending. A completed send failure
from a request claimed during drain forces close; a failure from a send
already started in the main loop does not. These are the two separate paths
in the retained current SDK service source. DRAIN_PROGRESS also waits for
queued responses unless the actual deadline or drain-send failure closes it.
Closed queued responses are dropped in FIFO order before row retirement.

The 110 original conversations and their original case-generating functions
are retained. Eight additional owned conversations compare EOF and explicit
cancellation with ordinary queued responses, a held old send, a held new
send, each kind of send failure, and an already-cancelled queued request.
This component still does not execute a worker or qualify a public host pump.


## Host admission operation 15

Operation 15 takes the complete current G1 HRCJR001 output, generation zero,
and the actual G2 mode before/after the uninterrupted first frontend turn.
Modes are bootstrap 0, legacy 1, inline 2, closed 3. It forwards a closed-mode
turn, treats a bootstrap request that did not enter inline mode as a bootstrap
reply, admits other requests through the original typed-ID admission, and
observes notifications only after the bootstrap mode. Disposition 15 means
bootstrap; 16 means forward-only. All older operations and the 34 unmodified
function ASTs remain identified in the admission composition proof.

The host does not read another public input between that first frontend turn
and this admission. This is a concrete current seam, not a claim that every
possible handler context is created at an identical instruction boundary.
G2 peer/protocol information is never used as an identity credential. The
current pending and observation ABI is runtime_mcp_task_host_abi.md.

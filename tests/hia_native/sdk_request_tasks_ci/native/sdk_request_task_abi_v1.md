# Current SDK request-task registry

This owner implements the incoming-request cancellation map and response claim
rules from RMCP 3.9.0 `src/service.rs::serve_inner`. It is a private component;
public JSON cannot select its operations, connection generation, task generation,
worker tag, job or clock. The source manifest binds the complete original files.
This first component does not implement outgoing requests, subscriptions,
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

`HRTKRQ01` is a 64-byte header of little-endian u64 words: magic, operation,
connection generation, request generation, argument 0, argument 1, payload bytes,
reserved zero. The complete input is the header followed by exactly the payload.
Generations are nonzero, process-private values. One workspace is one connection.
ADMIT allocates monotonic request generations and refuses wraparound.

| Operation | Input | Decision |
| --- | --- | --- |
| 1 ADMIT | G1 `HRCJR001` request payload; other controls zero | Store typed canonical ID and create one live handler |
| 2 NOTIFICATION | G1 `HRCJR001` notification payload | Select cancellation by typed request ID, or forward-only notification |
| 3 HANDLER_RESPONSE | Request generation | Mark handler complete and claim its response by the SDK's ID map |
| 4 SEND_ACK | Request generation; argument 0 is actual success 0/1 | Retire one pending response send; success does not alter cancellation policy |
| 5 HANDLER_DROPPED | Request generation | Retire handler interest after actual cancellation, without a response |
| 6 BEGIN_DRAIN | Argument 0: EOF=1, service cancel=2; argument 1: observed monotonic ns | Begin the corresponding bounded drain |
| 7 DRAIN_PROGRESS | Argument 0: observed monotonic ns | Close only after all handlers/sends drain or the actual deadline passes |
| 8 RETIRE | Request generation | Remove storage only when map, handler, send and cancellation delivery are drained |
| 9 ATTACH_CALLER | Request generation; arguments: runtime tag, observed job | Attach the independently allocated private worker caller |
| 10 NEXT_CANCEL | No extra arguments | Borrow the next undelivered cancellation decision in task order |
| 11 CANCEL_ACK | Request generation | Acknowledge its actual host cancellation delivery |
| 12 INSPECT | Request generation, or zero for connection totals | Read owned state without changing sequence |

No operation starts or polls a worker. The host sends Bellman command 3 only
after a registry cancellation decision and acknowledges only after that real
turn is delivered. It never uses an MCP ID as a private worker tag.

## Private output and storage

Successful entry return is 160 and the complete output is 160 bytes,
`HRTKRS01`, followed by: disposition, connection generation, selected request
generation, runtime tag, job, flags, phase, live map count, handler count,
pending send count, record count, workspace used, drain reason, deadline ns,
loop-token cancelled, outer-service-token cancelled, event sequence, zero, zero.

Flags are live map=1, context cancelled=2, handler done=4, response seen=8,
send pending=16, cancellation delivery pending=32. Phases are running=0,
draining=1 and closed=2. Dispositions are OK=0, admitted=1, cancelled=2,
cancel no-op=3, publish=4, drop=5, drain wait=6, closed=7, retired=8,
no cancel event=9, cancel event=10 and other notification=11.

`0xffffffd0` returns the existing complete 32-byte `HGRWS002` growth frame.
Growth happens before the affected admission or decision commits. Invalid
private input is `0xffffffff`; an unavailable lifecycle transition is
`0xfffffff8`. None of these values is an invented public business error.

The workspace starts with a 256-byte header/scratch area. Packed task records
have a 96-byte fixed part followed by their canonical ID bytes, padded to eight
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

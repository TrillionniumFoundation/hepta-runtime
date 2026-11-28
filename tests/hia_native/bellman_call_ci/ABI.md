# Private Bellman callable continuation

This component joins the qualified typed parameter decoder, complete serde
diagnostics, and the shared real Bellman worker. It is not yet a public MCP
route. Public request identity, session authority, cancellation notification
dispatch and the final MCP result constructor belong to the enclosing frontend.

All words are unsigned little-endian 64-bit integers. Every span is complete;
there is no truncation, implicit length cap, substituted completion or alternate
solver. The native entry uses the ordinary three borrowed-buffer HIA ABI.

## Input

`HBLCLQ01`, command, private tag, JSON length, four zero words, then canonical
`serde_json::Value` bytes. The header is 64 bytes. Command 1 starts a call;
commands 2 and 3 poll and cancel, respectively, with no JSON payload. Tags are
nonzero, allocated by the enclosing private bridge, globally distinct across
active callers, and strictly increasing when one caller workspace is reused.
They are never copied from public MCP request identifiers or peer information.

The enclosing bridge owns immutable input bytes throughout a continuation and
all capacity retries. The caller copies the complete initial request into its
owned arena before calling the parameter decoder. Once that copy exists,
every start continuation compares the entire input against the owned copy.
The exact original HBLPAR01 input is retained for diagnostic string spans.
Malformed typed parameters are fully diagnosed before the shared worker is
called. Valid typed parameters enter worker admission before numerical limits
are checked, including empty and over-limit state vectors.

## Result

`HBLCLR01`, status, private tag, private job, text length, three zero words,
then the entire text. The entry returns 64; the complete result extent is
64 plus the text length. Status 0 is the worker's complete JSON string;
status 1 is the exact `failed to deserialize parameters: ` prefix followed by
the complete serde error; status 2 is the exact business error string. The
public frontend must turn status 1 into an invalid-params protocol error and
status 0/2 into the target SDK's normal/error text CallToolResult constructor.

Status 3 means the actual admitted worker is pending and has no public result.
Status 4 means the caller has dropped its result interest. Neither emits a
public success or business error. A pending caller may be polled or cancelled
only after the preceding control continuation, including delivery and growth,
has completed. The worker keeps its own copied graph and its permit after
cancellation until the computation, canonical commitment and result rendering
have completed. Cancellation does not kill or prematurely release the worker.

Private ABI and resource failures stay private. Unknown worker return codes
are not converted into business errors or successful empty results. The owner
must tear down a failed private continuation; it must not repeat an admitted
worker command on the assumption that an error means no effect occurred.

## Child action

Return `0xfffffff0` suspends the caller at the 112-byte action at workspace
offset 256. Its words are magic `HBLCAC01`, sequence, target, delivery mode,
input offset, input extent, output offset, output capacity, acknowledged
sequence, bridge return code, zero, zero, complete reply extent, zero.
Targets 0 and 1 are the qualified parameter and diagnostic callable adapters.
Target 2 is the one persistent shared worker, initialized once for the runtime.
The target-2 input is the complete 64-byte HBWKRQ01 header plus any graph.
The fixed bridge only owns buffers, dispatches commands, and demultiplexes
complete HBPMSR01 event frames by event kind, private tag and job. All READY
events are retained. It never creates a fresh two-permit pool for each call.

For a completed child, the bridge acknowledges the exact sequence and writes
the complete reply. The bridge return code and complete reply extent are both
the complete frame length; the worker's own raw return code remains untouched
inside HBPMSR01. If a completed reply does not fit, the bridge acknowledges
`0xffffffcd` with the required complete extent and retains the reply. The
caller requests owned workspace growth and reissues the same sequence with
delivery mode 1. That mode copies the retained reply only. It must never
repeat parameter execution, worker admission, cancellation or result TAKE.

The caller rejects mismatched acknowledgements, input/output descriptors,
tags, jobs, reply kinds, reserved words and malformed frame lengths before
using a reply. A worker submission is issued once. Once POLL reports READY,
the caller issues TAKE once and delivers its full retained result through any
number of capacity retries.

## Capacity and state

`0xffffffd0` returns the standard 32-byte `HGRWS002` request: magic, kind,
required capacity, zero. Kind 1 grows the caller workspace; kind 2 grows the
output buffer. Growth preserves every old byte and is admitted only for the
requested buffer and extent. A buffer shorter than the 32-byte growth frame
returns `0xfffffffe`. Invalid input returns `0xffffffff` before executing any
child. The caller starts with a zero workspace of at least 4096 bytes and a
64-byte output; its arena begins at 4096. Five owned regions hold child input,
child output, the original request, typed graph/error descriptor, and final
text. Live offsets are always read again after growth.

The two child adapters preserve every qualified decoder function graph,
renaming only function and direct-call targets. They convert only the two
qualified capacity statuses to HGRWS002. Their complete successful typed
graphs, diagnostics, refusal codes and diagnostic precedence remain intact.

## Actual timing

The worker HBWKBOD1 word at offset 88 is the absolute monotonic time at which
the result elapsed duration was sampled. It lies between the actual BEGIN
time at offset 40 and completion time at offset 48. Offset 56 contains the
exact Rust-compatible f64 conversion of sample minus BEGIN. The 30-second
deadline begins at actual BEGIN; queue waiting does not reset or consume it.
The caller neither invents elapsed durations nor rechecks the deadline after
the target's last checked operation.
An error before result rendering has no elapsed sample: both the sample and
elapsed f64 bits remain zero. Its actual BEGIN and completion times remain
recorded. It is not rejected for lacking a success-only elapsed observation.

## Qualification scope

The frozen domain includes all 683 original canonical parameter cases,
including all three complete Unicode-scalar diagnostics, private header and
acknowledgement controls, capacity retries, repeated contexts, and real shared
pool admission/cancellation. The worker is always real and persistent within
each process group. Retained byte streams and complete input/output/workspace
buffers are evidence; tests never synthesize solver or lifecycle success.
Original and native physical elapsed times differ. Only the documented
`native_operation_wall_seconds` field may be removed for cross-process result
comparison; its actual bounds and exact intra-process serialization are
checked separately. No public/whole-runtime qualification follows merely
from this private composition.

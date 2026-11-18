# ServerMessage owner ABI v2

This fixed component has completed finite normalization, actual owned factory,
private continuation controls, the exact 8 MiB input boundary, complete retained
data admission and full evidence archival. Its bytes and callable ABI are the same
as the earlier core handoff. It is not a production or complete Worker qualification.

Actual normalizer job 1a1eb3e9d74-392-42fd matched 6,441 Original requests.
Actual callable job 1a1eb4113c6-392-4301 built the 15-image graph with 10 exact
parent images. Factory job 1a1eb463e1e-392-4306 compared 90 fresh Original wire
requests and ran 308 actual owned lifecycles in each of two Native scheduler
modes, including InitializeResult. There were 770 actual typed callbacks and
7,225 HIA entries per mode. Actual Native ownership is tested; an Original
ownership fixture for these typed owners is not yet paired.

Earlier failures remain immutable. Standalone build job
1a1eb0dfca7-392-42cd remains UNKNOWN and contributes no qualification. The five
module owner extension and its callable build are distinct completed attempts.

## Entry and effects

Actual SysV export:
server_message_call(input, input_length, output, output_capacity, counts48) -> u32.

Counts are physical owner, typed-controller, parser, emitter, ValueLease-create,
and reserved-zero words. They never select a business result.

The fixed broker invokes HIA, owns arenas, and creates the requested immutable
ValueLease. All typed choice, defaults, wire construction, capacity decisions
and projections are HIA. Invalid is 0xffffffff, capacity is 0xfffffffe,
continuation effect is 0xfffffff0. No Rust is used by the native graph.

## Input

The private 96-byte header is followed by exact body bytes and exact ID bytes.
All fields are little-endian u64.

| Offset | Meaning |
| --- | --- |
| 0 | HSSMQ001 |
| 8 | operation: 1 decode complete ServerJsonRpcMessage; 2 construct selected typed message |
| 16 | mode: 1 projection; 2 real owned ValueLease |
| 24 | message kind for construction: 1 Request, 2 Response, 3 Notification, 4 Error; zero for decode |
| 32 | selected variant for construction; zero for decode |
| 40 | body byte length |
| 48 | ID JSON byte length |
| 56 | legacy resultType removal flag, only construction of Response |
| 64 | same-thread SC cookie in owned mode; zero in projection mode |
| 72 | fresh positive ValueLease generation in owned mode; zero in projection mode |
| 80..95 | zero |
| 96 | exact body, followed immediately by exact ID |

The complete private input is at most 16 MiB. Each body and ID is at most 8 MiB.
Decode requires kind, variant, ID length and legacy to be zero. Request and
Response construction require an ID; Notification forbids it. Error accepts
absent ID or actual JSON null for None. Other ID forms execute the same real
NumberOrString typed owner, including its bounded signed integer rule.

Request variant order: Ping, CreateMessage, ListRoots, Elicit, Custom (1..5).
Response order: Discover, Initialize, Complete, GetPrompt, ListPrompts,
ListResources, ListResourceTemplates, ReadResource, SubscriptionsListen,
ListTools, Elicit, CreateTask, GetTask, CallTool, InputRequired, TaskAck,
Empty, Custom (1..18).
Notification order: Cancelled, Progress, LoggingMessage, ResourceUpdated,
ResourceListChanged, ToolListChanged, PromptListChanged,
SubscriptionsAcknowledged, TaskStatus, Custom (1..10).
Error has variant 1.

Operation 2 reads the actual selected Request/Notification/Result/ErrorData
from the body. The HIA constructor adds the exact JsonRpc envelope and typed ID.
It never accepts pre-serialized host-generated business envelopes.

## Projection

Success in mode 1 returns HSSMP001, a 128-byte header plus one complete wire.
Minimum output is 128 bytes; maximum is the unchanged 64 MiB profile.

| Offset | Meaning |
| --- | --- |
| 0 | HSSMP001 |
| 8 | kind 1..4 as above |
| 16 | variant |
| 24 | complete wire length |
| 32 | wire offset, 128 |
| 40 / 48 | canonical JSON ID offset / length, or both zero |
| 56 / 64 | canonical quoted method offset / length, or both zero |
| 72 / 80 | params, result or error offset / length, or both zero |
| 88 | input operation 1 or 2 |
| 96 | actual legacy flag |
| 104..127 | zero |
| 128 | complete exact typed JSON wire |

All nonzero member offsets alias the complete wire. No member is duplicated.
Method is canonical JSON string bytes, not an unescaped UTF-8 span. Consumers
must use the kind/variant or an actual HIA string decoder where raw text is
needed. Members are immutable and may overlap other declared spans by containment.

Decode directly matches serde_json::from_slice<ServerJsonRpcMessage>.
It does not silently strip a transport BOM. The upstream transport owns that
separate behavior. Construct matches actual selected typed constructors.
Exact Serde diagnostic text is not yet qualified by this owner.

## Owned receipt and payload

Mode 2 requires output capacity 64. It creates exactly one real ValueLease
after validation and capacity checks. It has no optional HTTP Parts child.

The 64-byte HSSMR001 receipt has kind at 8, variant at 16, actual ValueLease at
24, projection length at 32, input operation at 40, legacy flag at 48, zero at 56.
The descriptor and entire copied payload become read-only before the call returns.

Payload HSSMV001 is 32 bytes followed by the complete projection:
projection length at 8, kind at 16, variant at 24. The original input, temporary
typed tree and all call arenas can then retire. No raw caller pointers survive.

## Destruction

server_message_drop_entry(SC, actual_payload, payload_length, generation,
actual_descriptor) is the fixed ValueLease callback. Observer type 12 is reserved.
It validates exact same-thread SC, generation, descriptor, callback identity and
payload span before asking HIA to approve destruction. HIA returns the standard
HRTDR001 terminal record with type 12. The existing ValueLease custody unmaps
storage only after the typed callback completes. No child ownership is invented.

The 96-byte HSSMD001 HIA input carries descriptor at 8, generation at 16, SC at
24, full payload length at 32, zero at 40..63 and the actual 32-byte payload
prefix at 64..95. The payload is never copied in full just to destroy it.
The fixed prefix validates the actual complete descriptor before this narrow
borrow is formed.

## Layout and continuation

Owner scratch is the existing 256 MiB profile; minimum authoring contract
is 192 MiB. Input snapshot starts at 4096. Child query starts at 17 MiB,
body reply at 26 MiB (64 MiB capacity), ID reply at 90 MiB (16 MiB capacity).
Owned prefix starts at 106 MiB; projection follows at +32.

HSSMA001 actions use the existing 128-byte pattern at scratch 512, exact shadow
640. Kind/sequence 1 is complete/body typed normalization, 2 is ID normalization,
3 is actual ValueLease creation. The first 80 action bytes are immutable.
Completion at +80 is one, +88 is actual code, +96 is actual length; +104..127 zero.
The same immutable private input is compared again on every continuation.
No synthetic completion qualifies a physical creation or Drop.

The typed child owns a separate private 256 MiB workspace. Its controller,
parser/schema and emitter share that one child workspace and the identical
40-byte HSSVQ001 query. The broker never changes the query between these stages.

This component does not modify SC+640, does not add Timer and does not merge any
root-owned Timer/Handle prefix. Runtime, HTTP session, worker, full production
and Rust-removal claims remain false.

## Mechanical integration

Append server_message_callable_v1.S to the existing matching fixed prefix; do not
copy this component's ten parent modules into a graph that already owns them.
Keep the one existing SC and ValueLease implementation. The source introduces no
global slot and reads the existing SC typed observer at +640 through td_observe.
It does not change any Timer fields. Observer type 12 is exclusive to this value.

| Relocation label | Actual manifest role |
| --- | --- |
| server_message_owner_policy_call_displacement | server-message-owner |
| server_message_drop_policy_call_displacement | server-message-drop |
| server_message_typed_policy_call_displacement | server-message |
| server_message_schema_policy_call_displacement | server-message-schema |
| server_message_emitter_policy_call_displacement | server-message-emitter |

Each relocation is the four-byte displacement of its fixed rel32 call. Recompute
against the final image layout and verify the surrounding call opcode. The two
new callable exports are server_message_call and server_message_drop_entry.
Existing helper symbols are cbg_enter/cbg_leave, cdf_allocate/cdf_unmap/cdf_fatal,
scs_validate, vl_validate, value_lease_create, td_observe and TD_RESPONSE. Their
original ownership and same-thread validation contracts remain authoritative.

The actual component builder preserves the complete parent adapter bytes and all
parent export offsets, checks all image/source/compiler pins, performs three HIA
pack calls and compares the assembled complete ELF byte for byte. Its qualification
carrier is not an alternative implementation of message semantics. New parent
compositions must perform their own matching-prefix and relocation checks.


## Final finite evidence and limits

The final semantic graph is unchanged: five ServerMessage images and ten exact
parent images in the standalone 15-image callable. Actual normalizer comparison
has 6,441 Original requests and 25,211 HIA entries. The separate factory domain
has 90 actual Original wire requests, 308 actual owned lifecycles in each Native
scheduler mode, 770 typed callbacks and 7,225 HIA entries per mode.

Actual private job 1a1ebb919e8-392-4357 made 698 HIA entries, including 601 full
immutable refusals and nine real pure-child calls. Three ValueLease completion
acknowledgements are synthetic private protocol controls; they are not physical
ownership callbacks.

Actual boundary job 1a1eb8863ba-392-4339 used exactly 8,388,608 input bytes.
Original and Native wire both contain 31,876,198 bytes; the aliasing projection
contains 31,876,326 bytes and the immutable owned payload 31,876,358 bytes.
The actual factory and typed Drop completed. The full input, output, payload,
physical call sequence and typed observer trace are retained.

Data-only jobs 4373, 4374, 437b and final 4382 rebuilt complete historical raw
captures and checked source, Original package/toolchain, compile and pack
receipts. Final gate 1a1ebef3fac-392-4382 checked 9,024 pinned inputs,
2,152,496,961 bytes, and 22 in-memory evidence mutations followed by complete
restoration. It started no Original process, entered no Native image and
performed no compilation.

The complete archive job 1a1ebf485f5-392-4389 verified every member byte, mode,
owner, nanosecond mtime, extended attribute and hardlink, then rechecked every
source. The final handoff pins that archive, the exact final result and actual
external completion receipt. The final ABI and handoff are separately pinned
completion documents written after that immutable archive.

Factory ownership is actual Native ownership. This factory domain compares real
Original wire serialization; it does not by itself compare Original ownership.
Actual Rust ownership for Worker72 and Handle Initialize40 is admitted in the
separate Worker/Initialize/LocalError bundle. The archive records those scopes
separately and does not add their calls to the factory totals.

Mapping and FD balance are bound to the completed immutable fixture assertions.
The original factory did not capture raw maps/FD snapshots, so retained admission
does not claim an independent reconstruction of those unrecorded snapshots.
Serde diagnostic text, arbitrary threaded ownership, the full HTTP/session/Worker
execution path, production activation and whole-runtime replacement remain open.

Data checker attempt 4378 failed because the observer reports ID length for an
ID-deserialization error while that checker assumed body length. Its original
source, failure and logs remain intact; the correction changed only that check.
The unfinished historical job 1a1eb0dfca7-392-42cd remains UNKNOWN. No later
successful build or archive supplies a terminal state for that job.

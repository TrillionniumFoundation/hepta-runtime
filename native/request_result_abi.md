# Request result identity, acknowledgement and final budget

This HIA owner ports the original eligible/exposes_identity, identity_value,
attach_identity, reserve_final_wire, attach_ack and the server's completion
and retention-candidate decisions. Input is the canonical Value projection
of an admitted SDK typed response before transport normalization. It does
not parse untrusted SDK types or allocate server request identities. Audit
storage, result storage and public activation remain unqualified here.

## Input

The 96-byte header starts with `HRPRQ001`, followed by eleven little-endian
u64 fields: operation (1 identity, 2 reserve, 3 acknowledgement, 4 classify),
tag (1 Complete, 2 ErrorData, 3 opaque non-Complete), tool byte length,
request-identity byte length, acknowledgement-state byte length, body byte
length, audit-durable flag, cancellation observation, visible flag,
read-only flag and zero. Flags must be 0 or 1. Tool, identity, state and body
bytes follow in that order. Prefix strings are UTF-8. There is no padding
or trailing data. The server request identity is not the JSON-RPC ID.

The frame limit is 16 MiB. The Value child retains its 8 MiB body and
depth-127 profile. A preview exceeding the typed child's 8 MiB body limit
returns CAPACITY, not the original business-level budget error.

## Persistent invocation and fixed children

Workspace is 192 MiB. Zero its first 512 bytes once, then preserve it through
each operation. CALL is `0xfffffff0`, INVALID `0xffffffff`, CAPACITY
`0xfffffffe`; success returns output length. Refusal leaves output untouched.

CALL exposes a 96-byte action at workspace offset 256: `HRPRA001` then
eleven u64 fields: sequence, child ID, zero, request offset, request length,
reply offset, reply capacity, acknowledgement sequence, actual completion
status/byte length, zero and zero. The completion fields are initially zero.
Invoke only that fixed child, copy its complete reply and publish its actual
status with the same sequence. The original input and buffer lengths must
be unchanged when resuming.

| Child | Fixed source | Request |
|---:|---|---|
| 1 | `native/serde_json.hepta` | `HSJVAL01`, op 1, length, body |
| 2 | `native/typed_result_json.hepta` | `HRTYP001`, Complete tag 1, length, preview |

The request starts at 16 MiB + 8192; reply at 32 MiB + 16384, with capacity
64 MiB. Value uses its 256 MiB workspace, typed serialization its 96 MiB
workspace. Child 1 always executes and must return the exact original
canonical body. Child 2 executes only for Complete budget previews. Each
call has a new sequence. The original input, child request header/payload,
action fields and declared buffer lengths are rechecked. Invalid/capacity
child statuses propagate; they do not produce a successful budget decision.

## Result and semantics

The 64-byte result header is `HRPRS001`, then seven u64 fields: output tag,
body length, eligible, identity exposure, completion category, retention
candidate, budget refusal. Canonical body bytes follow. Completion is
1 completed, 2 failed, 3 unknown. These flags are not durable storage receipts.

Original server.rs observes cancellation twice, independently for completion
and retention. The real caller must preserve those two observations and
select the corresponding field from each; this operation does not authorize
collapsing them into one assumed state.

Budget preview uses exact SDK typed bytes after the original acknowledgement:
256 KiB for effective_config, 64 KiB for the four request-control methods.
Binary32 annotation formatting is included. Within budget, the canonical
body is unchanged. Over-budget Complete becomes the original same-identity
internal error. Opaque non-Complete responses are neither serialized nor
modified by this owner.

## Actual evidence

Fresh ai395 job `1a1de11f1c3-392-22b7` passed with Rust 1.95 and unchanged
original blocks and locked dependencies: 1,926 complete comparisons, 44
original budget probes, 4,702 native entries, 1,966 Value calls, 762 typed
serializer calls and 49 controls. The probes include 7 priorities across
6 content forms below/at/above both budgets, plus prior collision probes.
Total qualification time was 65.01 seconds.

Earlier v2 Rust fixture, v3 invalid Task fixture and v4 observer-guard
failures remain in v5 evidence. v5 passed its earlier domain but did not
qualify typed-f32 budget boundaries; v6 supplies that behavior. No storage,
production-handler or old-stack-removal flag changes from these results.

# Native retained-result Record conversion

`request_retention.hepta` implements the original pure Record construction and
completion transition from `request_results.rs`. The source SHA256 is
`f6b7a81ea874cabf142332907fb9c3e9c1fb92a6494772a4611fec252e312bf6`.
Its 27 functions include five exact relocated HIA functions. The native owner
uses the common borrowed-byte ABI, with a 256 MiB private workspace.

The caller must already own the original validated request identity, policy
binding and storage intent. This private component does not acquire those
capabilities, publish files, record an audit event, or make a tool public.
Neither a successful conversion nor a `stored` Record proves durable storage.

## Input

All integer fields below are unsigned little-endian u64. The input starts with
96 bytes, followed by tool, request ID, owner ID, policy binding and body bytes.

| Offset | Field |
|---|---|
| 0 | ASCII `HRRTQ001` |
| 8 | Operation: 1 creates the unknown Record; 2 completes an intent |
| 16 | Result present: 0 or 1 |
| 24, 32 | Low and high halves of the original u128 acceptance timestamp |
| 40 | Tool byte length |
| 48, 56, 64 | Request ID, owner ID and policy binding lengths; each exactly 64 |
| 72 | Body byte length |
| 80, 88 | Reserved; zero |

Tools are exactly `host_list`, `host_health` and `effective_config`. Each identity
is 64 lowercase hexadecimal ASCII bytes. The body, if present, is the actual
canonical Value serialization of an admitted typed complete `CallToolResult`,
bounded to 8 MiB. Operation 1 requires an absent body. ErrorData and task results
are not admitted by this private input contract. Presence of `structuredContent`
with a null value remains distinct from absence.

## Native child graph

The owner returns `0xfffffff0` when it requires a child. It issues at most seven
child operations for a stored result:

1. Real `serde_json.hepta` canonicalization validates the admitted body bytes.
2. Real `typed_result_json.hepta` produces original SDK field order and exact
   binary32 annotation formatting.
3. Real `request_result.hepta` attaches the original `stored`, audit-false ack
   to a private preview.
4. Real typed serialization measures that preview's actual wire bytes.
5. Real `request_safe_dto.hepta` checks the original identity marker, DTO shape
   and installed configuration through its configuration child.
6. Real `binary_codec.hepta` hashes the original typed result bytes.
7. Real binary codec Base64 encodes those same bytes.

The input is immutable across resumptions. A private snapshot is compared on
every continuation. The action descriptor, sequence, capacities, child selection
and child request bytes are also checked; the sequence never wraps. The original
typed output exceeding 65,536 bytes immediately produces overflow. This is an
equivalent pure short circuit of the original disjunction: either the original
or acknowledgement preview exceeding 65,536 bytes produces overflow, before DTO
admission is considered. No storage or audit work is skipped by this component,
because those effects are outside its contract.

The 96-byte action at workspace offset 256 starts with `HRRTA001`, followed by
sequence, child ID, zero, request offset, request length, reply offset, reply
capacity, acknowledgement sequence, result code, zero and zero. Child IDs 1–5
are Value, typed serializer, metadata owner, DTO owner and codec respectively.
The request offset is 167,837,696, reply offset 184,614,912 and reply capacity
67,108,864 bytes. Only the trusted child dispatcher fills the acknowledgement
sequence, result code and reply region after executing the selected HIA child.

## Output

`HRRTR001` is followed by state number, Record byte length and original payload
byte length, then the exact original compact Record JSON bytes. A 98,336-byte
output buffer covers the admitted record bound. The state number distinguishes
the internal serialized Record state from the original completion return value:

| State | Record state | Original completion result |
|---|---|---|
| 0 | `unknown` | Admission only |
| 1 | `stored` | `stored` |
| 2 | `overflow` | `overflow` |
| 3 | `refused_dto` | `not_retained_dto` |
| 4 | `not_completed` | `not_completed` |

The Record field order is request ID, owner, tool name, acceptance timestamp,
policy binding, state, Base64 payload, payload length and SHA256. The acceptance
timestamp is rendered as a full exact u128 decimal, including `2^128 - 1`.
The three payload fields are null for every state except `stored`. Stored bytes
are the original typed result before the retention acknowledgement and transport
normalization. Metadata and identity are not regenerated from Python values.

Malformed private frames return `0xffffffff`; insufficient capacity returns
`0xfffffffe`. Output is written only on successful completion. A child capacity
failure resets the active phase and propagates capacity. Malformed continuation
state is a refusal; the trusted owner must retire or explicitly reset that
private transaction before using its workspace for another one.

## Actual qualification

The fixed compiler is Hepta commit
`d3e2c90173cf733e42b299d0c4274df4b593a12f`, with B3 SHA256
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
The fresh qualification compiles all 18 HIA images, including the complete
11-image configuration graph and its native HIA packer. It builds the reference
with Rust 1.95.0, the original 100 locked registry packages and all 175 pinned
rmcp SDK source files. Sixteen original source blocks are retained byte for byte;
the entire original configuration and effective-configuration modules are used.

Actual job `1a1de5d3fd5-392-23a0` completed with exit 0 and complete durable logs.
All 6,287 compared Records matched exactly: 1,580 stored, 191 overflow, 4,060 DTO
refusals, 228 not completed and 228 unknown. The 28 independent summary/size
observations make 6,315 actual original requests. These are distinct counts,
not extra semantic comparison cases. There were 71,230 actual owner/metadata/DTO
native entries and 5,145 actual configuration process requests. Forty-two private
frame, capacity, action-custody and child-response controls passed. The empty-host
configuration was separately rejected by both real startup implementations.

Coverage includes all u128 limb boundaries, 512 deterministic random timestamps
and identity bindings, original binary32 annotation sizes at both 64 KiB
thresholds, an exact 8 MiB canonical input, installed/uninstalled configurations
and 256/257-host profiles. Comparison took 57.42 seconds; fresh qualification took
79.50 seconds. The first attempt's oracle formatting failure is retained as a
failure. It contributed no native or original semantic comparison claims.

Descriptor validation, per-record concurrency, archive initialization, file
publication, audit durability and public dispatch remain outside this qualified
pure conversion. Their closure flags remain false.

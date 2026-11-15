# Retained Record identity and integrity validation

`request_record_validation.hepta` owns the byte validation in the original
`request_results.rs::read_record` after its descriptor checks and bounded read.
It validates the retained filename, exact original typed Record, identity binding,
state/payload consistency, canonical Base64, payload length and SHA256. All these
operations execute in HIA-produced machine code. The original Rust reference is
qualification code only.

The caller must perform the original staging recovery, file opening, owner/mode/
link-count checks and bounded read before calling this component. This component
does not perform those filesystem operations, admission, audit authorization,
locking, archive anchoring or publication. It does not qualify a production MCP
handler or authorize removing the old runtime. Exact serde error text and source
locations are not yet part of this private projection: JSON failure is diagnostic
2, and a public error adapter must preserve the eventual public contract.

## Entry and custody

Entry `f0` has `(readbuf, mutbuf, mutbuf) -> u32`. The three spans are disjoint. The
caller provides at least 4 MiB workspace and starts a new session with zeroed
workspace. The session retains its sequence number across completed requests.
The input, output capacity and workspace capacity cannot change while suspended.
The native owner snapshots input and the complete issued child request and checks
both again on resume; action metadata, acknowledgement sequence and reserved
fields must match. Sequence overflow is refused rather than wrapped.

| Request offset | Value |
|---|---|
| 0 | Eight ASCII bytes `HRRCQ001` |
| 8 | Filename byte length, u64 little endian |
| 16 | Raw JSON byte length, u64 little endian |
| 24 | Filename bytes followed immediately by the raw JSON |

The private frame is at most 1 MiB and must have exact lengths. A valid retained
filename is 64 lowercase ASCII hexadecimal digits followed by `.json`. A valid
filename with more than 98,304 JSON bytes produces original size diagnostic 8.
The type parser retains the original struct map/sequence and enum forms, u128
acceptance time, exact u64/usize fields, Unicode decoding, duplicate/unknown-field
rejections, and nullable/omitted optional fields.

A valid Record has lowercase hexadecimal request ID, owner and policy binding,
each 64 bytes; its tool is exactly `host_list`, `host_health` or `effective_config`.
The request ID must match the filename. For `stored`, Base64 must be present and
canonical, decode to at most 65,536 bytes, and match both present payload length
and the lowercase SHA256 digest. Empty payload is valid with its exact digest.
For every other valid state all three payload fields must be absent or null.

## Result

A successful private invocation returns its complete output length. A normal
original validation refusal is a 32-byte result with zero data lengths.

| Output offset | Value |
|---|---|
| 0 | Eight ASCII bytes `HRRCV001` |
| 8 | Diagnostic code, u64 little endian; 0 means valid |
| 16 | Typed projection byte length |
| 24 | Decoded stored payload byte length |
| 32 | Complete `HRSTJ001` Record projection, followed by decoded payload |

The typed projection is exactly the one documented in
`request_storage_json_abi.md`. Its fixed canonical placement lets a future owner
compare every typed Record field without confusing JSON field order or escaped
spellings with semantic equality. This component does not itself compare an old
and new receipt or decide whether replacement is permitted.

| Diagnostic | Original validation category |
|---|---|
| 1 | `invalid retained result filename` |
| 2 | Original typed JSON deserialization failed; no exact error string claim |
| 3 | `request audit metadata identity refused` |
| 4 | `retained result refused` |
| 5 | `retained bytes refused` |
| 6 | `retained result integrity refused` |
| 7 | `retained result state refused` |
| 8 | `request audit metadata size refused` |

`0xffffffff` is an invalid private frame/state/child contract;
`0xfffffffe` is insufficient capacity. Neither publishes partial output.
`0xfffffff0` is a private pending call consumed only by the trusted caller.

## Native child calls

The 96-byte action at workspace offset 256 uses twelve u64 words, with word 0
holding ASCII `HRVLA001`. Remaining words are sequence, child ID, zero, request
offset, request length, reply offset, reply capacity, acknowledgement sequence,
child result, zero, zero. An issued action leaves acknowledgement/result zero.
The caller invokes the real native child, writes only its reply span and those
two completion words, then resumes the unchanged parent input. It cannot replace
these native operations with a host-language semantic implementation.

| Child | Request | Operation |
|---|---|---|
| 1 | `HRSTQ001`, kind 1 | Exact original Record type projection |
| 2 | `HRCODEC1`, operation 10 | Canonical Base64 decode |
| 2 | `HRCODEC1`, operation 2 | SHA256 as lowercase hexadecimal |

The maximum is three calls. Non-stored records use only the type child. Child
request/reply/custody-copy offsets are 1,114,112 / 2,162,688 / 3,211,264. Reply
capacity is 1 MiB. The parent independently validates the type projection layout
and digest reply alphabet/length; malformed private child replies do not become
ordinary user-data validation results. Child capacity failure remains capacity
failure.

## Actual qualification

Job `1a1de866bef-392-2428` used Rust 1.95.0 and the fixed Hepta compiler
`d3e2c90173cf733e42b299d0c4274df4b593a12f`. All 12 original source blocks remained
byte-for-byte unchanged. The 22 locked package identities/checksums were checked
against the original lockfile; 1,131 actual package archive members were checked
against the source files used for compilation. The minimal sha2/serde fixture
uses the corresponding minimal dependency features, recorded explicitly.

The fresh execution compared 9,361 original requests. Exactly 7,549 were valid;
1,812 were refused across the eight declared categories. All typed projection
bytes, decoded payload bytes and refusal classes matched. The 45 extra controls
cover frame bounds, output preservation/capacity, workspace capacity, action and
request custody, input mutation, malformed child projections, digest corruption,
capacity propagation at all phases and sequence exhaustion. The actual total is
25,814 owner entries, 9,321 typed JSON child calls and 7,086 binary codec calls.
No standalone end-to-end Record-validator process was asserted by this run: it
executes the actual native images through the declared borrowed-buffer graph.

The 6,287 prior retention outputs were input fixtures in this fresh run. Their
preparation made zero original calls; each fresh validation above is counted
once. The complete evidence archive has 131 members and SHA256
`5302f6feed04a5059307202328257795295ea6782facacae73165b872ffc8123`.
All members were checked remotely and after download. Source pins, process
receipts, unmodified original fragments, actual native and Rust images, inputs,
outputs and controls remain available in that archive.

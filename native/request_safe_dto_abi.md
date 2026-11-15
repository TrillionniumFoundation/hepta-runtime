# Native safe DTO admission

`request_safe_dto.hepta` implements the original
`safe_dto(tool, admitted_typed_complete).unwrap_or(false)` contract from
`src/mcp/runtime/request_results.rs`. Every input result is an already admitted
SDK `CallToolResult`, projected into canonical `serde_json::Value` bytes. This
private boundary does not deserialize arbitrary public SDK messages or grant
ownership of a retained result. It requires real native Value and installed
configuration children; the parent transports their requests and completions.

## Request and response

The borrowed-buffer entry returns a byte count, `0xffffffff` for a broken
private contract, `0xfffffffe` for capacity, or `0xfffffff0` for a child call.
It requires 256 MiB of private workspace and at least 32 output bytes.

| Request offset | Bytes | Meaning |
|---|---:|---|
| 0 | 8 | ASCII `HRSDQ001` |
| 8 | 8 | UTF-8 tool name byte length |
| 16 | 8 | Canonical typed result byte length |
| 24 | 8 | Reserved zero |
| 32 | Variable | Tool name followed by canonical result |

The complete frame is at most 16 MiB and the result at most 8 MiB. The separate
Value child retains its existing parsing and depth limits. A successful 32-byte
reply contains `HRSDR001`, a u64 acceptance bit, a u64 tool kind and a reserved
zero. Tool kinds are 1 `host_list`, 2 `effective_config`, 3 `host_health` and
0 for all other names. An ordinary refusal is a successful reply with bit zero;
it is distinct from malformed framing, missing capacity and invalid child
custody. Output is written only when a complete decision is available.

## Actual child sequence

The owner first calls native Value operation 1 and requires its complete
canonical output to equal the supplied typed result. It then checks original
error/structured-content exclusions, the exact request identity marker and
single plain text content shape. The text is decoded and passed to the real
Value parser. Its ordinary parse refusal becomes `false`, as the original
caller's `unwrap_or(false)` requires.

For `host_list` and `effective_config`, the owner calls installed configuration
operation 1 or 2, canonicalizes that actual response through Value and compares
the complete parsed objects before checking their exact reviewed field sets
and 256-host bound. It does not accept a caller-provided expected summary.

For `host_health`, the parsed host string is passed to private configuration
operation 10. That operation performs exact configured-name lookup, preserving
the original `runtime_config()?.host(alias)` behavior. It does not perform the
SSH-target alias search used by remote file preparation. The returned generation,
platform and complete configured name are checked before the original health
schema, status, flags, measurement, timeout and finite inclusive 0–60000 ms
range are evaluated. Canonical number magnitude is evaluated in HIA integer
operations, including signed zero and subnormal boundaries.

## Continuation custody

The 96-byte action at workspace offset 256 begins with `HRSDA001`, followed by
eleven little-endian u64 values: sequence, child, reserved zero, request offset,
request length, reply offset, reply capacity, acknowledgement sequence, returned
code, reserved zero and reserved zero. Child 1 is Value; child 2 is installed
configuration. Request and reply offsets are 167837696 and 184614912; the reply
capacity is 67108864. Sequences increase without wrapping.

The parent invokes the requested child, copies its actual response to the reply
span, writes the acknowledgement and returned code, then re-enters with the
identical original input and buffer lengths. The owner checks the complete
original frame, every fixed action field and a private copy of the complete
child request before consuming a reply. Faulted continuations must be retired
by the trusted parent. The separate control corpus deliberately mutates these
fields and never treats those synthetic callbacks as original semantic cases.

## Configuration query extension

`config_result_owner.hepta` preserves all 48 imported functions from the frozen
remote configuration owner, with exact AST equality and direct-call relocation.
Only its wrapper and platform-query function are new. Existing operations 1–9
continue through the preserved entry. Operation 10 accepts `HRCFGQ01`, u64 10,
u64 name length and the configured UTF-8 name. It uses the installed private
configuration arena and requires its trusted owner footer.

Success uses the existing `HRCFGM01` envelope with zero status and diagnostic.
Its payload is `HRCFPL01`, u64 generation 1, u64 platform 0 Linux / 1 macOS,
u64 name length and that exact name. Uninstalled and unknown-host failures use
the original error strings. This operation does not install configuration,
reload policy, open an SSH connection or authorize execution.

## Fresh observed qualification

The v2 ai395 run compiled all fourteen HIA images afresh with compiler
`d3e2c90173cf733e42b299d0c4274df4b593a12f`, compiled the actual original Rust
reference with Rust 1.95.0, and verified 100 locked registry dependencies and
all 175 pinned SDK source files. Four original function blocks and the whole
original configuration and effective-summary sources were unchanged.

It matched 5,043 typed DTO decisions and 544 exact-name platform queries, with
four additional actual original summary probes. Native execution recorded
19,398 owner entries, 9,837 Value child calls, 4,491 configuration child calls
and 5,035 total configuration-process requests. These are execution counts,
not additional independent cases. Twenty-seven private continuation controls
passed. Both actual programs also rejected the empty-host startup fixture
without creating its state directory. Every successful configured process was
reaped and its retained controller locks were verified released.

The first run's failure is retained: the fixture incorrectly placed an empty
host configuration among initialized DTO profiles. The original rejected it
before DTO execution. The v2 runner moved that same configuration into an
explicit paired startup-refusal case; both HIA production sources were unchanged.

Complete evidence contains both runs, input sources, original source proofs,
native compiler artifacts, actual reference executables, raw request/reply
corpora, child receipts and failure records. Its archive SHA-256 is
`df37c5395883e574b43df0f4d4c2d584f853408ab0e14aa3295c4c92ac840758`.
Result storage, request audit, public dispatch and whole-runtime replacement
remain unqualified by this increment.

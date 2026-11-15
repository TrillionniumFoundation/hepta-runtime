# Public HIA MCP composition

The executable accepts newline-delimited JSON-RPC on standard input. Arguments
are empty or `--runtime-config PATH`. Its working directory initializes one
private SessionWorkdir instance. Public JSON cannot choose a private child,
workspace, capability, continuation, lease, session, or descriptor table.

The catalog contains `host_list`, `effective_config`, `execution_shadow_admit`,
`view`, `workdir`, `directory_create`, `file_move`, and `directory_move`. It is a
partial replacement of the original 125-tool server. Published schemas are
independently generated and cleaned assets. Schema advertising does not
replace the original parameter-deserialization rules.

## Build and ownership

`scripts/hia_native_runtime_mcp_build.py` declares 58 compiled HIA members.
Default builds freshly compile all 58 members, the pinned upstream HIA ELF
linker, and `runtime_mcp_image_packer.hepta`. The linker first produces the
mechanical prefix. The HIA packer appends every complete image and fills 68
fixed addresses: 17 configuration, five native effect-fence, 27 nonempty public
engine, and 19 View engine entries. Repeated entries share an image and their
source-selected private authority; physical image indexes are not selectors.

`native/runtime_mcp_sources.json` binds build inputs, public input generators,
schemas, and the native producer. The evidence reader and refusal suite are
separately bound by qualification receipts, avoiding a manifest self-reference.
The ELF has RX code, an empty RW segment, and a non-executable stack, with no
interpreter or libc. Compiler cold qualification is a separate prerequisite.

The four separately named configuration span images use the same installed
configuration instance. Every borrow reads control+1024/+1032, and computes
the footer from the current capacity minus 256. The native effect-fence hub is
a separate allocation; it does not overlap that configuration control area.
Configuration installation and shutdown retain their actual lock lease.

## Private selectors

| Slot | Owner |
| --- | --- |
| 0 | Catalog |
| 1 | Metadata admission |
| 2 | View gateway |
| 3 | Complete ClientCapabilities decoding |
| 4 | View parameters |
| 5 | Session-context latch |
| 6 | Shared SessionWorkdir |
| 7 | Local path policy |
| 8 | Canonical path I/O |
| 9 | PathSource |
| 10 | Wide Serde Value |
| 11 | Installed configuration owner |
| 12 | Mechanical call into the actual View engine |
| 13 | Workdir gateway |
| 14 | Workdir parameters |
| 15 | Strict Workdir I/O |
| 16 | Workdir rendering |
| 17 | Original filesystem error text |
| 18 | MCP frontend |
| 19 | Wide JSON-RPC protocol owner |
| 20 | Installed execution controller |
| 21 | Filesystem gateway |
| 22 | Filesystem parameters |
| 23 | Filesystem caller |
| 24 | Actual filesystem effect owner |
| 25 | Filesystem result renderer |
| 26 | Directory-move configured-root guard |
| 27 | Filesystem admission and effect-fence controller |
| 28 | Mechanical call into the actual five-image fence engine |
| 29 | Borrow of this session's View scope |
| 30 | Borrow of this session's canonical cache key owner |
| 31 | Borrow of this session's cache lease owner |
| 32 | Borrow of this session's View cache |

The 19-slot View engine retains read/cache/scope/lease, literal search, and
regex search. Configuration and View reuse the same syntax, HIR, NFA, matcher,
and Unicode images. Filesystem scope and cache access borrow that same View
engine; they do not install a second cache for the public session.

A separate, explicit build option emits a private two-session fixture instead
of the public transport. It adds fixture selectors 33/34 and actual state
observations while sharing the same installed configuration and fence hub.
These selectors are absent from public JSON and public transport dispatch.
Its ABI, counter domains, raw state extents, and complete trace formats are in
`native/filesystem_public_abi.md`. A fixture's closed flag is not an observed
public BrokenPipe; the ordinary stdio executable supplies that evidence.

## Wide calls and result ownership

The frontend accepts complete raw JSON. State magic is `HRMCFS02`; its
112-byte `HRMCFA02` action begins at workspace offset 256. Lengths, offsets,
capacities, and sequence fields are u64. Eight 32-byte region rows begin at
512; arena extent, requested workspace capacity, and growth kind occupy
384, 392, and 400. Its fixed local children map to public slots
`[19, 1, 0, 10, 2, 13, 11, 20, 21]`.

Return `0xfffffff0` yields an admitted child. The bridge retains a completed
child result. If the parent needs space, `0xffffffcd` acknowledges delivery
only: growing the parent does not execute that child again. Each completed
filesystem effect is acknowledged once by its source continuation.

Successful frontend return is fixed 64 with `HRCMFR02`: magic, kind, reserved,
prefix length, body length, isError, sequence, reserved. Kind 0 is silent,
1 is raw JSON-RPC, and 2 transfers prefix/body to the actual result publisher.
Extent is 64 plus both lengths, independent of the u32 return. Publication
imports both full spans before START. PULL/write/ACK retain no borrow into a
reusable frontend buffer.

Protocol input is `HRJPRQ02` plus mode, JSON length, reserved zero, then JSON.
Output is fixed 192 with `HRJPRR02`, followed by full ID/name/version spans.
Node indexes and offsets are u64; the old 262,144-node cap is absent. The
existing nesting-depth policy of 128 remains.

The protocol first validates every unquoted JSON number, including numbers in
ignored fields, using the same finite binary64 conversion as the Value owner.
Its first preflight pass owns an isolated numeric slab at workspace offset
4352, extending through 11367. The parser stack ends at 4256 and retained tail
fields start at 13328 in the minimum 16384-byte workspace. Numeric validation
does not write output, change the existing 6320-byte minimum output request,
or expand RawValue objects in ignored fields.
Two additional cache words at offsets 11376 through 11391 retain only the
last successfully validated numeric span. Every preflight resets them; a hit
requires equal length and every original token byte to match. Failed numbers
are never cached, and intervening strings or containers do not change the
grammar or numeric validation rule.

An ordinary string or signed-i64 RequestId stays on the single protocol pass.
The locked SDK deserializes a selected RequestId through Value before applying
its String/i64 rule. For an object whose first decoded key is
`$serde_json::private::RawValue`, the protocol therefore yields a private
deferred result: return 192, `HRJPRR02`, kind 7 at offset 40, raw-ID length at
48, original-envelope length at 144, and the raw ID alone after the header.
Mode at 32 is preserved; all other fields, including offsets 152 through 184,
are zero. This result grants no public handler admission.

Frontend phases 9 and 10 call the generic Value owner for only that selected
ID, then resume the protocol with `HRJPRQ03`: mode, original-envelope length,
nonempty canonical-ID length, the exact original envelope at offset 32, and
the canonical ID immediately afterward. Total extent must match both lengths.
The original envelope remains the logical parsing bound; its method, params,
ignored fields, duplicate checks and depth checks cannot consume trailer bytes.
Resume requires the same first-key RawValue object and a canonical String or
signed-i64 value. Fractions, exponent forms, negative zero and integers outside
the signed-i64 range are not admitted as RequestId.

The SDK's typed field boundaries are preserved. Method and `params.name` are
strings; unknown struct fields remain ignored. Arguments are an optional
JsonObject, so its root is a map and only its member values deserialize as
generic Value. The full-span Value frame is `HJSVS002`; the typed-map frame is
`HJSMS002`. Both contain operation 1, a u64 JSON length, and exactly that JSON
span after the 24-byte header. The typed-map root must be an object and its own
RawValue-named key remains an ordinary map key. Inside generic Value positions,
only the first decoded object key activates RawValue; the string is decoded
and reparsed with an independent original depth budget. A later RawValue key
remains ordinary, and extra wrapper fields are rejected before publication.

Both wide frames return a fixed 32-byte `HJSVR002` header containing status,
body length and required capacity, followed by the canonical body on success.
Statuses are 0 success, 1 ordinary JSON/value refusal, 2 workspace growth,
3 output growth and 4 unrepresentable resource need. Status 5 is confined to
an inner RawValue semantic refusal from `HJSMS002` operation 1; its two length
fields are zero. The syscall bridge checks that exact originating frame before
accepting status 5. Generic Value refusal remains status 1. The legacy
`HSJVAL01` operation domain and its borrowed-buffer ABI are unchanged.

Observed SDK routing is retained: invalid typed IDs, invalid selected RawValue
IDs and unrepresentable raw JSON numbers silently discard that line while
preserving the connection. Invalid method/jsonrpc fields produce an Invalid
Request response without an ID, unless raw-number decoding has already failed.
Invalid typed call parameters and inner argument RawValue failures produce
the SDK's `-32601` / `tools/call` error with the admitted ID. These routes do
not invoke the requested filesystem handler. A following valid request still
uses the same live transport.

`HGRWS002` is a 32-byte header: magic, kind, required capacity, reserved zero.
Return is `0xffffffd0`. Kind 1 requests workspace, 2 output, and 3 denotes
an unrepresentable resource boundary. Bridges check arithmetic and real
allocation failure, preserve live bytes, and retry only a source-authorized
operation. Completed effects are delivered without replay.

Strict Workdir I/O retains its separate growth ABI. Return `0xffffffef`
requests logical C at workspace offset 40, requiring physical extent
`1,049,600 + 5*C`; `0xffffffee` requests output extent at offset 48. A terminal
RUN is followed by its actual generation-bound DROP before reuse.

Configuration op8 borrows its complete input without reserving seven copies
inside the installed-state arena. It computes the complete reply length with
checked arithmetic and requests exact output growth before writing its body.
This legacy query still reports successful complete size through a u32 return
below reserved control codes. This repair does not establish an unbounded
result channel; its explicit representation boundary remains documented.

## Qualification and unfinished domains

The native producer retains complete wire bytes, stderr, each request's
60-second deadline, and actual private-control buffers. Inputs cover 54 SDK
adapter cases, 13 information cases, 31 ordinary View calls, a 19 MB error,
a 67 MB input/output case, 262,146 JSON values, and 42 local Workdir scenarios
with 336 public calls. It does not read original results. Complete original
comparison is a separate qualification step.

Two additive suites retain 4847 full-span Value/map cases, 37 complete-buffer
capacity, refusal and recovery controls, and 94 actual public SDK-boundary
cases with 243 responses. Their evidence controls copy only admitted source
and artifact files and reject changed receipts, complete streams and domains.
Separate fresh locked Rust builds replay every Value/map input and all 94
SDK requests. The latter uses a typed SDK handler fixture to observe argument
deserialization and protocol/error behavior; its body is not represented as
the original View implementation. Existing public corpora, original reference
steps, 60-second exchange deadlines and 180-second suite limits are unchanged.

Filesystem SDK qualification is separate: complete native public and private
streams, the two actual session/cache states, filesystem observations, and
mechanical trace order must be compared with their actual original execution.
Reused original executables and fresh original builds are counted separately.
An image build or an earlier graph's passing result does not qualify a new
graph's runtime behavior.

Transport/frontend/gateway byte windows grow dynamically. Configuration and
execution retain some legacy result conventions; regex has remaining workspace
and frame profiles. Directory, remote and background View, HTTP concurrency
and cancellation, and the remaining public handlers are incomplete. SDK
fixture bodies and empty catalogs are compared only by explicit protocol and
schema projections. No evidence here claims full original catalog equivalence
or whole-runtime replacement.

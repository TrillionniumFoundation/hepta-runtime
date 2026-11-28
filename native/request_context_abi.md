# Native request context state

`request_context.hepta` implements the private hint queue and current view-cache
association from `src/mcp/request_ctx.rs` at Runtime commit
`2173a00ec314ebc0c5ada21e4cb60d8efdccb99a`. The source composition manifest binds
that complete original file, `src/mcp/server.rs`, and the unchanged HIA UTF-8 and
little-endian word helpers. The entry is
`f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`.

## Ownership and asynchronous integration

This is an internal state owner. No public request may select its workspace,
install a scope, supply a cache association, import state or destroy another
scope. The real scheduler must retain private state for the correct scoped
future and restore that state whenever the future is polled. A request ID,
session ID, task number or matching hash is not authority to select a workspace.

Tokio's original `CTX.scope` installs its context while polling a
`TaskLocalFuture`. It does not give every future in the same Tokio task one
permanently installed context. In particular, `join` or `select` can interleave
separate scoped futures in one task. Such independent branches need separate
private workspaces and scheduler-owned save/restore of the active context.
LIFO scopes on one active chain use ENTER and EXIT in one workspace. Spawning an
independent future does not inherit this state. The native state tests exercise
independent interleaved workspaces and nested restoration, but do not prove that
a production asynchronous dispatcher performs this scheduling correctly.

ENTER receives an opaque u64 cache association from the trusted dispatcher. All
u64 values, including zero, are representable. The value is an internal routing
alias, not a caller identity, memory address, authorization token or standalone
view-cache capability. The dispatcher must bind it to the correct already-owned
cache object, hold that object's lifetime across the scope and release the
reference on exit/destruction. Two private request contexts can refer to the
same session cache while retaining independent hint queues. CACHE reports only
that existing association; it performs no cache operation and grants no access.

On normal completion, failure, panic or cancellation, the scheduler must destroy
the abandoned scope and restore its enclosing scope. EXIT and DESTROY implement
the state destruction, but cannot observe a future being cancelled on their own.
These transitions must run after an in-flight synchronous HIA call has finished.
Neither this component nor a successful finite test replaces that scheduler,
the original Arc lifetime, the cache owner or the production MCP route.

## Request frame

Every request is exactly `32 + payload_length` bytes. All integers are unsigned
little-endian u64 values.

| Offset | Field |
|---|---|
| 0 | Eight ASCII bytes `HRCXQ001` |
| 8 | Operation |
| 16 | Payload byte length |
| 24 | Reserved, zero |
| 32 | Exact operation payload |

| Operation | Payload | Behavior |
|---:|---|---|
| 1 INIT | Empty | Admit a zeroed fresh private workspace; initialize an empty active owner. |
| 2 ENTER | Exactly eight bytes, private cache alias | Push a fresh empty scope; preserve the enclosing scope. |
| 3 EXIT | Empty | Clear this scope's pending hints and alias, and restore the enclosing scope. Empty-stack exit is refused. |
| 4 PUSH | A complete valid UTF-8 string | Copy the hint into the active scope. Outside all scopes it is a successful no-op. |
| 5 DRAIN | Empty | Return distinct hints in first-insertion order and clear the active queue. Outside a scope returns an empty list. |
| 6 PEEK | Empty | Return the same distinct list without clearing it. This is an extra internal preview for composition, not an original Rust API. |
| 7 CACHE | Empty | Return None outside a scope, otherwise this scope's private cache association. |
| 8 DESTROY | Empty | Clear the complete owned state and scratch span, even when private state is damaged. INIT is required before reuse. |

INIT is required before all ordinary operations. Reinitializing an active or
nonzero owner refuses rather than discarding its hints. DESTROY is a trusted
lifecycle operation that also accepts a fresh zero workspace. Malformed frames
and invalid UTF-8 refuse before touching either mutable buffer. Rust's `&str`
already provides this UTF-8 type boundary in the original API.

PUSH retains every supplied hint, including duplicates and empty strings, until
DRAIN or scope destruction. DRAIN does not normalize Unicode, CRLF, NUL bytes,
spaces or warning prefixes. It compares complete byte strings and keeps the
first appearance of each distinct value. A repeated DRAIN returns an empty
list. Nested child hints never enter the enclosing queue.

## Response frame

Every successful response is exactly `32 + payload_length` bytes.

| Offset | Field |
|---|---|
| 0 | Eight ASCII bytes `HRCXR001` |
| 8 | Tag |
| 16 | Scalar |
| 24 | Payload byte length |
| 32 | Payload |

| Tag | Scalar | Payload |
|---:|---|---|
| 0 | Zero | Empty; successful lifecycle transition or PUSH. |
| 1 | Number of distinct hints | Each hint as `u64 byte_length` followed by its exact UTF-8 bytes. No trailing bytes. |
| 3 | Zero for None, one for Some | None has empty payload. Some has exactly eight bytes of private cache alias. |

Unit responses always have zero scalar. An empty hint list has tag 1, scalar
zero and zero payload length. An actual empty string is one list entry with a
zero length word; these cases remain distinct.

The separate `response_hints.hepta` module consumes the complete list frame and
the original result bytes to implement `server.rs::append_hints`. Its formatting
contract is `result`, unchanged when the list is empty; otherwise append two
newlines followed by `⚠️ `, each hint and a newline. This state owner does not
perform that formatting. A future combined native caller must keep its private
scope stable across drain and formatting, or use PEEK to check complete output
capacity before committing DRAIN. A Python qualification adapter is not evidence
that the production caller has been connected.

## Capacity, layout and refusal semantics

The existing `standard` native module profile remains 8 MiB input, 8 MiB output
and 32 MiB workspace. No hint-count limit is introduced. Let `W` be the actual
workspace capacity and let `A` be the greatest power of two no larger than
`(W - 256) / 2`. Capacities below 512 bytes are refused. The component owns
`[0, 2A)`; all later bytes, including the last 256-byte bridge footer, are untouched.
With the standard 32 MiB workspace, `A = 8 MiB`.

The first A bytes contain a 64-byte header, 32 bytes per live scope and 16 bytes
plus the exact string length per retained hint. The second A bytes are temporary
deduplication storage. Thus one scope in a standard workspace can retain one
hint of `8 MiB - 112` bytes. More scopes or hints consume their actual additional
record bytes. A smaller native buffer can refuse earlier. The original Rust
Vec and String storage is allocator-backed and has no matching fixed arena
ceiling; this explicit finite profile is not a claim of unbounded parity.

| State header offset | Meaning |
|---|---|
| 0 | `HRCXST01` |
| 8 | Version 1 |
| 16 | A |
| 24 | Used arena end, initially 64 |
| 32 | Top frame offset, or zero |
| 40 | Live scope count |
| 48, 56 | Reserved zero |

A scope frame contains previous-frame offset, private cache alias, retained hint
count and a reserved zero word. Its following hint records contain a 64-bit FNV
index hash, byte length and complete text. A hash is only an index aid. The
temporary open-addressed table compares hash, length and all text bytes; it
does not treat equal hashes as equal hints. The table is sized to at least twice
the retained record count and cleared before every return. Draining wipes every
retired hint record. EXIT wipes the entire child frame and its records. DESTROY
wipes both owned regions, leaving the bridge tail unchanged. This is not a
claim of register erasure or whole-process memory erasure.

| Return | Meaning |
|---|---|
| `0..output_capacity` | Complete response byte length |
| `0xffffffff` | Invalid framing, operation, reserved field, payload shape or UTF-8 |
| `0xfffffffe` | Insufficient input-independent workspace, arena or output capacity |
| `0xfffffffd` | Uninitialized/damaged private state, repeat initialization, empty-stack exit or contaminated scratch |

For a valid private state, refusal preserves both the output and the complete
workspace. Output capacity is checked before semantic state changes or output
publication. Temporary deduplication changes are cleared before a capacity
refusal. The private state validator checks complete frame/record extents,
UTF-8, record hashes, counts and the nested chain; it is not an authentication
scheme for externally imported memory. No state import API exists.

The validator scans retained state on ordinary calls. Repeated PUSH of many
small hints therefore has quadratic total validation work in the current
implementation. The 4,097-unique-hint test and maximum single-hint byte test do
not establish a cost bound for every arena-filling hint-count distribution.

## Persistent executable fixture

`scripts/hia_native_request_context_build.py` uses a fixed two-image table:
the existing generic `view_cache_hex_transport.hepta` fixture and this context
image. The HIA composition packer emits a persistent static Linux x86-64 ELF.
Only the private fixture controller can call its context slot. Each process
owns its separate context workspace. This test entry is not installed in the
public MCP service.

The fixture's 8 MiB outer input contains hexadecimal request bytes, so its
decoded request domain is smaller than the direct image's 8 MiB input domain.
Its reused bridge also reserves only `1 MiB + 32` bytes for a child response.
A larger DRAIN response refuses capacity before changing the queue. Direct
image capacity tests and persistent transport tests remain separate evidence;
this fixture does not qualify the full direct-image domain over stdio.

## Qualification boundary

`test_request_context.py` loads the actual emitted image and compares complete
responses to an independent Python list model. It retains every semantic input
and result byte, and separate complete-state/output hashes for refusals. Its
domains include scope-free calls, nested restoration, interleaved private
workspaces, duplicate ordering, exact text, lifecycle cleanup, more than 4,096
hints, full declared arena capacity and every valid Unicode scalar in one string.
Malformed frames, capacities, damaged state and untouched bridge tails are
separate controls. These are real native calls, not original Rust executions.

The original Rust/Tokio comparison and the actual persistent static ELF fixture
are separate mandatory suites. Production scheduling, authenticated cache
binding, every public tool, whole-runtime replacement and old-stack removal
remain unqualified by this component alone.

# Native public SDK connection admission

The three-buffer entry ABI is `f0(readbuf input, mutbuf output, mutbuf workspace)
-> u32`. Each connection has its own persistent workspace. Inputs are borrowed
only for that call; every forwarded admission record contains owned output
bytes. No public JSON field selects an installation, host authority or connection
mode. All multi-byte words below are little-endian unsigned 64-bit values.

## Wire message owner

`sdk_message.hepta` accepts `HRCJQ001`, operation 1, an exact byte length, then
one raw transport frame. The header is 24 bytes. Raw input is bounded to 8 MiB.
The `serde-json.v1` manifest permits 16 MiB input, 64 MiB output and 256 MiB
workspace; the source's narrower 8 MiB frame bound is explicit. The fixed
transport removes LF and a preceding CR, ignores empty frames and accepts the
final nonempty frame at EOF. The HIA parser strips one leading UTF-8 BOM.

The result starts with `HRCJR001` and has a 256-byte header.

| Offset | Meaning |
|---:|---|
| 8 | 0 ignore, 1 request, 2 notification, 3 response, 4 error, 5 transport Invalid Request |
| 16 | Typed request/notification variant, or zero |
| 24 | Missing required metadata bits: 1 protocol version, 2 client capabilities |
| 32 | Metadata object was present |
| 40 | ID kind: 0 absent, 1 signed integer, 2 string |
| 48 | Signed ID's two's-complement 64-bit representation |
| 56 | Reserved zero |
| 64..223 | Ten offset/length pairs, relative to the result |
| 224..255 | Reserved zero |

Pairs 0..9 contain: raw method UTF-8; canonical JSON ID; canonical metadata JSON;
raw metadata protocol version; raw initialize version; normalized initialize
capabilities; normalized initialize client info; normalized typed parameters;
raw tools/call name; canonical tools/call argument Value.

For response/error dispositions, pair 7 instead retains the result Value or
normalized ErrorData. Pair 9 retains the **complete original raw message**. The
result Value is not claimed to be normalized through the SDK's `ClientResult`
untagged enum. Its eventual peer-response owner must consume the preserved raw
message before completing a pending server request. Losing this body or treating
it as an empty result is forbidden. The current connection owner forwards it
without making that pending-request decision.

An absent pair is `(0,0)`. A present empty string has a nonzero offset and zero
length. Request variants 1..19 are Ping, Initialize, Discover, Complete,
SetLevel, GetPrompt, ListPrompts, ListResources, ListResourceTemplates,
ReadResource, SubscriptionsListen, Subscribe, Unsubscribe, CallTool, ListTools,
GetTask, UpdateTask, CancelTask, Custom. Notification variants 101..105 are
Cancelled, Progress, Initialized, RootsListChanged and Custom.

The parser preserves the locked SDK's untagged order and typed fallback. An
invalid numeric request ID can therefore become a custom notification. This is
not replaced by a stricter generic JSON-RPC validator. Known malformed parameter
types can become a custom request, while malformed metadata still follows the
SDK transport's data-error/compatibility-ignore rules. Exact typed parameters
include sequence structs, Option behavior, numeric promotion and JSON bytes.

## Persistent admission owner

`sdk_connection.hepta` accepts `HRCNQ001`, operation, exact payload length, then
payload. Operation 1 contains only a projection from the fixed message owner;
operation 2 is an empty EOF event. This is a private composition ABI, never a
public method. The `history.v1` allocation maxima are 128/128/256 MiB. Minimum
workspace is 64 KiB; the fixed production-sized fixture supplies 256 MiB.

Output `HRCNS001` has a 256-byte header:

| Offset | Meaning |
|---:|---|
| 8 | 0 ignore; 1 emit direct wire response; 2 admitted request; 3 notification; 4 peer response; 5 peer error; 6 close |
| 16 | Close after any emitted response |
| 24 | Connection selected modern mode |
| 32 | Effective context version is at least 2026-07-28 |
| 40 | This request is a legacy request under the original SDK predicate |
| 48 | Peer info existed at admission |
| 56 | Required-metadata missing bitmask |
| 64/72 | Complete direct wire response, without LF |
| 80/88 | Complete input message projection |
| 96/104 | Legacy peer capabilities JSON snapshot |
| 112/120 | Legacy peer protocol-version snapshot |
| 128/136 | Legacy peer client-info JSON snapshot |
| 144/152 | Effective request-context version |

The remaining header is zero. All spans are relative to this output. A router
may retain the complete record for asynchronous work; it must not use a later
initialize's peer snapshot for an already admitted request.

Private persistent state is 64 bytes at workspace offset 0, followed by scratch.
Cached peer version/capabilities/info start at 16384. Modes are awaiting opener,
legacy, modern and closed. Repeated initialize rewrites peer info but never
clears a previously selected modern mode. The initial initialize stores the
negotiated version; later initialize stores the requested version, exactly as
the SDK does. Pre-initialize ping leaves mode unselected. Initial non-initialize
admission checks missing metadata before unsupported version; running requests
check unsupported inline version first. `server/discover` is the real method.

Output is measured before any publication. State and peer data commit only
after complete output capacity and cache admission. Refusals leave the semantic
state and output unchanged; scratch may be rewritten. Invalid private ABI or
state returns `0xffffffff`, insufficient buffers return `0xfffffffe`. Other
returns are exact output lengths. Neither owner has an OS effect capability.

## Real transport fixture

`sdk_connection_packer.hepta` constructs the static ELF, patches three fixed
relative calls and copies complete pinned images. The fixed x86-64 adapter owns
only mmap, read/write, LF framing and exit. Its 889,274,368-byte anonymous map is
lazy, disjoint and never pre-cleared wholesale. No interpreter, dynamic loader,
libc, Rust or Python is needed by the executable. It accepts no arguments.

The third image, `sdk_default_fixture.hepta`, deliberately reproduces only the
unoverridden SDK handler methods used by the independent reference. It is a
**test fixture**, not a production runtime dispatch registry. Successful exit is
0; invalid internal result is 2, capacity is 3, I/O error is 4, invalid CLI is 64.
The public connection/config integration must replace that third image with the
real fixed native registry and immutable installed-config owner.

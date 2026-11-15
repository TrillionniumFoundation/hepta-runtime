# Local regular-file `view` caller

This HIA controller is the ordinary local-file
execution branch after native typed parameters, session/workdir snapshot and
installed path policy. The production JSON-RPC frontend must create its private
input; a public caller cannot select a session, scope, cache, child image or
installed configuration. Until that frontend is connected and qualified, the
static controller executable remains a component composition fixture.

## Input and result

The request is a 64-byte header followed by four byte spans. It contains
`HVCLQ001`, flags, raw-path byte length, resolved-local-path byte length,
start-endpoint frame length, end-endpoint frame length, and two zero words.
Payload order is raw path, resolved path, start frame, end frame. The raw path
is the original public UTF-8 path. The resolved path is the exact Unix byte
path produced from that path and the private session workdir; it is not its
canonical cache key. Flag 4 is `full`; no other public flags are accepted.

An absent/null endpoint has a zero-length span. A present endpoint carries the
existing complete `HIAEP001` typed frame. Its parsing is deliberately deferred
until after the original existence/directory dispatch, preserving error order.
The native `view_params` owner supplies these frames from actual JSON Values;
Python adapters used by component tests are not production parameter parsing.

The separate private `HVCPI001` entry has the same header and spans. It models
an internal raw Unix `PathSource` which has already bypassed public
`render_view`: after opening its scope, it starts with endpoint resolution
and then `view_file_spec`. It skips the outer blank-path, `exists` and
`is_dir` observations. Its resolved span may contain non-UTF-8 Unix bytes or
an embedded NUL, preserving the original internal error behavior. This is
not the ordinary MCP entry, and public calls cannot choose its magic.

The result uses the existing `HRCFGM01` text-result envelope: status zero for
success or one for a tool error, a zero reserved word and text byte length,
then exact UTF-8 text. Its immutable storage is owned by the caller until the
existing configuration MCP frontend has transferred it to `result_publication`.
Scope destruction cannot release or overwrite that result storage.

The controller has one private installation and a monotonically increasing
request generation. Installation is an internal dispatcher operation before
ordinary requests. It provides a live session-cache lease and fixed child
bindings. Ordinary input contains no cache ticket or request-scope selector.
The explicit fixture can install an unbound original execution context for
component parity; the actual MCP `view` route always installs a bound scope.

## Native children

The caller owns order and data selection. Its fixed boundary owns mappings,
validated byte copies and child calls. Local child slots are source-owned:

| Slot | Owner |
| ---: | --- |
| 1 | Ordinary metadata reader workspace, reused only after DROP |
| 2 | First range-read reader workspace |
| 3 | Actual file-read reader workspace |
| 4 | Existing line-endpoint owner |
| 5 | Existing canonical file-key owner with its closed Linux boundary |
| 6 | Request-scope lifecycle owner |
| 7 | Shared cache-lease owner |
| 8 | The same growable view-cache instance retained by that lease |
| 9 | Growable view-render image |
| 10 | Request-context owner privately bound by slot 6 |
| 11 | Exact existing OS-error message owner extracted from `atomic_write` |

The production parent may place these images at different ELF offsets. The
local table is private and fixed; protocol IDs never index it. The same cache
workspace is used for reads, mutations and the final lease RELEASE's actual
DESTROY, including after mapping growth. The scope convenience CACHE window is
not used as an input quota. The controller first obtains ACCESS, verifies the
returned live lease with INSPECT, then invokes the same cache through the
serialized trusted dispatcher.

Reader snapshots remain in the reader's owned arena until copied into the
caller's growing immutable render frame. The copy boundary admits only the
exact successful snapshot span and current generation. Renderer and cache
result copies likewise name a completed, still-live child result. Every copied
extent and destination addition is checked. No source pointer survives a
mapping relocation or a child-result retirement.

The render frame is the existing `HVIEW001`: two independent complete reads,
the original typed endpoints, metadata observations and the prior cache value.
The new renderer uses independent u64 endpoints/counts, with no fixed input
byte ceiling. Its internal line tables grow according to actual requirements.
The original output body limit remains exactly 8 MiB.

## Required state sequence

1. Open the request scope after the frontend's typed/session/policy checks.
2. Follow the original `exists` and `is_dir` observations. A separate literal
   search frame selects its file-search branch at this point. Directory,
   regex, alternative-path search, remote and background-resource branches
   remain distinct unfinished routes, never reported as a local-file success.
3. Parse start then end. If present, observe first metadata, apply its original
   5 MiB check and perform the first strict UTF-8 read. First metadata failure
   is ignored; first read failure means zero lines. A nonempty first snapshot
   resolves endpoints and queues swap then clamp hints before the second read.
4. Observe actual `exists`, `is_file`, metadata and strict read separately.
   Check that metadata's 5 MiB threshold before reading. A subsequent growth
   does not create a total read quota or imply an original oversized-file error.
5. For whole-file rendering, derive the canonical key, get the prior cache
   entry, prepare the native cache action, commit it to the actual cache, then
   render with the immutable prior entry. No later failure rolls this back.
6. Apply the original 8 MiB base-body gate before hints. On success, drain the
   real request queue and append each distinct hint exactly once. On error,
   destroy the queue without appending it.
7. Close the request's own lifetime and return the complete immutable text in
   the caller's independent output allocation. The frontend copies it into
   the result publisher before reusing the caller. Cancellation does not
   reclaim an independently owned publication or undo a previously committed
   cache mutation.

The 8 MiB check applies to successful `execute_view` base text. It does not
truncate original parameter, endpoint, path or I/O errors. The caller output
starts at 16 MiB and grows when final phase 92 explicitly requires a larger
complete result. Other capacity refusals are not converted into output growth
or tool-level size errors. A canonical endpoint Value can therefore produce
an error longer than 16 MiB and still retain every original byte.

Ordinary awaits use the scope's private YIELD/RESUME continuation. A cancelled
generation can only retire a late callback's resources. The native fixture's
serial event loop does not establish concurrent HTTP execution, Tokio-general
polling, timer handling, spawned-task inheritance or a production panic hook.

## Deterministic I/O qualification

The ordinary executable path executes effects directly. Its explicit test-only
synchronized mode emits a logical-I/O completion record and waits for an ACK
after each completed `exists`, `is_dir`, `is_file`, `metadata` or full `read`.
The parent then changes a real file and acknowledges that exact generation and
sequence. This schedules real filesystem races while HIA still decides the
next operation. These fixture ACKs are not production authorization or proofs
of a concurrent MCP dispatcher.

Tests retain full request/result bytes, actual kernel receipts, logical I/O
order, exact cache probe bytes, cancellations and all original-reference
process stdout/stderr. Direct component cases, synchronized real-I/O cases and
actual production MCP calls are counted separately.

## Callable native boundary

`view_engine_create` takes the private twelve-address image table in `rdi`
and the real `AT_SECURE` value in `rsi`. It returns the engine pointer or an
unchanged negative Linux errno. Failed creation releases every partial
allocation. With the engine in `r15`, `view_call_run` takes a complete private
frame pointer and length in `rdi` and `rsi` and returns a zero-extended u32 HIA
result. All SysV callee-saved registers are preserved. Input and live result
borrows must refer to distinct, admitted allocations.

Installation uses sixteen bytes `HVCLI001`, bound flag 0 or 1. Bound
installation creates the session's initial cache lease in the actual native
lease owner; unbound installation exists only for the explicit original
context qualification. The response is `HVCLINR1`, bound flag, cache epoch and
session ticket, four u64 words. The table and ticket are never derived from a
protocol request ID.

`view_engine_retire` requires a completed ready caller and releases the
session ticket against the same cache instance, including after growth. It
keeps result storage alive. `view_engine_destroy` requires successful retire
and the end of every borrowed result; it then frees the mappings. The
frontend must finish copying a result into its independent publisher owner
before destroying or reusing that storage.

Each child descriptor is 64 bytes: entry, workspace pointer/capacity, output
pointer/capacity, last return, then two private words. Slots 6 and 7 reserve
the last two words for consumed HIACAL sequence and active state. All nested
scope/lease calls reread the descriptor table, so a final cache release sees
the current slot 8 allocation. Growth allocates guarded storage, copies the
complete old contents, and retires the old mapping only after success. If
retirement fails, the new mapping is released and the original errno and
mapping are retained.

## Deterministic fixture wire

The standalone fixture accepts either no arguments or the qualification-only
`--sync` flag. It reads `u64 frame_length` followed by the complete private
request. Every stdout record is `u64 payload_length` followed by its payload.
The ordinary mode emits only final results. Synchronized mode additionally
emits `HVCLIO01` plus seven u64 words: request generation, action sequence,
logical kind, child slot, child return or gate status, body length and zero,
then the complete body.

Logical kinds 1 through 5 are `exists`, `is_dir`, `is_file`, metadata and full
read. Their body is the complete 80-byte `HVRDR001` result, followed by the
complete successful read snapshot when present. Kind 6 is a scheduler gate
after the original successful-body limit and before draining hints; its body
is the complete base text and its status is zero for success or one for an
original error. The ACK is exactly `HVCLACK1` plus generation, action sequence
and action, four u64 words. Action zero continues; action one cancels only at
kind 6. Production mode never waits for these test ACKs.

A final record is `HVCLOR01`, native return, result length and zero, followed
by the complete `HRCFGM01` result. `0xffffffcf` is the private completed
cancellation result with no payload. `0xffffffc1` indicates a distinct
unimplemented branch, such as a directory, after request cleanup; it is not
an original tool-success text.

Only synchronized mode admits `HVCFIX01`, operation, value, payload length
and payload. Operation 1 selects an independently installed bound (value 1)
or unbound (value 0) caller while retaining the same session/cache. Operation
2 invokes actual cache `FORGET_ALL`; operation 3 derives the actual canonical
key for the raw Unix payload and probes that same cache. Their response is
`HVCFXR01`, operation, status and payload length. Probe payload contains the
complete key result followed by the complete cache result. These controls
cannot select a session identity or cache from ordinary MCP input.

The fixture retains complete 128-byte kernel completion receipts on stderr.
The source-owned private engine word at offset 96 enables those receipts
only when its value is exactly one. Fresh production engines leave it zero;
the standalone fixture sets it to one explicitly. The reader/key HIA
completion and ACK are written in both modes. The trace flag cannot be set
by any public tool frame, and neither a receipt nor its absence is used as
the semantic completion decision.
It does not change stdin/stdout open-file-description flags. Partial writes,
EINTR and an already nonblocking descriptor's EAGAIN use the admitted native
boundary. This component's serial fixture, internal lifecycle controls and
actual file I/O remain separate evidence domains from production MCP routing
and from general asynchronous cancellation.

## Literal content-search frame

`HVCSQ001` contains seven little-endian u64 words after its magic: flags,
raw-path length, resolved-path length, UTF-8 content-pattern length, typed
context value, zero, zero. The three payload spans are raw path, resolved
Unix path and the complete untrimmed pattern. Only flag 4 (`full`) is admitted;
search ignores that flag, as the original method does. No endpoint frames are
sent because this branch is selected before endpoint resolution.

Only the trusted frontend constructs this frame after complete SDK metadata,
typed ViewParams, session/workdir and installed-policy admission. A public
caller cannot select the magic, cache, lease or request context. A nonblank
content value with `regex` false selects this branch; blank content follows
ordinary view. Regex search remains a separate unfinished branch. Context is
the admitted u64; values above i64::MAX become zero, matching the original
Value::as_i64 fallback. No private negative-JSON or invalid typed-parameter
domain is inferred from this controller interface.

The controller performs the original outer exists/is-directory observations,
then the inner file-search exists/is-file/metadata observations. It enforces
the original metadata threshold of 5 MiB before a raw read. It follows symlinks,
allows hard links and reads through EOF; later file growth does not create a
new total input quota. The snapshot is immutable until copied, then is decoded
with the original String::from_utf8_lossy replacement grouping. Files with NUL
content are searched normally. File-read errors precede decoding.

The HIA caller matches the complete literal pattern in each Rust str::lines
line. LF splits lines; CR is removed only immediately before LF, and a final
trailing empty line is omitted. Context ranges are expanded and overlapping
or adjacent ranges merge. Each selected line appears once as the original
one-based number, two-digit folded FNV hash, delimiter and exact line bytes.
Selected lines are joined by LF without a trailing LF or gap marker.
The existing renderer's scalar FNV and decimal-rounding functions are imported
by exact AST with recorded relocation.

Empty-file and no-match messages preserve every original pattern byte.
Successful text is measured against the original execute_view 8 MiB limit
before publication; above the limit, the complete original size error is
returned. This is the existing body gate, not a snapshot or cumulative input
quota. Allocation and LP64 representation remain real resource limits.
The caller does not run the cache key/get/prepare/apply/render path for search.
A previous nonempty cache entry therefore survives success, error, full=true,
an unbound execution context, and cancellation. Request cancellation or close
still retires its actual scope and lease.

An existing filename containing `|` is a single literal pathname. A missing
raw path containing `|` returns the private unfinished-route code after scope
cleanup, because the original alternative-path dispatch is a distinct branch.
The ordinary MCP frontend does not turn that code into a fabricated original
search success.

The synchronized fixture retains successful raw operation 5 snapshots in the
same full HVRDR001/HVCLIO01 records used for strict operation 2. It does not
decode or search in the boundary. Its test-only gate remains disabled in
production. New literal cases, whole-file cache preparation, private completion
controls, real public MCP calls and independent Rust replays are separate
evidence domains. None establishes whole-view or whole-runtime replacement.

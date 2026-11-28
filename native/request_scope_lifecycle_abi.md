# Private request scope and shared cache lifetime

These HIA controllers connect the existing `request_context.hepta` and
`view_cache.hepta` owners. They do not install a public MCP route or implement
session admission, workdir, filesystem effects, path keys, or a Tokio scheduler.
The source baseline is Runtime `70df0bca4c5062ee0565fb1feacc1f7e3e4864df`;
the original request context is pinned to
`2173a00ec314ebc0c5ada21e4cb60d8efdccb99a`.

## Production attachment

The trusted dispatcher owns each scope workspace and each installed child
binding. For `server::view`, OPEN is after typed parameter admission,
`ensure_session_workdir`, workdir snapshot and `enforce_runtime_path_spec`.
Parsing and range hints inside `execute_view` occur after OPEN. The same
request continuation carries the private binding through ordinary awaits.
Independent requests have separate workspaces. Spawned completion tasks and
the shell heartbeat branch receive no binding. No JSON-RPC ID, session ID,
external number or equal hash selects a scope workspace or cache capability.

One scoped execution chain has at most one suspended continuation. Its IO or
timer owner may have several readiness sources; only the dispatcher may consume
the current continuation once. Independent scoped branches use independent
owners, even when a dispatcher polls both on one OS thread. This is the actual
nine-caller structure, not a general nested/join Future implementation.

Success preserves the caller's original ordering: compute its body and apply
any original body size gate, DRAIN, seal the result and transfer publication
ownership using the result owner's acknowledged handoff, then CLOSE. A cache
prepare/set already applied before a render or size error is
never rolled back. Errors, cancellation, drop and unwind destroy hints and
release the request's cache clone. A suspended cancelled scope becomes a
tombstone; its one late completion only retires the continuation. It cannot
ACCESS, append a hint, operate on cache, reopen the scope or revive its lease.
The trusted executor must finish an in-flight synchronous HIA call before
issuing cancellation. Actual FD/process/callback cleanup remains with its
existing effect owner.

Publication START transfers result ownership to its publisher; it is not a
scope-owned cancellable borrow. Before handing a cache reference to a publisher
or worker, the trusted dispatcher creates an independent live CLONE. Cancelling
the request releases only its own reference and hints. It cannot kill a worker
already inside write, reuse that worker's borrowed result bytes, reclaim its
arena, or release its cache clone. A late worker completion releases only the
worker-owned clone. This scope ABI has no operation that destroys publisher
storage or a worker handle. The finite clone-lifetime example establishes this
ownership relation; it does not implement a complete stdio asynchronous writer.

## Private installation and resources

Both entries are `f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`.
They use the existing `HIACAL01` checked child-call bridge. Trusted OPEN/CREATE
select only already installed private child slots allowed by the native image
table. The finite qualification table has two independent scope/controller
instances, two context instances and one shared lease/cache pair. That table
is a test installation, not a two-request production quota.

The shared lease controller stores one eight-byte record per live clone in its
actual supplied arena. It has no configured object/request-count ceiling or
eviction. A full supplied arena returns CAPACITY; allocator-backed growth and
unbounded total cache contents remain separate integration work. Existing
request-context and view-cache buffer limits remain explicit. No successful
finite lifetime test establishes their unbounded allocator domain.

Every accepted call is serialized on its private owner. A production event
dispatcher must serialize operations on the shared cache/lease pair as well.
The executable qualification demonstrates serialized interleaving; it does not
establish an installed concurrent HTTP route or native mutex poison production.

## Request-scope input

The header is eight ASCII bytes `HRSCQ001`, followed by seven little-endian
u64 words: `operation, generation, continuation, a, b, payload_length, zero`.
The frame ends exactly after its payload.

| Op | Meaning | Fields |
|---:|---|---|
| 1 | OPEN | generation/continuation=0; a=context slot; b=lease slot; payload=`cache_epoch, existing_lease` (two u64). |
| 2 | ACCESS | Current generation/continuation; no args or payload. |
| 3 | PUSH | Current binding; payload is exact UTF-8 hint. |
| 4 | DRAIN | Current binding; no payload. |
| 5 | YIELD | Consume active binding and issue the next suspended continuation. |
| 6 | RESUME | Consume that suspended continuation once; a cancelled tombstone only retires. |
| 7 | CLOSE | Active binding; a=0 success or 1 error. |
| 8 | CANCEL | Current generation, continuation=0; a=2 cancel, 3 drop, or 4 unwind. |
| 9 | CACHE | Current binding; payload is an existing complete HVCACH01 frame for op 1,2,3,4,6,7,8. |

All unused a/b fields are zero. ACCESS/PUSH/DRAIN/CACHE with generation and
continuation both zero are the explicit unbound path. They preserve the active
request, drop hints, return an empty drain or missing cache, and never borrow
the request's lease. Typed string/frame boundaries remain checked.

Generation is generated internally on OPEN; it never wraps or resets when the
same workspace is reused. The active initial continuation is 1. YIELD increments
it without wrapping. OPEN is refused until the previous scope is closed and
its pending continuation has retired. The generation/sequence words are only
stale-completion checks inside the private workspace; knowing them gives no
authority to acquire that workspace.

The response is `HRSCR001` plus seven u64:
`generation, continuation, phase, tag, cache_epoch, lease, payload_length`.
Phases are 0 closed, 1 active, 2 suspended, 3 cancelled and awaiting retirement.
Tags are 0 unit, 1 active access, 2 unbound, 3 retired late completion,
4 drained list, 5 cache result. Payloads are complete original owner response
frames; unbound DRAIN carries the empty HRCXR001 list and unbound CACHE the
missing HVCAR001 frame. Unbound headers disclose no active binding.

## Shared cache lease input

The header is `HRCLQ001` plus seven u64:
`operation, cache_epoch, lease, a, b, payload_length, zero`.

| Op | Meaning | Fields |
|---:|---|---|
| 1 | CREATE | epoch/lease=0, a=private cache slot. Initializes existing view_cache and returns initial session lease 1. |
| 2 | CLONE | Existing epoch and live source lease. Returns a fresh monotonic lease, retaining the same cache. |
| 3 | RELEASE | Existing epoch/live lease. Consumes it once; the last release invokes existing cache DESTROY. |
| 4 | CACHE | Existing epoch/live lease; exact original cache frame. Initialization/destruction remain private to CREATE/last RELEASE. |
| 5 | INSPECT | Existing epoch/live lease; reports lifetime state only. |

All other args are zero. Cache operations 1 through 9 are accepted using their
existing selector rules. This permits an independent `publication_cache` clone
to call owned `forget_all`, including after the session's initial lease has
been released. Any live clone can clone again. The owner does not assume that
only the original session holder can retain an Arc-equivalent reference.

The response is `HRCLR001` plus seven u64:
`cache_epoch, returned_lease, live_count, phase, payload_length, zero, zero`.
Phase 1 means live; 0 means destroyed. Only CREATE/CLONE returns a new lease;
other responses return the addressed lease, including its just-consumed number
on RELEASE. CACHE appends a complete HVCAR001 frame. Cache epoch increments
on reuse, never wraps, and stale epochs/consumed leases cannot access new state.

## Failure and evidence boundary

Returns `0xffffffff`, `0xfffffffe`, `0xfffffffd` mean malformed input,
resource capacity, and invalid private state/binding respectively. Child-call
failure cleanup is distinct from an input refusal: OPEN rolls back an acquired
lease. An INIT refusal preserves the preexisting context; only an ENTER failure
after this OPEN's successful INIT destroys its own tentative context. CLOSE only completes after actual
context destruction and actual lease release. The monotonic private bridge
sequence may advance on an attempted child call. Ordinary rejected input
does not change a context, cache, active lease or output bytes.

PUSH checks the complete child-frame extent against both its transfer window
and the actual private workspace before saving call state or copying a hint.
Direct entry controls also exercise larger borrowed inputs than the standard
transport admits; those controls establish a safe capacity refusal, not a
larger admitted transport profile. The qualification-only root can access its
two context slots to verify that an already initialized context survives a
failed OPEN. Production callers never receive this fixture entry.

The bridge only accepts the exact pending target, request span, output span,
sequence, and successful native receipt. Source/image/ELF identity and complete
public fixture input/output bytes belong to the focused evidence. A forged
receipt is a controller error, not proof that child work happened.

This implementation does not replace any of the nine Rust filesystem callers
until its private dispatcher attachment actually ships. It does not claim a
production unwind hook merely because a test invokes the CANCEL-unwind event.

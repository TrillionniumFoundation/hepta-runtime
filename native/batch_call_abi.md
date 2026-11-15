# Local batch call continuation

This is the private caller of the original local `batch_edit_spec` body. The
upstream typed owner, effect permit, Session/workdir and policy admission must
complete before its START. A typed path or protocol request ID is not authority.
The installed scope/cache binding comes only from the trusted dispatcher.
The public MCP route and whole-runtime completion flags remain false.

The owner controls preflight, existence, canonical lock acquisition, the first
strict read, Editable normalization, input projection, planning/application, the
second existence/read used by history, a newly derived history key, original
atomic write, a newly derived cache key, cache update, diff, lock release, hint
drain and scope teardown. Native boundaries perform only admitted calls and
Linux effects. They do not decide batch results.

All words are little-endian u64. `f0(readbuf, mutbuf, mutbuf) -> u32` returns 64
for an ordinary private response; the complete extent is carried in its header.
Input and output are disjoint borrowed spans. Workspace belongs to one request
chain; offsets, never absolute mapping addresses, survive growth.

## Installation and request

`HBCINI02 + 7Q(bound, cache_epoch, session_ticket, 10, 7, 0, 0)` installs a fresh
workspace. The first 4096 bytes must be zero. `bound` is 0 or 1; an unbound
installation has zero epoch/ticket. The numeric slots are fixed private graph
identities, not public selectors.

`HBCALQ02 + 7Q(op, generation, sequence, a, b, c, d)` has these operations:

| op | Meaning | Fields / payload |
| --- | --- | --- |
| 1 | START | generation/sequence zero; a = full successful HBPRR002 length; b = already resolved local raw Unix path length; c/d zero; payload is those two spans |
| 2 | COMPLETE | exact live generation and pending sequence; a = complete zero-extended child u32 return; b = body length; c/d zero; body is the child's exact result |
| 3 | CANCEL | exact generation/current sequence; remaining words zero; private cancellation of the bound future |
| 4 | LATE | exact retired generation/sequence; a = retired child return; b = body length; c/d zero; retires resources without reviving the request |
| 5 | WAKE | exact generation/current sequence; remaining words zero; polls a queued lock after a trusted wake |
| 6 | DROP | only idle and with no retired borrow; zero remaining fields; erases the owned workspace prefix |

The reader boundary returns its exact 80-byte HVRDR001 response followed by the
complete snapshot only on successful op 2. The snapshot offset remains the
original private-reader offset; no pointer is serialized. Other children return
their complete unchanged frames. Original io_exists treats all stat failures
as false. Neither original read nor history read receives a new metadata size
gate. The two reads are separate actual filesystem operations.

## Responses

`HBCAR002 + 7Q(status, generation, sequence, target, body_len, auxiliary, 0)`:

| status | Meaning |
| --- | --- |
| 0 | Complete successful original String, body is exact UTF-8 |
| 1 | Invoke the fixed child target, body is its complete request |
| 2 | Waiting for the held/queued file lock; no body |
| 3 | Complete original String error, body is exact UTF-8 |
| 4 | Cancelled; no application result; auxiliary identifies an outstanding retired borrow when nonzero |
| 5 | Grow the controller allocation: target 1 workspace or 2 output; auxiliary is the exact required extent; retry the unchanged input |
| 6 | Nonsemantic native resource/contract failure; auxiliary is the actual native code |
| 7 | Unit installation/drop/late-retirement result |
| 8 | Delivery-only continuation: body is an exact retained COMPLETE frame with the current sequence; copy it to the next borrowed input and invoke this owner, without re-executing its child |

The fixed child graph is reader 1/2/3, key 5, scope 6, lease 7, cache 8,
input bridge 12, planner 13, apply 14, Editable 15, diff 16, history 17,
file-lock state 18 and atomic-write 19. Planner's retained HIACAL children are
fixed endpoint/verifier images; apply's retained child is Editable. Scope's
fixed recursive graph remains 6 -> {7,10}, 7 -> 8. There is no arbitrary image,
syscall, pointer or file-descriptor selector in public input.

Growth after a completed child only retries delivery to this controller, never
the completed effect. Output allocation failure after a successful rename is a
real resource failure, not a fabricated batch semantic error. History and cache
effects already completed are retained on later error/cancellation. Complete
private bytes and all actual effects are retained by qualification; no result
is replaced by a hash or truncated preview.

Cancellation may retire an outstanding whole-read or original atomic stage.
The dispatcher must retain that independent borrowed child arena until the
late completion is joined, while the controller releases its lock and scope.
An atomic child observes the existing source-owned cancellation word and stops
only at an original async stage boundary; a started write_all stage finishes
before retirement. A late result never becomes a successful tool response and
never obtains a new request's capability.

Before an ordinary whole-read or atomic await the caller actually YIELDs the
native scope. It retains the complete child response while RESUME consumes the
same continuation once, then status 8 redelivers that already completed response.
Queued lock waits use the same YIELD/RESUME lifetime. Cancellation tombstones
the scope; LATE consumes its pending continuation only after the independently
owned native borrow has retired. This is a single request chain, not a generic
Tokio scheduler or a claim that spawned independent work inherits its binding.

This document is an implementation contract. Actual build, corpus, original
comparison and lifecycle qualification must be recorded before any closure
claim is made. Existing retained child ABIs still have their own representable
result extents; those limits are not relabelled as original batch quotas.

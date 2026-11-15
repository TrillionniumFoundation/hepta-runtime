# Private native SessionWorkdir contract

This owner implements the `SessionWorkdir` state in `src/mcp/server.rs` and the
one-time `session_applied.swap(true, SeqCst)` latch. One private workspace belongs
to one actual server session. The closed transport/controller creates and owns
that workspace; a public request cannot select another session or invoke this
internal frame. The state is not filesystem authorization. The caller must run
the original installed policy and actual OS checks before any file effect.

## Request and response

The `f0(readbuf, mutbuf, mutbuf) -> u32` borrowed-byte ABI uses little-endian
64-bit words. A request is `HRSWQ001`, operation, payload byte length, a zero
reserved word, then exactly the payload. There are no trailing bytes.

A response is `HRSWR001`, result tag, scalar, payload byte length, then exactly
the payload. Tag 0 is unit with zero scalar and no payload. Tag 1 is a raw Unix
path with zero scalar. Tag 2 is a Boolean with scalar 0 or 1 and no payload.

| Operation | Private caller | Payload | Result |
| --- | --- | --- | --- |
| 1 | Transport startup | Immutable root path bytes | Unit; initialize this new session once |
| 2 | Tool/controller | Empty | Current path, falling back to root if unset or poisoned |
| 3 | Tool/controller after its checks | Replacement current path bytes | Unit; retain root; ignore mutation if poisoned |
| 4 | Workdir controller | Empty | Unit; clear current path unless poisoned |
| 5 | First-tool context controller | Empty | Boolean; atomically mark context applied and return whether this call was first |
| 6 | Qualification injection only | Empty | Unit; model a genuinely poisoned original RwLock |

Empty, non-UTF-8 and NUL-containing paths are representable here because Rust
`PathBuf` stores them. Policy checks, actual directory/canonicalization queries,
UTF-8 lossy display and JSON serialization are separate owners. In particular,
an affirmative first-tool latch result grants no filesystem permission.

The trusted session dispatcher serializes each short state operation against the
same private workspace, including operation 5. Worker-process copies or separate
workspaces for cloned session handles do not satisfy this contract. The latch
call and a later validated set remain separate operations, preserving the
original possible interleaving while directory checks run.

The first-tool controller calls operation 5 before reading capabilities. A false
result ignores later capabilities. A true result remains applied even when the
capabilities/session/workdir value is absent, has the wrong type, or the
directory/policy check rejects it. Only a validated path reaches operation 3.
The actual installed-policy and OS owners must provide those validation results;
ordinary request Booleans or claimed path hashes cannot substitute for them.

Operation 1 is accepted only in a new zero-initialized workspace. The state
owner retains root, optional current path, poison state and first-tool latch.
Directory callers only need operation 2 and must retain the complete returned
raw path through their own checked continuation.

Malformed framing/state, repeated initialization, unsupported operations and
nonzero reserved words return `0xffffffff`. A path beyond the full 8 MiB
request-domain storage or insufficient input/output/workspace capacity returns
`0xfffffffe`. Both refusals leave output and persistent state unchanged.
Ordinary set/reset operations preserve the original nonfallible behavior when
the lock is poisoned. The closed production call table does not expose the
qualification poison operation to public MCP requests.

## Shared state and growing borrowed spans

The current owner accepts the legacy `HRSWQ001` frame above and the growing
`HRSWQ002` frame, both with the same 32-byte request header. Both use a newly
initialized `HRSWST02` workspace. An old workspace must not be reused with this
owner. Its first 64 bytes contain eight little-endian words: magic, root length,
current length, current-present Boolean, poisoned Boolean, applied Boolean,
initialized word (one), and reserved word (zero). The full root starts at byte
64; the current path starts immediately after the root. Shrinking or clearing
the current path zeroes every vacated byte.

The legacy frame retains its 8 MiB path limit, minimum 16 MiB plus 64-byte
workspace, `HRSWR001` reply and refusal codes. The growing frame uses
`HRSWR002`, checked 64-bit span lengths and caller-owned workspace/output
growth. It has no fixed path limit. A caller must preserve this same private
state across arena growth and must retry delivery without repeating a committed
state transition. Sharing state between the two frame versions does not grant
cross-session access. All declared lengths, Boolean values, reserved words and
the initialized magic are checked before use.

This file defines the integration seam while its implementation is in progress.
It does not claim a completed owner, production activation, HTTP concurrency,
the public `workdir` handler, or old-stack removal.

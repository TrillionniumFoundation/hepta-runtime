# Native Linux directory caller

This fixed, private profile composes the original controller-local
`directory_create` call order with real installed configuration, full
`RequestContext` capability resolution, SessionWorkdir, local path policy,
descriptor-bound directory creation, and one shared effect-fence process.
All decisions run in compiled HIA. The static executable needs no Python,
Rust, libc, assembler, or external worker executable at runtime.

The executable is a qualification and integration boundary. It does not yet
replace the public MCP handler, authenticate an HTTP caller, or supply an SSH
implementation. Ordinary input never supplies a permit, a trusted owner hash,
configuration memory, or a syscall address.

## Fixed source and image closure

`directory_service_profile.json` pins twenty-one actual image byte ranges,
their source hashes, their fixed call displacements, and the normalized native
adapter prefix. It also pins an embedded five-image fence executable.
`directory_fence_profile.json` separately describes that executable and its
one-worker queue qualification fixture. The production fence has 512 worker
slots. The queue fixture is not selected by the production caller.

| Image | HIA owner |
|---:|---|
| 0 | Unified installed configuration, including trusted uninstalled initialization and workspace/remote policy queries |
| 1–4 | Configuration filesystem, typed JSON, validation, and identity |
| 5–6 | Local path authorization and actual existing-ancestor canonicalization |
| 7–10 | Full Session request context, SessionWorkdir, JSON Value, and ClientCapabilities |
| 11 | Directory method ordering, preflight, cancellation, result rendering, and permit ownership |
| 12 | Original PathSource parsing and resolution |
| 13–14 | Actual directory creation and Linux error rendering |
| 15–20 | Regex syntax, Unicode data, HIR, NFA, matcher, and compilation controller |

The compiler is the unchanged d3e2c90173cf733e42b299d0c4274df4b593a12f
checkout. Its B3 SHA-256 is
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
The resulting 5,220,324-byte executable has SHA-256
`b405a68f6e920ffb8c989168bb787e2b643a62ad7f7a68f9431f9ce018ae8780`.

Configuration validation source
`bffa7d3cd65cae422a13589df7a057ff8e01b19bf91f34223cc318f07cb13ecc`
uses actual fixed regex continuations. Its logical child graph is
3→15, 15→10/12/13/14, and 10/12/14→11. These private logical IDs are distinct
from the parent table's physical member IDs. Every source, actual image and
call displacement is pinned; the six regex images receive no OS authority.
`directory_regex_dependencies.json` records the published dependency identities.

The existing unified configuration owner d3dd23f0 is deliberately preserved.
It retains trusted uninstalled initialization and read-only workspace/remote
policy accessors. Updating validation does not replace that private state with
the public projection owner's narrower entry contract.

Regex contexts occupy private metadata bytes 3072..3327 and per-logical-module
sequences start at 3584. Their workspaces extend the original mapping to
3,489,730,624 bytes. Each address constant above 2 GiB is loaded through a
32-bit register before adding the mapping base. The fixed bridge bounds
nesting, checks every borrowed span and overlap, and restores the caller's
input/output/workspace pointers before the original validation continuation.

## Administrator startup

The executable accepts `--runtime-config FILE --session-root RAW_PATH`.
The configuration option may be absent. The absent branch invokes the HIA
owner's trusted kind-4 initialization; it does not counterfeit a failed read or
install memory from the host. Installed configuration and the session root are
immutable startup inputs. `HEPTA_EFFECT_OWNER_FENCE_DIR`,
`HEPTA_EFFECT_OWNER_SELF`, and `HEPTA_EFFECT_OWNER_FENCE_REQUIRED` retain their
original process-start meaning. `USER` retains its original PathSource default
username meaning; it is not an authorization token.

Descriptor 4 is a private, read-only FIFO consumed before ordinary stdin:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 8 | `HMDINIT1` |
| 8 | 8 | Context mode: 0 legacy, 1 modern |
| 16 | 8 | Legacy capability snapshot present: 0 or 1 |
| 24 | 8 | Legacy JSON byte length, at most 8 MiB |
| 32 | variable | Complete legacy snapshot bytes |

All integers are little-endian u64. Absent means length zero. The FIFO must
reach EOF at the exact frame end. Regular files, a write-only descriptor,
trailing bytes, and repeated or malformed initialization are refused. This is
a trusted lifecycle input, not a field accepted from a normal request.

## Private request and response transport

Each stdin record is a u64 byte length followed by:

| Offset | Width | Field |
|---:|---:|---|
| 0 | 8 | `HMDCTL01` |
| 8 | 8 | Command: 1 begin, 2 soft cancellation, 3 outer-future drop |
| 16 | 8 | Nonzero request identifier; new requests increase monotonically |
| 24 | 8 | Payload byte length |
| 32 | variable | Payload |

A begin payload contains `HMDCRQ02`, path length, metadata-presence bit,
metadata length, and a reserved zero word, followed by the UTF-8 path and raw
`_meta` JSON bytes. Its header is 40 bytes. Each variable part is bounded by
8 MiB. The largest complete control record is 16,777,288 bytes, excluding the
outer length word. Soft cancellation and drop have empty payloads.

The full context owner first claims the original SessionWorkdir latch, then
resolves complete modern or legacy ClientCapabilities through its own Value
workspace. It does not treat a raw `experimental` fragment as a complete SDK
context. Configuration, path preflight, local checks, and actual directory
effects follow the original selected method order.

Each stdout record is a u64 byte length followed by `HMDCTR01`, event kind,
request identifier, exact-u32 result, payload length, and payload. Event kinds
are 1 accepted, 2 completed, 3 soft-cancel acknowledged, and 4 drop
acknowledged. Successful acknowledgement events have code zero and no payload.
A completed business result is `HMDCRS01`, tag 0 success or 1 error, reserved
zero, text length, and the original result text. Its code equals its complete
payload length. A cancelled result may instead have code zero and no payload.
Malformed transport terminates with exit 111; normal EOF exits zero after the
required cleanup and drain.

`tests/hia_native/directory_service_support.py::Session` is the reusable test
client for this exact twenty-one-image profile. It checks the executable hash,
keeps the private startup FIFO separate, retains complete wire bytes, and
waits for the process. Its member-count check must not be silently relaxed for
an unrelated profile.

## Permit and worker lifetime

The parent starts one source-pinned fence executable from a sealed memfd and
keeps it for the entire server lifetime. Requests never create replacement
fence owners. The manager's private command 8 polls/takes a real submitted
acquisition without blocking the event loop; a private nonblocking ready FIFO
only signals completion. Actual clear-TID join precedes ready notification.
Queued cancelled acquisitions still finish owner-record validation.

The HIA caller owns the actual permit and decides when to release it. The
fixed adapter starts the HIA mkdir worker, retains its result pipe and PID,
and reaps it before accepting its complete result. Descriptor normalization
preserves every input before assigning 0/1/3/4/5. Parent-death signal setup is
followed by a parent-PID recheck; startup failures, broken pipes, and worker
death retire owned descriptors and children.

The measured original cancellation behavior is deliberately preserved:

| Event | Permit and effect behavior |
|---|---|
| Soft cancellation | The method future remains alive. The submitted mkdir completes; its response is suppressed. |
| Outer future drop | The permit is released while a submitted mkdir worker may still be running. A second admitted call can complete before the first worker is resumed. |
| EOF | Active caller futures are dropped, while already submitted workers are drained and joined. |
| Drop during queued acquisition | The queued blocking validation completes; no cancelled directory effect is started. |
| Parent death | Actual parent/child death and permit release are observed and reaped. |

This is not a claim that the permit always outlives background effects, nor
that a public rmcp cancellation route has already been connected to this
private transport.

## Qualified evidence and limits

The final source-bound run has five native suites (18 groups, 74 native
processes), a fresh explicit Rust 1.95 locked build, 22 paired functional
processes with 67 requests per side, six paired kernel lifecycle cases,
12 paired regex-configuration processes with 18 directory requests and six
startup refusals per side, and six evidence-control groups with 10 accepts
and 31 refusals. Functional
comparison includes complete owned filesystem snapshots, not only replies.
Fault cases separately record ten synthetic errno interventions, one actual
broken pipe, and one actual worker SIGKILL; these are not counted as original
Rust parity cases.

No suite skips a ptrace requirement. The local EPERM failure and the earlier
observer ESRCH race remain separate retained failures. The corrected observer
accepts an ESRCH race only after the same registered task has an actual -9
wait status and a recorded successful owned kill, with all tasks reaped.

Fresh compiler cold qualification is not claimed by this component run: it
reuses and rechecks the existing pinned B1/B2/B3 bootstrap, then actually
recompiles all 30 selected roles. Whole-runtime replacement and public MCP/HTTP
activation remain false here. The older fifteen-image observation remains
separate historical evidence and is not relabelled as this regex profile.

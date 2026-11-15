# Public HIA MCP composition

The executable accepts newline-delimited JSON-RPC on standard input. Arguments
are empty or `--runtime-config PATH`. Its working directory initializes the
single private SessionWorkdir instance. Public JSON cannot choose a private
child, workspace, capability, continuation, lease, or descriptor table.

The catalog contains `host_list`, `effective_config`, `execution_shadow_admit`,
`view`, and `workdir`. This is a partial replacement of the original 125-tool
server. View and Workdir schemas use independently generated and cleaned
assets; schema advertising does not replace actual Serde parameter rules.

## Build and ownership

`scripts/hia_native_runtime_mcp_build.py` declares 46 compiled HIA members.
Default builds freshly compile all members, the pinned upstream HIA ELF
linker, and `runtime_mcp_image_packer.hepta`. The linker first produces the
mechanical prefix. The HIA packer then appends every complete image and fills
17 configuration calls, 20 nonempty public-engine slots, and 19 View-engine
slots. Repeated slots share the same image and private authority.

`native/runtime_mcp_sources.json` binds build inputs, public input generators,
schemas, and the native producer. The evidence reader and refusal suite are
separately bound by qualification receipts, avoiding a manifest self-reference.
The ELF has RX code, an empty RW segment, and a non-executable stack, with no
interpreter or libc. Compiler cold qualification is a separate prerequisite.

## Public engine selectors

These are source-bound private selectors, never public request arguments.

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

The 19-slot View engine retains read/cache/scope/lease, literal search, and
regex search. Configuration and View reuse the same syntax, HIR, NFA, matcher,
and Unicode images. Each graph's selectors are distinct from physical indexes.

## Wide calls and result ownership

The frontend accepts complete raw JSON. State magic is `HRMCFS02`; its
112-byte `HRMCFA02` action begins at workspace offset 256. All lengths,
offsets, capacities, and sequence fields are `u64`. Eight 32-byte region rows
begin at offset 512; arena extent, requested workspace capacity, and growth
kind occupy 384, 392, and 400. Its fixed local children map to public slots
`[19, 1, 0, 10, 2, 13, 11, 20]`.

Return `0xfffffff0` yields an admitted child. The bridge retains a completed
child result. If the parent needs space, `0xffffffcd` acknowledges delivery
only: parent growth does not execute that child again.

Successful frontend return is fixed 64 with `HRCMFR02`: magic, kind,
reserved, prefix length, body length, isError, sequence, reserved. Kind 0 is
silent, 1 is raw JSON-RPC, and 2 transfers prefix/body to the actual result
publisher. Extent is 64 plus both lengths, independent of the u32 return.
Publication imports both full spans before START. PULL/write/ACK never
retain a borrow into a reusable frontend buffer.

Protocol input is `HRJPRQ02` plus mode, JSON length, reserved zero, then JSON.
Output is fixed 192 with `HRJPRR02`, followed by full ID/name/version spans.
Node indexes and offsets are u64; the old 262,144-node cap is absent. The
existing nesting-depth policy of 128 remains.

`HGRWS002` is a 32-byte header: magic, kind, required capacity, reserved zero.
Return is `0xffffffd0`. Kind 1 requests workspace, 2 output, and 3 denotes
an unrepresentable resource boundary. Bridges check arithmetic, preserve live
bytes, and retry only a source-authorized operation. Completed effects are
delivered without replay.

Strict Workdir I/O retains its separate growth ABI. Return `0xffffffef`
requests logical C at workspace offset 40, requiring physical extent
`1,049,600 + 5*C`; `0xffffffee` requests output extent at offset 48. A terminal
RUN is followed by its actual generation-bound DROP before reuse.

## Qualification and unfinished domains

The native producer retains complete wire bytes, stderr, each request's
60-second deadline, and actual private-control buffers. Inputs cover 54 SDK
adapter cases, 13 information cases, 31 ordinary View calls, a 19 MB error,
a 67 MB input/output case, 262,146 JSON values, and 42 local Workdir scenarios
with 336 public calls. It does not read original results. Complete original
comparison is a separate qualification step.

Transport/frontend/gateway byte windows grow dynamically. This does not close
all resource dimensions. Configuration/execution still have legacy capacity
limits, including independently observed failures for wide configuration
roots. Regex retains its workspace/frame profiles. Directory, remote and
background View, HTTP concurrency/cancellation, and remaining public handlers
are incomplete. SDK fixture bodies and empty catalogs are compared only by
explicit protocol/schema projections, never claimed as full original handler
or catalog equivalence.

# Serial public lifecycle graph

This selected graph implements the serial stdio lifecycle used by
`host_list`, `effective_config`, and `execution_shadow_admit`. It is a callable
qualification graph. The production registry remains unchanged: all 125
production handlers and all 10 owner categories remain `not_ported`.
Production activation, complete runtime replacement, and old-stack removal are
false. A component count is not a count of migrated production handlers.

## Selected sources and fixed boundary

`public_lifecycle_graph.json` selects 71 distinct HIA images for 86 fixed roles.
Forty images reuse existing canonical files. Thirty-one required images and one
HIA packer have one selected file each in `native/`; private historical source
trees and duplicate dependency directories are not part of this import.
The graph records every source/image identity and each fixed address or size
slot. The native prefix is assembled from `public_lifecycle_adapter.S` and its
single `public_lifecycle_metadata.S` include. HIA performs all business policy;
the prefix owns fixed allocation, invocation, continuation custody, descriptors,
and transport. Two bounded HIA pack calls construct the complete executable;
neither call exceeds the existing 8 MiB input/output limits.

The public transport accepts JSON-RPC lines through stdio. Only the three tool
names above are within this qualification. Installed configuration comes from
trusted startup arguments, and caller authority comes from the native session
owner. Tool arguments cannot supply an owner, policy binding, installed config,
or private capability. Repeated initialization remains part of the fixed SDK
projection. Canonical JSON-RPC ID and protocol version stay with the dispatcher.

The internal typed response seam retains complete `CallToolResult`/`ErrorData`
bodies. `HRPCTYP1` is the trusted child response; `HRPCRES1` carries the completed
dispatcher response. The private response type is preserved until final SDK
wire normalization. A complete result with `isError=true` remains Complete.

## Effect and ownership order

The outer caller resolves and binds authority before request admission. It
creates the actual audit Ticket, admits a ResultIntent for the two eligible
tools, invokes the tool, attaches request identity, applies the final wire
budget, classifies completion, finishes the actual audit Ticket, completes or
drops the Intent, and attaches the retention acknowledgement. Cancellation is
observed at the original two separate decision points. This serial qualification
does not prove concurrent cancellation or a general asynchronous scheduler.

An early ResultIntent business error preserves the original error result and
its audit identity/acknowledgement. Cleanup drops the Intent and conversion
owner, allowing the next request in the same process. EOF retires remaining
Tickets in their fixed service order before shared owners and configuration.

The repair is one fixed assembly operand:
`mov edi, OFFSET FLAT:tk_CV_BYTES`. Its prior forward `.equ` operand was decoded
as a memory load. The explicit immediate supplies the allocation size when an
early error first needs the metadata conversion workspace. Existing cleanup
logic and all 71 semantic images are unchanged. The direct bridge regression
uses explicit synthetic child results and is reported separately from actual
ResultIntent execution.

## Reproducible qualification and retained history

The native normal suite executes 64 processes and 359 requests, checks every
complete wire response against retained original bytes, and validates complete
live filesystem snapshots. The original recipe performs a fresh Rust 1.95
locked build of the selected 38-file reference, checks 274 unchanged original
blocks and all 138 locked crate archives and installed source members, then
executes another 64 native and 64 original processes with 359 requests each.
Both implementations use the same fixture pathname in sequence. Complete
request/response streams, snapshots, process exit records, and typed retained
payload bytes remain available for read-only admission.

Two cases use an ordinary pre-existing application file at the results-directory
pathname. They require the original business error, remove that owned fixture,
and require subsequent legal calls to succeed in the same process. This suite
does not intercept syscalls, inject kernel failures, or contact remote hosts.
No historical execution is counted as a fresh execution.

Before projecting nondeterministic fields, each snapshot checks real directory
identities and complete anchor hashes; bounds clock values by observations; and
requires raw request ID, owner, tool, and accepted time to agree across audit
and retained records. Payload Base64, length, SHA, and complete pre-ack typed
serialization are checked. These are identity-consistency checks, not an
independent entropy-source qualification. Completed fixtures are retired only
after all captured bytes and metadata have been verified.

The prior repair handoff SHA is
`4ed453bbe3a3c795a1359912bef0334549e2e3aaabb4bedd14c646499734410c`.
Its complete remote archive SHA is
`1dc8739b7e91dfb0981cb1e4cb350a4e20345643c00d77bc62aa5fdf87be13e8`.
The separate local complete-capture archive SHA is
`30a4a706d0b58e8b0d9de291e7727bc8ac1e41c835764e2d989066272693f3cf`.
Those archives retain old failures and actual repair observations outside the
repository. Their 64 paired processes/359 requests per side are historical
evidence for this repair, not a replacement for the portable gates.

## Remaining integration work

This graph does not activate production routes, HTTP, unrestricted concurrent
owners, async cancellation, active Index publication, the remaining handlers,
or whole-runtime replacement. `OwnerScope::annotate` is not supplied by the
Authority subtree. Public Read and Async owners require their own final shared
state and lifecycle integration. Public Read must retain its outer pre-typed
Async observation and its separate handler observation; direct invocation of
the result store is not an equivalent public reference.

The repository still contains older independently qualified modules needed by
existing graphs. Final convergence requires selecting the production call
graph, repacking every dependent image against the selected modules, replacing
every registry/CI reference, proving the complete public behavior, and only then
removing superseded sources. Existing qualification records must not be relabeled
after a dependency change. Historical sources/evidence belong in verified
external archives; they must not be copied back as parallel stage trees.

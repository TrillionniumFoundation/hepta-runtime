# Bellman frontend continuation

This candidate adds one fixed edge to the current public HIA frontend. Its
implementation is the emitted `native/runtime_mcp.hepta`, authored from the
exact 70-function Authority frontend with source SHA-256
`9faea69f883e2d72ae839fc43b46f1ccfb2d5befd9687112f83fd38bf413493e`.
The entry, prepare and name-selection functions gain wrappers; the other
67 original function graphs remain exact. The retained entry admits phases
15–17 only after its original complete-child delivery checks. Removing those
phase and dispatch changes restores the complete original entry graph.

The candidate does not establish public transport, current SDK asynchronous
request ownership, public cancellation, or whole-runtime replacement. Those
require the actual shared worker port and request-task host qualification.

## Fixed private route

The public tool name `weight_bellman_plan` selects frontend tool kind 11.
After the existing protocol, metadata, authority and canonical typed-map
boundaries, frontend child 14 always selects public engine slot 57.
Public JSON never selects a child, private control operation, worker, tag,
workspace, descriptor, or continuation.

| Phase | Complete private request | Complete private reply |
| --- | --- | --- |
| 15 | `HBLTAG01` / 64 bytes / operation 1 | `HBLTGR01` / 32 bytes / fresh private tag |
| 16 | Unchanged `HBLCLQ01` / start, poll or cancel | Unchanged `HBLCLR01` / 64-byte header and every text byte |
| 17 | `HBLRET01` / 64 bytes / operation 1 and tag | `HBLRTR01` / 32 bytes / the retired tag |

Allocation belongs to the attached engine and shared runtime-wide tag
namespace. Start passes the complete canonical argument map from frontend
region 4. Poll and cancel pass no JSON. Every private reply is checked for
exact magic, entry return, complete extent, tag, job and reserved fields.
The bridge's existing retained delivery path handles output growth without
executing a completed child operation again.

Caller status 0 retains the complete success text in region 5 and uses the
unchanged current-target text constructor. Status 1 retains the caller's
complete already-prefixed diagnostic and uses the unchanged `-32602`
JSON-RPC renderer. Status 2 uses the unchanged error text constructor.
The terminal reply is copied before phase 17 retires caller storage.
Status 4 retires storage and returns a silent kind-0 frontend result.
Retirement does not release a running worker's permit.

## Pending is a scheduling boundary

Caller status 3 has no text and a nonzero worker job. It stores frontend phase
97, finishes the current child delivery, and immediately returns 64 with
`HRCMFR02` kind 4. Header words at offsets 16, 24, 32, 40 and 56 are zero;
offset 48 retains the completed child sequence. This is a host-only scheduling
result. It is never passed to the JSON-RPC publisher or written to the peer.
It does not call the ordinary `finish` function, which would reset the phase.

All words are little-endian u64. The pending request has a private 64-byte
workspace record at offset 1280:

| Offset | Meaning |
| --- | --- |
| 1280 | `HBLFRS01` |
| 1288 | Runtime-allocated private tag |
| 1296 | Worker job |
| 1304 | Zero while pending; command 1/2/3 only during a caller turn |
| 1312 | Zero while pending; terminal caller status before retirement |
| 1320 | Last fully delivered child sequence |
| 1328, 1336 | Reserved zero |

The trusted host retains the exact request input, complete frontend workspace
and output, slot-18 descriptor/continuation identity, originating engine and
SDK request generation. A new public request cannot reuse these live objects
or a borrowed child reply. Session state shared by different requests remains
owned by the shared engine's actual owners, not copied into separate pools.

To resume, the host writes exactly 64 bytes at workspace offset 1344:
`HBLFRQ01`, command 2 (poll) or 3 (cancel), the private tag, worker job, last
completed sequence, and three zero words. It then calls the same frontend
entry with the retained original input. The frontend checks every word,
consumes the control once, and enters phase 16. A stale generation, sequence,
tag, job, partial control, unsupported command or nonzero reserved field is
refused. A wholly zero control returns the same pending observation without
polling, cancelling, reallocating a tag or issuing another child.

Valid public cancellation first resolves in the current SDK request-task
registry. The frontend never interprets a public ID or a JSON field as the
private control. The host services the actual worker wake FD and finite
abnormal-reap interval; it never loops synchronously until Bellman completes.
During growth, all offsets are relative to the current retained workspace.
No pointer into an earlier allocation survives relocation.

## Failure and shutdown ownership

Private invalid/capacity/resource results remain runtime errors, not synthetic
business results. An allocation that cannot complete its first caller turn
still belongs to its engine and requires the port's documented cancel/retire
cleanup. A caller waiting for a full reply cannot be discarded merely because
the frontend needs more capacity. On disconnect the SDK host drops interest
for that session's live callers and retires their storage; the shared worker
continues already-admitted computation, rendering and actual process reaping.
The runtime-wide shared worker is shut down and destroyed only after all
engines, READY borrows, retained events and actual workers have drained.

## Evidence scope

The separate pending ABI controls deliberately supply private test-owned
workspace records and child acknowledgments. They test native HIA admission,
fixed capability routing, growth, immutable delivery and cancellation-state
handoff. They are not public-handler, original-Rust or real-worker evidence.
Public activation requires the complete actual port and SDK integration gate.

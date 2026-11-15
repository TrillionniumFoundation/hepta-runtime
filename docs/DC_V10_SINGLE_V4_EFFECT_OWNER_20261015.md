# Optional single-V4-effect-owner V10 facade (2026-10-15)

This is a source-only enhancement to the previously qualified optional
V10/V4 historical read adapter, not a production route change. The default
mode remains read-only and all V10-only effectful tools stay refused.

## Precisely scoped execution contract

The full 66 V10 tool descriptors and annotations are unchanged. With the new
explicit --route-original-v4-effects option, only the exact original
50 tool definitions may execute state changes, and the only upstream for
those effects is the existing V4 at 127.0.0.1:8790. Each successful V4
job or PTY writes the original durable registry, so subsequent
process_status/process_read/process_wait/pty_read operations resolve the
same host-bound original V4 identity. File changes are made by V4 under its
existing account/workspace policy, not by a shadow V10 process. The V10
controller at 127.0.0.1:8791 remains read-only through this adapter.

All six new V10 state-changing tools, including generic operation_start and
request_start, are refused before submission. For original process_cancel
and pty_write/pty_close, provenance must independently bind the exact job or
terminal identity to V4 and not V10; ambiguous, missing or changed identity
is refused. V4 still applies its original command/UID/sudo and host policy;
the adapter never creates a new privilege. All original read-only methods
work as before, and V10-only read-only methods remain directed to V10.

A lost V4 response to an effectful call is recorded as outcome=unknown with
automatic_retry=false, not not_submitted or an automatic V10 retry. V4
and V10 are distinct MCP sessions; a V4 in-flight request cancellation is
only an intent and never forwards a fabricated V10 cancellation. Requests
using legacy MCP must complete original initialize first. No cross-host or
cross-controller task resubmission is performed.

## Actual isolated exercise

8 dedicated offline owner/routing/negative tests passed, plus 16 prior
dual-read provenance tests. Offline coverage includes all 31 original
state-changing tool name routes, all V10-only effectful tool refusals, and
job/PTY owner collision and not-initialized cases. This is dispatch
qualification, NOT independent approval of every parameter of all 31 tools.

One private real V4 test invoked V4 process_start through this 66-tool
adapter; the original job succeeded and retained complete stdout. Repeating
the same idempotency key reused exactly the V4 job ID. Only the V4 durable
job registry gained one record; the V10 job registry gained zero.
Another original V4 tool created a unique 0600 scratch text file, content
and SHA256 independently verified.

One real V4 PTY smoke initially failed because the fixture Python source
contained literal backslash-n characters and exited with code 1. That
original failure was retained, not overwritten/retried. A new PTY
idempotency key then completed with one input, exact original pid,
complete output and normal exit, adding just one V4 PTY record, no
V10 PTY record.

A separate V4-loopback-disconnected negative test returned a truthful
unknown outcome for V4 process_start with no retry to V10, while V10
process_status and its new host_health read-only tool still worked. Private
receipts at:
/home/qian-qi/hepta-runtime-legacy-effect-evidence-r10-20261015/

## Not yet a complete product release

This optional route does not automatically migrate the other V10-only
effectful workflows or all historical search/operation/stream identities;
a dual-controller global admission freeze/shared owner and caller-isolated
request history are not yet proven. Original DC Node-owned SSH descriptors
and their stream buffers are not adopted. The ChatGPT old 50-tool
registration has not refreshed to 66 and no real authenticated 66-tool
model-origin business write was tested. Existing V4, DC, 8791, and Full
Operator tunnel services remain active and unchanged. No production
connector, unit or tunnel profile has been updated;
full_dc_replacement_qualified=false.

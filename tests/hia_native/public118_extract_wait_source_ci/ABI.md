# Actual extract lock WAIT in the public task pump

The candidate keeps 118 HIA images, 111 physical image containers, 64 descriptor
slots and ten installed handlers. Source registration and assembly are separate
from semantic qualification.

## Retained ownership

WAIT is the existing zero-extended 0xffffffdf with no completed child extent.
The fixed pending chain is 18 → 59 → 61 → 62 → 63. Descriptor60 already completed
parameter parsing. Every parent retains its original HIA CALL magic, sequence,
request span and output reservation with empty completion fields. Continuation
busy=1/pending=2 means actual unfinished WAIT; pending=1 retains its existing
meaning of a completed child awaiting delivery. No filesystem action is replayed.

Each request mapping remains4096 bytes plus its original guard page. Added
private fields: active@480, five descriptors@512, five continuations@832,
body-context@1152, caller-installed@1160, work-ownership@1168 and
output-ownership@1176. Existing engine context@456 and installed@464 transfer
with that exact lifetime. Only bitmap bits59..63 transfer. Rows59..62 own their
work/output mappings; row63 borrows the callable's retained output.

Completed extract requests retain this same context until actual SDK response
retirement. Later typed/admission failures may leave idle reusable rows; only
idle completed mappings are retired before installing a saved future. The
existing HIA caller owns same-session Scope/cache/hints/drain, and the existing
HIA gateway owns effect-admission release.

## Actual wake and destruction

Shared hub additions: linked-head@192, wake-sequence@200, linked-count@208.
Outer callable context additions: linked@512, lease@520, ready@528, next@536,
node@544, wake-sequence@552, wake-operation@560. The original192-byte callable
ABI and cache/hint callback fields keep their meaning.

Only a complete actual HRFLKR01 cancel/unlock/drop result can mark ready.
Its offset56 supplies the exact HIA-reserved lease. The lock owner is local3
for Text/extract and local7 for Batch. Conditional hooks observe that actual
owner and direct drop-lease returns. Standalone builds without the hook retain
their original paths.

The event loop resumes only a ready retained extract. Poll timeout alone never
executes its HIA body. The existing local_extract_lines_resume entry completes
the same CALL; another WAIT retains that future. Notification cancellation
delivers the original SDK context token and leaves the handler running, because
the original extract gateway does not poll that token.

Only actual future destruction after writer/transport close uses
local_extract_lines_cancel_wait. It drops the actual WAIT lease through the
original HIA lock state. The original caller then drains Scope, and the gateway
releases effect admission. The frontend admits CANCELLED/empty only for its
extract child15/phase6 continuation and returns silence. Its old after_tool
function remains exact as f93. Registry58 observes actual Drop and retirement.

This adds no cancellation of synchronous in-flight file syscalls. Asynchronous
worker I/O, remote execution and full SDK qualification remain separate.

## Complete private observations

Production selects no observation descriptor. Existing FD4 events remain; an
actual WAIT has no invented HRCMFR02 response. Following extract detach/restore/
retire, additional events copy the actual retained mappings:

- Event9: complete4096-byte node, outer context and callable control.
- Event15: complete4096-byte hub and16384-byte extra engine.
- Six event10 records: descriptor and complete work/output capacities, in fixed
  order frontend18 then59..63.
- Fourteen event11 records: actual callable descriptor rows and full buffers.
- Two event12 records: actual shared lock/history rows and full buffers.
- Five event13 records: exact pointer/capacity pairs and complete owned input,
  callback, auxiliary, mkdir request and mkdir workspace.
- Event14: cache/hint frame pair and complete allocation.

Absent zero-length mappings are recorded exactly. Observation never invokes an
owner, acknowledges a write or creates a wake. Shared View owners retain their
separate observation contracts; these records do not claim every process
allocation is captured.

## Qualification boundaries

The58e1 ordinary body/typed/session/context, raw108, custom142, opener15 and
new valid-host catalog11 original domains remain retained. Invalid no-host
startup failures also remain explicit evidence. This successor requires fresh
native regression against retained original references and a distinct original/
native actual lock-contention domain covering FIFO, independent progress,
token cancellation, EOF Drop and complete filesystem/cache/history/lock effects.

Budgets stay60 seconds per exchange,180 per lane,900 per graph and15 minutes per
job. This source package and its assembler checks execute neither HIA nor Rust.

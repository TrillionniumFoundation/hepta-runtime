# V10 + V4 native job/PTY read-custody adapter — 2026-10-15

This is a separate optional stdio MCP entrypoint, not an activated
replacement for the existing 50-tool ChatGPT plugin.

## Problem independently reproduced

The live original V4 at localhost:8790 can read its original durable job
identities, including a success and a timed-out ROG job, but V10 at
localhost:8791 cannot read the same IDs. The inverse is also true for
V10-owned jobs. A direct tunnel switch would make historical jobs and their
original outputs appear missing, even when the dispatch queue is empty.

## What this actually implements

The new deploy/chatgpt_v10_dual_read.py advertises and checks the exact
66-tool V10 catalog. It routes four read-only methods — process_status,
process_read, process_wait, pty_read — to the original V4 only if an exact,
host-bound original controller record exists and no matching record exists
in V10. Both controller-local roots are account-owned mode 0700, their
subdirectories are private, and metadata is read with O_NOFOLLOW, bounded
sizes, identity and post-read stability checks. A metadata ambiguity
or corruption is a refusal, never a guessing heuristic or retry.

The original V4 uses its separately pinned 50-tool contract and local
token; V10 uses its 66-tool contract and separate token. Both are
loopback HTTP only. No original result, credential or remote task is copied
to the source repository. Modern tool responses preserve original native
content and add the existing V10 presentation metadata.

EVERY state-changing tool is refused before dispatch to either controller.
This is deliberate: duplicate idempotency keys across independent V4/V10
launch domains could otherwise execute twice during migration. Merely
checking an empty queue is not sufficient to prevent that race.

## Real live loopback proof (private receipts)

A temporary stdio child connected to both real controllers:
- Discovered all 66 V10 tools, retaining the unchanged original 50 definitions.
- Read original V4 success, timeout, output and exited PTY through the new
  facade, plus a V4 process_wait terminal result.
- Read original V10 job and exited PTY through that same facade.
- Refused process_start, process_cancel and pty_write before dispatch.
- Exited normally, without touching production units or DC sessions.

15 synthetic ownership/path tests passed. Live private receipt:
 /home/qian-qi/hepta-runtime-legacy-read-evidence-r9-20261015/result.json

## Honest remaining boundary

This adapter is NOT enabled in the production Full Operator tunnel and
is not a full 66-tool action connection in ChatGPT. It deliberately blocks
all writes, creates, signals, cancels, and PTY input. Legacy asynchronous
request and stream_handoff controller operations are not migrated here.
Two original Desktop Commander-owned SSH sessions are neither duplicated
nor adopted. Original DC-held buffers are not accessible through Hepta's
job or PTY registries. No production admission freeze, owner transfer,
model-origin 66-tool Refresh/Review or authorized DC-off rollback occurred.

The old V4 service must stay running for its histories while this adapter
is used. A production-grade write-capable transfer needs one coherent
launch idempotency authority or a fully frozen/drained old writer first.
The root mode checks validate original controller-local roots, not the
group-writable host-state archive roots for six remote machines.

full_dc_replacement_qualified=false.

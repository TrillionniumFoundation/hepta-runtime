# X230 controller → AI395 executor: eight-job native concurrency acceptance

This is a new, fixed direct-SSH acceptance attempt. It is separate from the old
current-agent observation-pool acceptance and makes no performance-improvement,
six-host, reboot or power-loss claim. Only the root agent may execute it remotely.

## Admission and scope

Before creating either fixture, bind the complete qualified A54 r01 source/release
receipt, the byte-frozen original Controller library (SHA-256
`8ed769c4ca6a44cfd4c38ab31a6b378025f4e84ab13f77e564bbd70a1e594f7a`), this
harness and helper, the new `native-ai395` flattened config and trusted host-key
file, and the independent AI395 operator identity receipt. Missing values or
pending qualification prohibit fixture creation. Recheck the actual target
UID/home/hostname/boot/machine/Python through the new profile before creation.

The local fixture is one fresh direct child of the existing X230 development
directory, named `a54-native-concurrency-r01`. The only remote fixture is the new
private directory `/home/qq/hepta-runtime-native-concurrency-a54-r01`. Existing
authentication files, production services and other jobs are not changed.

## Fixed business and RPC schedule

- One qualified Rust MCP controller, two Tokio workers, one stdio MCP connection.
- Eight distinct `process_start` requests are registered as pending before the
  batch is written. Each has a unique idempotency key, a 30-second owner timeout,
  a 64 MiB memory ceiling, nice 10, and an exclusive ready/effect pathname.
- Each controlled Python business writes one exclusive ready receipt, waits at
  most 24 seconds for all eight ready receipts, then uses one fixed staggered
  delay, writes one exclusive effect receipt, and emits fixed stdout/stderr.
  Expected exits are `[0, 3, 0, 7, 0, 2, 0, 5]`. No business can run indefinitely.
- Read all eight start replies by JSON-RPC ID, accepting arbitrary arrival order.
  Record the actual reply-arrival order; an in-order observation is never renamed
  out-of-order. One batch of eight same-key requests must return the same original
  identities, `reused=true`, `retried_launch=false`, and no new launch.
- Poll terminal status in concurrent eight-request batches within the fixed
  active budget; preserve all responses. A final mixed batch has eight statuses
  and eight output reads outstanding together. Verify exit codes, durable complete
  output, exact stdout/stderr bytes and cursors, with a fixed final same-key batch.
- On AI395 only, use the recorded monotonic start/end observations to prove all
  eight businesses overlapped. Never subtract X230 and AI395 monotonic clocks.

## Independent final reconciliation and ownership

The remote helper has only `probe`, `prepare`, immutable `bindings`, and final
`snapshot` modes. It cannot
start or signal business work. It reads only the fixed newly created fixture,
enforces regular single-link files and bounded stable reads, and returns all
original job metadata, output and effect evidence. Final reconciliation requires
exactly eight local job records, exactly eight remote job directories, one effect
per slot, unchanged original request/owner/runner bindings, exact stdin/output,
and exit witnesses bound to the original job/launch nonce and exact exit bytes.

Before the first same-key request, an independent bindings read freezes the
original request, owner intent/start, child, runner, launch and stdin files.
The final snapshot must retain each exact file and filesystem identity.

Each short SSH helper invocation owns its original Popen and pidfd and records
actual raw wait4 before returning or raising. No helper SSH child may remain
unreaped when Controller.stop runs. The Controller library's subreaper cleanup
therefore cannot reap an independently owned helper child. Normal shutdown must
finish with EOF, exit zero, no cleanup signal, no adopted orphan and an actual
original-controller wait4 receipt.

The active schedule is capped at 90 seconds, preserving cleanup time within the
absolute 180-second attempt budget. Failure stops new business submissions and
retains all attempted/pending requests. There is no replacement key or automatic
rerun. The original remote owners retain their 30-second business deadlines.

Report controller lifetime wall time and original wait4 CPU/RSS, plus separately
owned SSH-helper wait4 observations. Remote business resource samples are taken
inside the controlled business before its final effect fsync/output/exit, and are
explicitly not complete owner lifetime or comparative performance measurements.

Static/no-business self-checks cover out-of-order and duplicate/unknown RPC reply
handling and owned short-child cleanup. The actual eight-job run requires a
complete same-source Linux custody selfcheck receipt. The preparation executor
does not expose the required proc child inventory, so its three original-child
checks remain explicitly unexecuted; root must run `selfcheck.py
--require-custody` on X230 before freezing the actual execution plan. No live
remote run occurs in preparation.

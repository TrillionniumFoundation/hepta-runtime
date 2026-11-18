# Worker transport request and result owners

Copyright 2026 Muvon Un Limited and TrillionniumFoundation. SPDX-License-Identifier: Apache-2.0.

## Qualified scope

The callable combines 32 HIA semantic images: the unchanged 23-image CancellationToken/Timer/Handle/channel parent, five unchanged ServerMessage images, and four Worker request/result Drop/Take images. This is a finite creator-thread ownership implementation for `WorkerSendRequest<LocalSessionWorker>` with cancellation registration `None`, plus `Result<(), LocalWorkerError>` with actual `Ok(())` values. It does not implement `WorkerTransport::spawn`, `send`, `receive`, `close`, the complete LocalSessionWorker, nonempty cancellation registrations, or an actual LocalWorkerError child.

The four HIA policies make validation, ownership, effect-order and continuation decisions. Fixed assembly executes ValueLease operations, calls those policies and records actual callbacks. Python qualification programs construct and observe fixtures; they are not a production implementation. All integers below are little-endian u64 unless stated otherwise. Live owners use the existing read-only 80-byte `HRVLS001` ValueLease descriptor and the same cooperative scheduler as their children. No clone or forget primitive is added.

## Request payload and ownership

| Offset | 48-byte `HRSWR001` payload |
| --- | --- |
| 0 | Eight-byte magic |
| 8 | Owned actual ServerMessage ValueLease |
| 16 | Owned oneshot TX ValueLease for `Result<(), LocalWorkerError>` |
| 24 | Cancellation registration; exactly zero in this domain |
| 32 | Control generation; the entire u64 range is accepted |
| 40 | Zero |

Message and responder are nonzero, distinct and different from the enclosing descriptor. Drop calls the actual message destructor first and the responder destructor second. The responder destructor performs the real channel transition, including actual waiter notification. The typed observer tag is **11**; a complete request Drop has three HIA entries and two child effects.

`worker_send_request_take(lease, output, capacity)` returns 80 or an error code. It consumes only the outer descriptor/payload storage, transferring both owned fields to the caller. The caller must subsequently use or drop them. The 80-byte reply is `HRSWFR01`, generation at 8, old descriptor address at 16, payload length 48 at 24, and the original 48 payload bytes at 32. Tag **13** records two HIA entries and one storage-consume effect. A capacity below 80 leaves the live lease and caller output unchanged. A WorkerResult lease is rejected by this export.

## WorkerResult payload and ownership

| Offset | 32-byte `HRWRV001` payload |
| --- | --- |
| 0 | Eight-byte magic |
| 8 | Kind; exactly 1 for unit result |
| 16 | 0 for Ok, 1 for Err |
| 24 | Zero for Ok; owned LocalWorkerError child for Err |

WorkerResult is a separate type from `HRSRS001` SessionResult. The policy validates both representations, but physical ownership qualification currently covers only **Ok(())**. No probe or unrelated error is substituted for an Err child. A nonzero child must differ from its outer descriptor.

`worker_result_drop_entry` has tag **14**. Actual Ok Drop executes one HIA entry and no child effect. The Err branch is not physically qualified. `worker_result_take(lease, output, capacity)` returns a 64-byte `HRWRFR01`: generation at 8, old descriptor at 16, payload length 32 at 24, and payload bytes at 32. It consumes outer storage, with tag **15**, two HIA entries and one effect. Capacity below 64 and wrong-type leases are rejected without consuming the lease or changing caller output.

## Private policy input and continuation

All four policies accept `HRTDQ001`: descriptor at 8, nonzero lease generation at 16, nonzero scheduler at 24, payload length at 32, zero bytes 40–63 and the exact payload from 64. Request input is 112 bytes; result input is 96 bytes. Each requires a zero-initialized 2,048-byte workspace. Drop needs 80 output bytes, Request Take 80 and Result Take 64. Error codes are u32: invalid `0xffffffff`, capacity `0xfffffffe`, effect continuation `0xfffffff0`.

The immutable input snapshot starts at workspace 256. The 128-byte action is at 512; its immutable shadow is at 640. Drop actions use `HRTDA001`; Take uses `HRWSTA01` or `HRWRTA01`. Action fields are kind at +8, monotonic sequence +16, lease generation +24, target descriptor +32, zero operands +40 through +64, child output offset 1024 at +72 and child output capacity 80 at +80. The first 88 bytes must match their shadow. Only the 40-byte completion suffix is mutable: done at +88 must become 1; child code at +96, child length at +104 and remaining +112/+120 are zero for these operations. Drop child outputs also remain zero. Re-entering before acknowledgement, modifying input/shadow/sequence, dirty reserved state and replaying a terminal continuation are refused without modifying workspace or output.

Request Drop plans two kind-1 effects. Take plans one kind-4 outer-storage consume. Terminal Drop emits `HRTDR001`, generation at 16, old descriptor at 24, type tag at 32, effect count at 40 and zero context-retired field at 48. The fixed adapter owns callback arenas, validates real child results, and releases those arenas after completion.

## Actual Waker observer bridge

The frozen native defaults still perform all physical retain, release and notification work. `channel_waker_observer_table()` returns a link-time `HRSMVT01` relative callback table: the fixed wrappers call `sem_default_clone`, `sem_default_drop` or `sem_default_wake`, then append a record to the borrowed `HROBS001` observer at scheduler offset 632. The observed kinds are 1 clone, 2 drop and 4 consuming wake. Oneshot creation receives the same observer as its third argument; its notification uses kind 3 (`wake_by_ref`) and its final release remains a separate kind 2. Typed callbacks use scheduler offset 640. The bridge changes no HIA image or parent export offset.

## Evidence and limits

Callable build v3 (4311) reused all 32 semantic images, ran zero semantic compiles and five HIA packer compiles/packs. Native v2 (4312) passed 72 cases in each scheduler mode. Each mode exercised 72 real ServerMessage factories, 72 oneshot channels, 40 MPSC channels, 24 owned reply sends, 24 request Takes, eight result Takes, and 392 typed callbacks. Actual observer counts are 56 Waker clones, 40 drops, 40 wake-by-ref callbacks and 16 consuming wakes. Both canonical files are byte-identical.

Each case checks the exact guarded allocation mapping set before scheduler creation and after scheduler destruction, balanced FD sets, actual callback-arena retirement and live descriptor/payload read-only mappings. Historical virtual addresses can be reused by later writable Python allocations; those reuses are separately recorded rather than reported as unmapped. No read-only/RX native owner mapping may remain at a historical address after retirement. The qualifier retains full descriptor/payload bytes and every physical export ENTER/RETURN.

Private v1 (4314) uses 96 retained real Native input frames. It made 1,235 actual HIA entries, 192 valid sequences and 803 immutable refusals, including 24 capacity refusals. Its 240 child acknowledgements are explicitly synthetic, with **zero physical callbacks and zero Original executions**. It does not qualify the WorkerResult Err branch.

Composer v1 (430c) rejected an external-envelope schema before any compilation; v2 corrected strict parsing. Native v1 (430e) failed an address-retirement assertion after seven completed cases and lacked attached Waker observers. Its result is not admitted as complete. V3 assembly/v2 Native add actual observers and whole guarded-allocation checks; all failed attempts remain immutable evidence. Actual Original comparison and complete archival admission are delivered separately; production activation and full Worker remain false.

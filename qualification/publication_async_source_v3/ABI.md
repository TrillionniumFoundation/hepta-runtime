# Publisher asynchronous public boundary

This source candidate extends only production `320862f03902153b5c804d1b68142126a9c7a606`. The original 486 source files and all preserved Extract, Bellman, Batch, Authority and SDK owners are verified before composition. No application qualification is claimed by source authoring or GNU assembly.

## Fixed ownership

| Owner | Fixed location | Lifetime |
|---|---|---|
| Publisher gateway / typed parameters / caller | slots 64 / 65 / 66 | One handler future |
| Publication worker bridge | slot 67, descriptor +8 | Native HTPAWC01 context, 4096 usable bytes |
| Existing cache Forget capability | slot 68 | Current caller's actual Scope output loan |
| Blocking pool | shared process hub +216 | Created lazily, 512 active-body limit, all owned children reaped before destruction |
| Publisher retained mappings | PN [1184, 1896) | Actual descriptors 64–68 and their complete continuations, plus native context/job/tag |
| Effect fence 27 | existing PN [3584, 3744) | Existing complete admitted guard, retained until actual release |
| Scope 6 and Context 10 | existing PN [3744, 3888) | Request owned; lease 7 and cache 8 stay shared |

The bridge accepts only the actual caller66 child2 input loan. The retained edges are exactly 18→64→66→67. Raw WAIT is 0xffffffdf with zero result extent; parent continuations retain busy=1, pending=2, the original sequence, input and complete owned mappings. There is no invented HRCMFR02 result. Ordinary completion remains raw64 with the complete HTPBS001 response extent, and the real worker borrow lasts until caller delivery and task retirement.

The native context holds magic HTPAWC01, bytes4096, engine@16, hub@24, pool@32, job@40, tag@48, stage@56, private PN@64, full 320-byte HIA worker reply@128 and full 64-byte HPTWB001 borrow@448. Stage1 is admitted/pending, stage2 owns the worker result loan, stage3 records actual future Drop. No public JSON field selects a pointer, job, private tag, context or operation.

## Completion and cancellation

A real worker owns the full copied HTPBQ001 input before enqueue. The previously qualified native worker and publication callable bytes are unchanged. An actual completed worker reply resumes the saved caller; its original post-await order remains complete result copy → actual lock key → active Scope cache Forget → hints → Scope close → outer fence release → SDK response publication.

A notifications/cancelled token changes only the actual SDK registry. It does not send private command3 or cancel a blocking body. The handler continues to its normal post-await Forget; the registry's existing generation policy decides whether its wire is delivered.

Only destruction of the actual handler future sends command3. The worker records Drop but continues an admitted blocking body. The new caller wrapper accepts CANCELLED (0xfffffff7) only at phase3, child2, body substate0, active Scope and zero extent. It calls the existing Scope op8 cancellation path, skips post-await Forget and returns the existing CANCELLED result. The gateway's unchanged cancellation path releases the actual effect fence. The frontend accepts that exact empty result only from child15 (existing Extract) or child16 (Publisher), phase6, and creates its original silent result.

EOF preserves the existing SDK order: old sends and queued responses → bounded drain → writer lock and actual close → context cancellation → actual future destruction → registry retirement → owned worker service/reap. Publication pool close/drain is after handler destruction. No body is killed to shorten EOF.

## Mechanical observations

Production has no worker observer. A separate compiled fixture requires original FD3 Bellman journal, FD4 complete task trace and FD6 complete publisher worker journal. FD6 is checked before configuration opens files and remains caller owned. Its callback is the previously qualified full HPTWJR01 writer with renamed local labels and an explicit FD6 argument. Public arguments and environment values never select observations.

Private serial filesystem carriers wait only on the actual publication worker wake and re-enter the same retained HIA CALL. They do not stand in for the production asynchronous pump. Their two sessions release all real descriptor borrows before the shared process pool closes and reaps.

## Qualification boundary

Source composition verifies every unchanged function AST and the complete inverse of each mechanical splice. New caller f4 relocates the exact old function to f43. Frontend f6 changes only the accepted fixed child set; all other 96 functions remain exact. All HIA composition JSON is read/written using Python unbounded integers; no JavaScript parse/stringify of u64 metadata is used.

The graph has 116 direct HIA images plus the existing packed eight-image Bellman capability: 124 HIA images in 117 physical containers, still 69 fixed descriptors and a 16 KiB engine. These counts are build structure, not a public-handler qualification count.

Full SDK, complete asynchronous TextEditor/Batch/remote behavior, 136 routes, audit integration and old stack removal remain false. Actual public async and regression qualification follow the source-only gate.

# Canonical file locks with shared native state

This internal Linux x86-64 component composes the unchanged HIA canonical-key and lock-state owners. A fixed native boundary runs four actual Linux threads. Each thread owns its controller buffers, canonicalization buffers and two directory descriptor slots. One state arena is shared by all four threads and is accessed only while holding its native compare-and-swap/futex mutex. It is a component interface, not an MCP tool or a path authorization interface.

The original semantic owner is the complete `FILE_LOCKS` block in `src/mcp/fs/text_editing.rs` at runtime commit `a0dcdda1991ec536d5e2d252c006a778993fa566`, with the unchanged `PathSource` type and remote key method from `src/mcp/fs/remote.rs`. Its original source hashes and locked Rust dependency identities remain those of the separate file-lock component. `native/file_locks_abi.md` defines every state transition and canonical-key rule. This component preserves those owners byte for byte; it adds their real caller, shared arena custody and native thread boundary.

## Fixed images and authority

| Image | Owner | Permitted boundary |
|---|---|---|
| 0 | `file_lock_service.hepta` | Request canonical key 1, then state 2; other state operations call 2 directly |
| 1 | `file_lock_key.hepta` | The existing closed canonicalization effect set and two private descriptor slots |
| 2 | `file_lock_state.hepta` | Pure state transitions inside the shared arena mutex; checked arena growth |

The executable contains these three exact images in this order. The 32-byte table at offset 5,872 contains their three lengths and `HFLKSIM1`; images begin at offset 5,904. The HIA packer emits the complete static ELF prefix and image bytes. The strict builder verifies the normalized prefix, whole ELF, image order, every actual embedded image, compiler dependency and complete native compile/pack receipts. Authoring assembly is not needed to build or run the final component.

Input is immutable while a controller is running. The controller workspace is temporarily read-only while a child borrows its request. Children cannot read native metadata or select another image. The canonical child never holds the shared state mutex. The state boundary acquires that mutex **before** reading the arena pointer and capacity; growth, complete copying, publication of both values and retirement of the old allocation occur before releasing it. No other worker retains an old arena pointer.

## Request and result

The internal request is a 64-byte little-endian header followed by the raw path and host bytes:

| Offset | Width | Value |
|---:|---:|---|
| 0 | 8 | `HRLKSRV1` |
| 8 | 8 | Operation 1 through 7 |
| 16 | 8 | Lease identifier, or zero for acquire/statistics |
| 24 | 8 | Path kind: 1 Local, 2 Remote; zero for other operations |
| 32 | 8 | Path byte length |
| 40 | 8 | Host byte length |
| 48 | 8 | Remote port, at most 65,535; zero for Local |
| 56 | 8 | Zero |

Operation 1 accepts a raw Unix Local path, including invalid UTF-8 or NUL, because these belong to the original canonicalization/fallback domain. A Remote path and host must be UTF-8. Port, host and kind rules follow the original typed owner. Exact frame length is mandatory. Remote processing formats the original lock key; it performs no SSH/SFTP operation.

Operations 2 clone a lease, 3 poll it, 4 cancel an unheld waiter, 5 release a held guard, 6 drop a lease, and 7 inspect statistics. Operations 2–6 require a nonzero lease; operation 7 requires zero. Their path fields must all be zero. The input cannot initialize or destroy the shared arena: lifecycle operations 0 and 9 remain private to the native process boundary.

A successful result is the unchanged 64-byte `HRFLKR01` state response. Its operation, status, lease, node, map count, strong-reference count and awakened-lease fields have the meanings in `file_locks_abi.md`. `0xffffffff` refuses a malformed frame, `0xfffffffe` refuses a supplied buffer capacity, and `0xfffffff9` refuses a state or continuation contract. Those returns publish no result bytes. Capacity is not substituted for an original semantic error or a reduced operation domain.

The transport accepts `u64 byte_length`, `u64 request_tag`, then the complete request. Each reply is `u64 request_tag`, `u64 Linux_thread_id`, `u32 code`, followed by 64 bytes only when the code is 64. Tags correlate replies; concurrent replies may be reordered. The thread identifier is qualification/transport information, not an authorization capability. It cannot select a worker or a state arena. There is no request path, lease or descriptor authority shared with an unrelated process.

The four worker slots apply transport backpressure. They do not cap the original map at four keys or leases. State storage grows from the native allocator; the original `len > 1024` sweep threshold remains a cleanup condition, not a quota. Complete 5 MiB raw path inputs, including their larger UTF-8-lossy keys, are exercised through the dynamic executable. The existing `history.v1` direct-image carrier is unchanged and remains a separate, bounded test carrier.

## Controller continuation

The controller's private workspace starts with phase, original input length, child sequence and growth requirement at offsets 0, 8, 16 and 24. The child descriptor occupies bytes 64–191. Request/body storage begins at offset 256. The descriptor contains `HFLCKCAL`, sequence, fixed child id, input offset/length, output offset/capacity, return code, actual output length, completion word and six zero words. Initial child receipt words are zero; the native boundary writes the result and completion word after the child returns.

Phase 0 admits a fresh request. A valid short workspace returns `0xffffffef` with the exact requested extent at offset 24; no semantic operation occurs. Child continuation `0xfffffff0` requests key 1 or state 2. Key output begins at 288, so its 32-byte header leaves the canonical bytes at 320, immediately after the later 64-byte state request. The controller checks key header, kind, exact returned length and UTF-8 before submitting state. It checks the complete 64-byte state result and allowed status before publishing it. Phase 100 is terminal; a second invocation refuses it. The fixed native boundary rejects dirty upper return bits, undeclared return codes, illegal child order, invalid spans and reused growth/call phases.

There are no cryptographic secrets in this owner. Output beyond the returned result is not published. Refusal tests distinguish unchanged output/workspace from the explicitly permitted growth requirement or terminal continuation updates; they do not infer whole-buffer erasure from a short return.

## Thread and descriptor lifetime

The native boundary creates four `clone` threads with private guarded stacks and private caller/key mappings. It publishes work with an atomic exchange, waits with an atomic futex comparison, and serializes complete stdout frames separately from lock-state access. Idle publication increments an availability epoch so the input thread cannot miss a wakeup. At EOF it waits for each worker to finish, publishes its exit state and waits for the kernel's clear-TID notification before process exit. Broken stdout and fatal child contracts terminate the entire owned thread group.

Canonical descriptor handling is unchanged from the qualified key boundary: descriptor zero is valid, each slot is retired before a single close attempt, and an interrupted close is not blindly retried. The service kernel supervisor restricts memory inspection to the owned process/thread group and retains startup, input/output transport and every owner syscall separately. Its second operation is admitted only after the first complete response. Real random thread IDs and descriptor numbers are normalized solely for comparison; no owner event is selected away to obtain a match.

## Scope of qualification

The native suite exercises all 51,783 non-lifecycle state transitions from the existing complete 23-session corpus, 89,715 canonical-key inputs followed by real acquire/drop operations, and 6,210 operations across four actual threads. Concurrent tests cover alias identity, one held guard, pending cancellation, and 2,080 retained leases while the shared arena grows. The original Rust recipe must compile the unchanged owner again with locked dependencies, compare all 231,214 sequential result frames byte for byte, and separately execute the 6,210 original concurrent-property operations. Nondeterministic concurrent ordering is not represented as a byte-identical original schedule.

The native boundary has a separate real 112-case paired kernel domain. It keeps its 15-second supervisor and 20-second subprocess limits. Both the original and native sides execute acquire and drop; all normalized owner events and complete resulting state frames must match. Controller fault fixtures and deliberately invalid flat-image return fixtures are separate adapter domains and are not counted as original-owner cases.

This component does **not** implement an automatic async waiter scheduler, a public guard capability, caller cancellation/drop orchestration, or the edit/create/delete/undo disk-operation chain. A trusted caller must still poll, react to awakened-lease identities and release/cancel/drop in the correct order. In particular, the original asynchronous file worker can outlive cancellation of its await; a later caller must preserve that behavior rather than silently retaining a guard until worker drain. Production activation, all 125 MCP handler migrations, full-runtime replacement and old-stack removal remain false.

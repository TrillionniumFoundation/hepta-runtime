# Bellman worker port for the public engine

This stage composes the frozen three-image Bellman caller and the frozen five-image worker. It introduces no solver, commitment writer, result renderer, parameter decoder, business-error mapping or permit policy. The current implementation and public qualification remain pending.

## Fixed ownership

The current 91-image public engine stores its descriptor-table pointer at engine offset 8. Slot 57 is reserved for the Bellman caller; the production table must grow from 57 to 58 entries. The existing private fixture observation selector 57 has a separate entry and is not a production selector.

The engine has no current reads or writes at offsets 440 and 448. Offset 440 will hold a private port context, and offset 448 will record its installation/borrow state. That context holds one runtime-owned `bellman_worker_init` handle, the global private tag allocator, READY events and any completed child reply awaiting capacity delivery. A request does not create a pool. A future multi-session or HTTP host must attach its engines to the same runtime context; creating a new handle per session would change the original process-wide two-permit contract.

The public frontend assigns the caller a fresh nonzero private tag through this runtime capability. Public MCP request IDs, peer metadata and JSON parameters cannot select it. The tag must not wrap or collide with an active caller. MCP response identity remains in the existing frontend/SDK pending-request owners.

## Caller edge

The unmodified caller accepts `HBLCLQ01` and emits `HBLCLR01`. Its `0xfffffff0` continuation is the complete 112-byte `HBLCAC01` descriptor at workspace offset 256. Targets 0 and 1 enter the frozen parameter and diagnostic callable adapters. Target 2 enters the persistent worker. All relative offsets are checked against the current workspace after every growth; no old address survives relocation.

Target 2 receives the complete `HBWKRQ01` frame, without the standalone fixture's outer length. Public work always has hold word zero. A mode-0 action executes exactly one worker control. It drains the actual worker FIFO, copies every event-2 READY frame into the port's owned event queue, and associates the complete event-1 reply with the caller tag, job and action sequence. It never creates completion or elapsed values.

The worker's receive pointer is a borrow. Before another control, poll, receive, shutdown or destroy operation, the port copies the entire needed frame into its own retained storage and releases the exact borrow token. READY events are delivered to the enclosing host in their observed FIFO order; they are not converted into public responses or discarded because a caller cancelled.

When the caller's output region is large enough, the adapter copies the complete event-1 `HBPMSR01` frame and acknowledges the exact action sequence with both bridge return and complete extent equal to its full length. The frame's inner raw return word is unchanged. If the region is too small, it acknowledges `0xffffffcd` and the required complete length. A subsequent mode-1 delivery must match the retained sequence, caller identity and complete original input. It copies only that retained reply and cannot repeat control, admission, cancellation, POLL or TAKE.

## Host scheduling boundary

A caller status 3 is a genuine pending result and must return control to the host. It is not an empty success or a reason to block the public input loop. The host services the worker wake descriptor and a finite periodic reap check for abnormal exits, and resumes the appropriate caller with command 2 only between completed continuation turns. A valid public cancellation notification must resolve through the existing SDK request lifecycle before the host sends caller command 3. Cancellation never calls worker destroy, kills a worker or releases its permit.

The current public engine's serial request pump does not by itself qualify overlapping public requests or notification-driven cancellation. The port can be qualified first through the same actual caller/worker APIs and full FIFO capture; public activation additionally requires the enclosing input pump and pending-request storage to resume and cancel these continuations correctly.

## Teardown

Closing a caller retires its own result interest only. Runtime shutdown calls the worker shutdown export once, continues servicing actual completion and reap events, releases every outstanding borrow, and drains every retained event before destroy. `BUSY` remains a live resource state. It must not be translated into successful cleanup, an original Rust panic or a business error. The engine context and shared handle remain allocated until all actual worker tasks and borrowed/retained frames have retired.

## Fixed inputs

- Caller source: `integration-work/bellman-call-v1/checkpoint-v4`; its three HIA images remain unchanged.
- Worker portable source: `blocking-worker-work/v1/portable-stage/source-v1`, source pin `1cd154ed65c8b1478f29f4eb9d9835f8076f65932359c29c29d43649b07937db`.
- Callable worker ELF: 849,219 bytes, SHA-256 `6e68e9bb5a95513402e8555ba452d954a0fc51789b709d5a8d06523449a517c8`.
- Worker source checkpoint: commit `5ce3c86534dd230d79b8d0d32ea07cc0bfc104ca`; combined CI is independently tracked. No public qualification follows from this document.

## Frozen frontend edge, revision 1

The production mapping is frontend child **14** to public engine slot **57**.
Child 12 remains authority and child 13 remains Batch. This slot is a fixed
private capability. JSON-RPC parameters cannot choose a control operation, tag,
worker pointer, image address, or qualification hold mode.

The slot accepts exactly these private frames. All words are little-endian
u64 and every stated reserved word must be zero.

| Private request | Complete input | Complete output | Entry return |
| --- | --- | --- | --- |
| Allocate a caller | 64 bytes: `HBLTAG01`, word 1 = 1, words 2–7 = 0 | 32 bytes: `HBLTGR01`, fresh nonzero tag, 0, 0 | 32 |
| Start | Unchanged `HBLCLQ01`, command 1, allocated tag, JSON byte length, four zeros, then the complete canonical JSON | Unchanged `HBLCLR01` plus complete text | 64 |
| Poll | Unchanged 64-byte `HBLCLQ01`, command 2, tag, then five zeros | Unchanged `HBLCLR01` plus complete text | 64 |
| Cancel | Unchanged 64-byte `HBLCLQ01`, command 3, tag, then five zeros | Unchanged `HBLCLR01` plus complete text | 64 |
| Retire caller storage | 64 bytes: `HBLRET01`, word 1 = 1, word 2 = tag, words 3–7 = 0 | 32 bytes: `HBLRTR01`, retired tag, 0, 0 | 32 |

Allocation reserves one caller record for this exact attached engine. Its tag
comes from the shared runtime context's monotonic counter, never from the MCP
request ID, caller JSON, peer metadata, or a per-request counter. Exhaustion
refuses; wraparound and reuse are forbidden. A start/poll/cancel/retire request
must name a record owned by the current engine. Start requires an allocated
record and is executed once. Poll and cancel require a completed prior caller
turn. A terminal or dropped caller can be retired only after its entire result
has been copied by the enclosing continuation. An allocated but never-started
record can also be retired. Retiring caller storage never destroys the shared
worker or releases a running permit.

`HBLCLR01` status 0 is the complete success JSON text; status 1 is the complete
invalid-parameters diagnostic; status 2 is the complete business error. Status
3 returns immediately to the enclosing host as pending. Status 4 is dropped
interest with no public success/error response. These statuses and their exact
text remain decisions of the unchanged HIA caller. The port does not classify
typed or solver errors. Private invalid input returns `0xffffffff`, resource
exhaustion returns `0xfffffffc`, and busy lifecycle admission returns
`0xfffffff8`; those are not public business-error messages.

For all three response families, the slot's existing descriptor at engine+8,
row 57, stores the output pointer at +32, its owned capacity at +40, the entry
return at +48, and the complete output extent at +56. HBLCLR01's extent is
64 + its text-length word at offset 32. The parent copies that complete extent
before another operation can replace the descriptor's borrow. Private
allocation/retirement responses have extent 32. No truncated response counts
as delivery.

## Frozen runtime host exports, revision 1

The exported ABI is System V Linux x86-64. These are trusted host calls, not
frontend-selectable wire operations. The installer supplies the verified fixed
worker image and three caller images through fixed compiled references.

| Export | Arguments | Result and ownership |
| --- | --- | --- |
| `runtime_bellman_create` | journal FD | One private runtime context, with one worker handle; failure has no attached engine |
| `runtime_bellman_attach` | runtime context, engine pointer | 0 after engine+440 points to this context and +448 records installation; rejects an already attached engine |
| `runtime_bellman_owned` | existing slot-57 convention: r15 engine, rdi input, rsi complete extent | Completes one nonblocking caller turn and updates the existing descriptor |
| `runtime_bellman_service` | runtime context | Polls actual workers and retains all complete READY frames; never waits for a solve |
| `runtime_bellman_wake_fd` | runtime context | Actual worker wake descriptor |
| `runtime_bellman_ready_receive` | runtime context, descriptor pointer, capacity | 32 for `HBRPBR01`, pointer, complete extent, exact borrow token; 0 if empty |
| `runtime_bellman_ready_release` | runtime context, exact token | 0 after retiring that one full READY event |
| `runtime_bellman_detach` | runtime context, engine pointer | 0 only after this engine has no caller records and no active slot borrow |
| `runtime_bellman_shutdown` | runtime context | Drops remaining worker caller interest once; it does not end a computation or release its permit |
| `runtime_bellman_destroy` | runtime context | 0 only after all engines detach, all retained READY events are consumed, and actual workers are reaped; otherwise BUSY |

READY events retain the unchanged complete `HBPMSR01` event-2 frame and observed
FIFO order, including completion after cancellation. The host releases a READY
borrow before another host operation on this context. Control event-1 replies
belong to their one exact caller child action and are never emitted as READY.
The host keeps the journal FD open through successful destroy. A runtime
context is created once for the process; more sessions attach to that same
context and therefore share the same two-permit pool and tag namespace.

The host services the actual wake FD and the existing at-most-10-ms abnormal
reap poll. After READY, it resumes the matching still-live caller through a
separate command-2 turn. Cancellation notifications first pass the current
SDK request/task ownership checks; only then may the trusted host issue a
command-3 turn. Disconnect of one session cancels and retires only its own
callers before detach. It never shuts down the shared runtime context.

The worker effect within a caller remains `HBLCAC01` target 2. Its mode-0
operation copies the complete event-1 reply before releasing the worker borrow.
Its mode-1 operation validates the retained sequence, target, tag and original
input, then copies only the retained reply. No capacity retry executes worker
control, POLL, cancellation, or TAKE again. Targets 0 and 1 remain the two fixed
HIA parameter/diagnostic adapters, not new globally selectable child slots.

These interfaces are fixed for authoring the frontend. No public or async
qualification follows from this ABI document; implementation, full FIFO/buffer
reader, and the SDK pending-request integration still require actual gates.

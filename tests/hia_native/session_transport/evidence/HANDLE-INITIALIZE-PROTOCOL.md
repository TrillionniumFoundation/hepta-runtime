# Actual LocalSessionHandle.initialize success ownership comparison

This finite corpus has 40 cases: eight actual typed ServerJsonRpcMessage inputs times five lifetime scenarios. All Client inputs are real InitializeRequest messages. The API itself returns any ServerJsonRpcMessage supplied through its responder; therefore a JSON-RPC Error message can be an Ok Rust result. This fixture observes the actual public initialize Future and actual private SessionEvent channel; it does not run the LocalSessionWorker or substitute a model.

The original may append a fixture module to the frozen local.rs to access LocalSessionHandle fields. Construct the handle directly with a real Tokio bounded MPSC Sender and an actual SessionId. Create actual ClientJsonRpcMessage and ServerJsonRpcMessage values through their frozen serde implementations. `wire` strings below must come from `serde_json::to_string` of those actual values. Poll the real `handle.initialize(client)` future. Native uses the frozen HIA Handle policy with actual typed messages, bounded MPSC, oneshot, SessionResult and actual ValueLease callbacks in one 36-image ELF.

## Canonical output

Produce a JSON array in corpus order. Each element is `{ "name": case.name, "rows": [...] }`. A row is `{ "step": string, "result": value, "events": [...] }`; default result is null. Events since the preceding row are `{ "kind": "clone" | "drop" | "wake" | "wake_by_ref", "waker": 0 | 1 }`, in actual callback order. Waker 0 polls initialize; Waker 1 polls the event channel receive/send helpers. Exclude final base Waker drops, but record them separately in the original report. Do not fill observations from expected scenario outcomes.

The Native observer is attached to the actual MPSC defaults and to the internally created oneshot. All actual callback effects run before observation. No no-op Wakers, Probe children, string-only values or Python-generated results replace actual objects.

## Common steps

1. `construct_client`: result `{ "wire": actual_client_wire }`.
2. `create_future`: obtain the actual initialize future, unpolled. No channel operation occurs yet.
3. Only for `pending_send_resume_ok_take`: fill the capacity-one event channel with actual `SessionEvent::Close`, fully complete/drop that helper send future; emit `fill_queue`.
4. `poll_initial`: poll initialize once with Waker 0; result is `"pending"`.
5. Only for the capacity scenario: receive and drop the actual filler Close event; complete/drop helper recv future before `drain_filler`. Poll initialize once more with Waker 0; emit `poll_after_capacity`, result `"pending"`.
6. Receive the actual InitializeRequest SessionEvent using Waker 1, and drop the completed helper recv future. Destructure it, moving request and responder. Emit `take_initialize_event`, result `{ "wire": serde_of_actual_request }`.
7. Drop the moved ClientJsonRpcMessage; emit `drop_client_message`.
8. Deserialize the corpus ServerJsonRpcMessage and wrap it in actual `Result<ServerJsonRpcMessage, SessionError>::Ok`. Emit `construct_reply`, result `{ "wire": actual_server_wire }`.

## Cancellation before send

For `cancel_before_reply`, drop the pending initialize future now, then emit `drop_future` with `{ "when": "before_reply" }`. Call the actual oneshot responder.send(result). It returns the original owned result on failure. Emit `send_reply` with `"closed"`, while retaining that returned result. Drop it and emit `drop_rejected_reply`. Do not poll initialize again.

## All other cases

Send the actual Ok result through the real responder, consuming the sender. Emit `send_reply` with actual `"sent"`.

For `cancel_buffered_reply`, immediately drop the pending initialize future; the actual receiver Drop must release the buffered Ok value and its ServerJsonRpcMessage. Emit `drop_future` with `{ "when": "buffered_reply" }`. Do not poll it again or separately drop a transferred value.

For both `reply_ok_*` and `pending_send_resume_ok_take`, poll initialize again with Waker 0. Retain the actual returned Ok result and emit `poll_reply`, result `{ "status": "ok", "wire": serde_of_actual_returned_message }`. Drop the now-completed initialize future, retaining its returned result, then emit `drop_future` with `{ "when": "ready" }`.

For `reply_ok_drop`, drop the returned Ok result and emit `drop_reply_result`. For the two `*_take` scenarios, destructure the actual Ok result to move its message, emit `take_reply_result` with `{ "wire": serde_of_actual_moved_message }`, then drop that message and emit `drop_server_message`.

## Cleanup

Drop the handle/event TX before the event RX, then emit `channel_cleanup`. Drop base Wakers only after the canonical rows and count them separately. All helper Future polls must actually return the expected result and completed helper Futures must be dropped before their enclosing step is recorded. Preserve full actual trace and source/compile/process identities; do not equate a constructed expected answer with observed behavior.

Native separately records real typed destructor/Take counts, full payload/descriptors, all physical ENTER/RETURN calls, Handle continuation receipts, actual Waker binary rows, exact guarded mapping retirement and FD balance. The original compares public wire, actual steps and Waker order; absence of a Rust heap observer must not be called an observed destructor callback. No production or whole-Worker claim follows from this corpus.

# LocalSessionWorkerError owned values

This ABI adds two HIA policies and two fixed physical entry points to the
36-image SessionMessage composition. The 36 parent semantic images, parent
adapter prefix, and parent export offsets remain byte-for-byte unchanged.
The complete callable contains 38 semantic images. No Rust or Python business
logic is embedded in the native callable.

## Qualified domain

The concrete error variants are:

| Tag | Original variant | Owned child | Scalar fields |
| --- | --- | --- | --- |
| 1 | TransportTerminated | None | Zero |
| 2 | UnexpectedEvent | Actual SessionEvent ValueLease | Zero |
| 3 | FailToSendInitializeRequest | Actual SessionError ValueLease, class 1 | Zero |
| 4 | FailToHandleMessage | Actual SessionError ValueLease, class 1 | Zero |
| 5 | InitTimeout | None | Duration seconds and nanoseconds |
| 6 | TransportClosed | None | Zero |

Seconds use the full unsigned 64-bit range; nanoseconds are less than
1,000,000,000. No millisecond narrowing occurs in the owned representation.
The frozen corpus contains both zero and maximum u64 seconds, with zero and
999,999,999 nanoseconds. All eight SessionEvent variants are represented.

Tag 7, TokioJoinError, is rejected by this constructor. The Drop policy reserves
its child-owning shape, but no real tag-7 value is qualified here. Complete
LocalSessionWorkerError Display, Debug, and Error::source are not implemented
by this ABI. Actual SessionError child Display is observed through its existing
typed projection. Full WorkerTransport and LocalSessionWorker execution,
cross-thread operation, and production activation remain unqualified.

## Factory

`local_worker_error_create(input, length, output, capacity, counts_or_zero)`
returns 64, `0xffffffff` for invalid input/type, or `0xfffffffe` for insufficient
capacity. Output capacity must be at least 64. Input remains unchanged. Optional
counts point to three u64 values: HIA entries, attempted real typed views, and
actual ValueLease creations. The caller retains every child on rejection;
ownership transfers only when the constructor returns 64.

The 64-byte little-endian request has these fields:

| Offset | Value |
| --- | --- |
| 0 | `HRLWQ001` |
| 8 | Variant 1 through 6 |
| 16 | Nonzero scheduler context |
| 24 | Nonzero generation |
| 32 | Owned child pointer, required only for tags 2, 3, 4 |
| 40 | Duration seconds, only tag 5 |
| 48 | Duration nanoseconds, only tag 5 |
| 56 | Zero |

Successful output is 64 bytes: `HRLWR001`, descriptor pointer at 8, variant at
16, child pointer at 24, seconds at 32, nanoseconds at 40, generation at 48,
and zero at 56. The returned actual ValueLease has a read-only descriptor and
payload, the same scheduler and generation, and the exact
`local_worker_error_drop_entry` callback. Its 48-byte payload is `HRLWE001`,
variant at 8, owned child at 16, seconds at 24, nanoseconds at 32, and zero at 40.

Child-free success uses two HIA entries and one actual ValueLease creation.
Child-owning success uses three HIA entries, one actual typed view, and one
actual creation. Real wrong-type children are rejected after two HIA entries
and one view attempt, with no creation. Short output is rejected on the first
HIA entry before a typed view or creation.

## HIA continuation state

The factory uses a fresh zeroed 2,048-byte HIA workspace inside a fixed guarded
physical arena. The header is `HRLWST01`: phase at 8, sequence at 16, scheduler
at 24, generation at 32, variant at 40, child at 48, seconds at 56, nanoseconds
at 64, and finished flag at 72. The exact 64-byte input snapshot is at 256.
Action and immutable shadow occupy 512 and 640, respectively. The future
owned payload occupies 1024 through 1071. The child-view receipt is at 1152,
and the ValueLease creation receipt at 1536. Reserved ranges remain zero.

The action is 128 bytes beginning `HRLWAC01`. It carries effect kind at 8,
sequence at 16, generation at 24, target at 32, child type or payload length at
40, receipt destination at 48, receipt capacity at 56, scheduler at 64, and
zeros at 72 and 80. The first 88 bytes must remain equal to the shadow.
Completion fields are done at 88, child return code at 96, and receipt length
at 104; the last 16 bytes are reserved. Before an effect these fields are zero.
The HIA policy accepts a continuation only with done equal to one, an exact
input snapshot, valid captured fields, and the expected effect result.

Effect 1 requests a typed child view. Type 1 means SessionEvent and type 2 means
SessionError; destination and capacity must be 1152 and 256. The fixed bridge
validates the real ValueLease, actual scheduler identity, and exact parent
destructor address before copying actual bytes. The 256-byte receipt begins
`HRLWCH01`, followed by type, descriptor, actual generation, scheduler, payload
length, copied-prefix length, and zero at offsets 8 through 56. At offset 64 it
contains at most the first 128 payload bytes; unused space is zero. SessionEvent
has exactly 128 bytes and is validated completely by HIA, including its variant
shape, nullable fields, child aliases, and Duration constraints. SessionError
must have the actual parent callback and class-1 `HRSERV01` payload; the HIA
policy checks its declared projection length and full payload length.

Effect 2 requests actual ValueLease creation from workspace offset 1024 with
length 48. Destination and capacity are 1536 and 16. Its receipt contains the
actual descriptor and generation. A zero pointer, wrong generation, or pointer
equal to the owned child is invalid. On success HIA emits the result, marks the
workspace finished, and clears the action and shadow. Completed replay is
rejected without modifying workspace or output. A real typed-view rejection
also closes the factory state, returns INVALID, preserves output, and retains
the caller's child; it is distinct from a malformed immutable continuation.

## Drop and enclosing Result

`local_worker_error_drop_entry` is an actual ValueLease callback. It feeds HIA
a 112-byte `HRTDQ001` frame: descriptor, generation, scheduler, payload length
48, three reserved zero words, then the exact 48-byte error payload at offset
64. Its fresh HIA workspace uses `HRLWDR01` and the existing generic
`HRTDA001` effect / `HRTDR001` result envelope. Observer type is **16**.

Child-free errors complete with one HIA entry and no child effect. Child-owning
errors issue exactly one real `value_lease_drop` on the child, then complete
with a second HIA entry. Actual SessionEvent Drop releases its real message
before its real responder. Actual SessionError Drop follows its existing typed
child ownership. The outer error storage retires after its callback returns.

An enclosing WorkerResult remains `HRWRV001`, kind 1, status 1, and the owned
error pointer. WorkerResult Drop uses existing observer 14 and drops its error
once. WorkerResult Take uses observer 15, consumes only the outer result
storage, and returns the still-live owned error to the caller. Its existing
policies and images have not changed. No result or error is cloned or forgotten.

## Physical execution and evidence

Factory policies are pinned by these manifest SHA256 values:

- Owner: `7184175bcf2267d6b82d8534b012141c80a82d8526ae5966fbf2e1f64756b382`
- Drop: `9338f4b2edb68742a9dac7cad0e05f94dfe8f558f30b321690870fd8316f72b2`

Policy build 4327 performed two actual semantic compilations. Callable build
432b reused the 36 parent images and performed five HIA packer compilations and
packs. Native run 433e completed 140 programs in each of scheduler modes 1 and
2. The canonical results are byte-identical. Each mode executed 140 real error
factories, 70 real SessionError factories, 10 real ClientMessage factories, 142
real oneshot channels, 228 oneshot polls, 112 real WorkerResult reply sends,
28 actual WorkerResult Takes, and 656 typed callbacks. Actual channel Waker
events were 142 clones, 142 drops, and 114 wakes by reference. Every native
guarded allocation retired and file descriptor sets returned to their exact
per-case baseline. Writable host reuse of historical unmapped addresses is
recorded and is not misreported as a live native mapping.

Oneshot polling uses the actual current scheduler task. The test driver selects
the requested task through real `finish(Pending)`, `notify`, and `next` calls;
it does not write scheduler memory or substitute channel Waker callbacks.
The first Native attempt, 4337, is retained as failed: 105 cases completed,
then the driver tried to poll with task 1 while task 0 was current. The existing
budget binding correctly terminated it before the next error factory. Native
v2 fixes only the driver, retaining all 38 semantic images and the frozen
140-program protocol.

Private run 4345 performed 1,823 actual HIA entries from retained real Native
input frames. It checked 282 valid sequences, 1,177 immutable refusals including
72 capacity refusals, and two terminal typed-view refusals. It reconstructed
110 child-view receipts from retained real descriptors and payloads and used
140 retained creation outputs as explicitly synthetic creation receipts.
All 362 private child acknowledgements are synthetic: this private run performs
zero physical callbacks, zero ValueLease creations, and zero Original calls.
Its 111 child-drop plans and one outer-storage-consume plan are not physical
effects. Actual effects are established separately by Native 433e.

The frozen Original comparison protocol and all-case canonical trace are
`LOCAL-WORKER-ERROR-PAIR-PROTOCOL-v1.md` and
`local-worker-error-cases-v1.json`. Original comparison and archive admission
are recorded by separate handoffs; neither is inferred from Native success.

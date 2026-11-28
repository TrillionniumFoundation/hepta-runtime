# Private persistent Bellman worker bridge

This bridge contains the same five HIA images as the qualified standalone v4:
the two-permit pool, resumable numerical core, resumable canonical writer,
integer-to-binary64 elapsed converter, and complete result renderer. The exported
functions change mechanical transport and ownership of returned bytes. The
original Rust public handler is not qualified by this interface alone.

## One persistent instance

The host creates one handle for its runtime and shares it among all Bellman
calls. Creating a handle for each request would create separate permit pools and
violate the original process-wide two-permit contract. Handles and export
addresses are private runtime capabilities; they are never request fields.

The host serializes calls to an instance. A nonblocking entry guard rejects a
concurrent call with `0xfffffff9`; this is an admission guard, not a claim that
the entire public runtime has been qualified under concurrent host entry.

All functions use the Linux x86-64 System V calling convention and preserve
callee-saved registers. The fixed component records each function's byte offset
from the beginning of the packed ELF image. All internal code and five image
references are relative, so a host can map the complete verified image at a new
base and call `base + offset`. Runtime execution requires no Rust, Python,
dynamic loader, or compiler.

| Export | Arguments | Result |
| --- | --- | --- |
| `bellman_worker_init` | Actual writable journal file descriptor, at least 2 | Private nonzero handle, or `0xffffffff` for invalid descriptor |
| `bellman_worker_control` | Handle, immutable input pointer, input byte length | 0 after one complete control turn; response is appended to FIFO |
| `bellman_worker_poll` | Handle | 0 if FIFO is empty, 1 if it has a complete event |
| `bellman_worker_receive` | Handle, writable descriptor pointer, descriptor capacity | 32 for a new borrowed event; 0 when FIFO is empty |
| `bellman_worker_release` | Handle, exact nonzero borrow token | 0 after consuming that one event |
| `bellman_worker_wake_fd` | Handle | Actual nonblocking wake-pipe read descriptor |
| `bellman_worker_shutdown` | Handle | 0 after dropping remaining callers; running workers continue |
| `bellman_worker_destroy` | Handle | 0 after completed shutdown and actual reaping; `0xfffffff8` while any task or queued event remains |

The host keeps the supplied journal descriptor open until successful destroy.
The bridge owns both pipe descriptors and its mappings, and closes/unmaps them
only after every actual worker is reaped. The host must keep standard file
descriptors 0, 1, and 2 open during initialization; internal pipe descriptors are
required to be above 2. The bridge does not change the host's signal handlers or
the flags on standard input. The standalone qualification fixture alone sets
its own nonblocking standard-input and SIGPIPE handling.

Malformed private control frames return `0xffffffff` before the retained
control code runs. Descriptor capacity below 32 returns `0xfffffffe` without
writing the descriptor. Resource failure, unexpected syscall status, or an
inconsistent shared mutation is fail-stop with owned-child cleanup. Such
failures are not relabeled as original Rust business errors or panics.

## Control turn and asynchronous completion

The `control` input is the complete `HBWKRQ01` frame, without the transport's
outer u64 extent. Its 64-byte header contains eight little-endian u64 words:

| Offset | Meaning |
| --- | --- |
| 0 | `HBWKRQ01` |
| 8 | Command: 1 submit, 2 caller poll, 3 cancel, 4 take, 5 statistics, 6 shutdown, 7 release qualification hold |
| 16 | Host-assigned response tag |
| 24 | Job identifier; submit/statistics/shutdown require zero |
| 32 | Qualification hold mode, 0 through 4 on submit; other commands require zero |
| 40 | Complete payload byte length |
| 48, 56 | Zero |

Only submit carries a payload: the complete typed `HIABELL1` graph. Production
caller composition always passes hold mode zero. The physical clone is admitted
to the HIA pool, its full queued response is appended, and its child startup gate
is opened within that one call. Cancellation may occur between complete host
turns, never by reentering an unfinished submit call.

Workers own their permits. Caller cancellation changes only caller ownership;
the numerical solve, canonical commitment, elapsed sample, and result renderer
continue. Only completion after the renderer releases a permit. Ready results
have separate storage and may remain unconsumed without retaining a permit.

`poll` performs nonblocking actual `wait4`, retains completion events, drains the
wake pipe, and retires only reaped tasks whose caller has taken or dropped its
result. The host uses the returned wake descriptor with its event loop. While
any task remains, it also polls at most 10 ms apart, as the standalone bridge
does, so an abnormal worker exit without a wake is still observed. Polling does
not move a computation's 30-second start time or invent an additional deadline
checkpoint.

## Borrowed event

On return 32, `receive` writes exactly 32 bytes, preserving any remaining output
capacity. The little-endian descriptor is:

| Offset | Meaning |
| --- | --- |
| 0 | `HBWBRW01` |
| 8 | Actual pointer to the complete `HBPMSR01` event |
| 16 | Complete event byte length |
| 24 | Monotonically increasing nonzero borrow token |

The host reads or copies all needed bytes before calling `release` with that
exact token. While a borrow is outstanding, `control`, `poll`, `receive`,
`shutdown`, and `destroy` return `0xffffffff` without changing the borrowed
event. `wake_fd` remains a read-only operation. A wrong, zero, or already
released token is rejected. After release, the host must not retain or use the
pointer. The next operation may reuse or move the FIFO mapping.

The FIFO contains all control and completion events, without dropping events
for cancelled callers. The host routes control responses by event/tag/job and
retains or consumes completion events explicitly. No delivery-only retry may
repeat control or TAKE.

`HBPMSR01` is unchanged: 64-byte header `[magic, extent, event, tag, job,
raw_return, body_length, 0]`, followed by the full 128-byte `HBPWRS01` pool
response and optional complete body. Event 1 is a control response. Event 2 is
one READY notification for each admitted job. Successful TAKE has raw return
**0**, independently of the renderer's byte-extent return. Numerical and writer
refusals preserve their exact u32 codes. A successful ordinary control has raw
return 128. A pending caller POLL has pool status 3; ready has status 0 and phase
4. Caller POLL and TAKE after cancellation are invalid, without releasing a
running permit.

## Complete owned result and actual time

The optional `HBWKBOD1` header is 96 bytes:

| Offset | Meaning |
| --- | --- |
| 0 | `HBWKBOD1` |
| 8 | Complete body extent |
| 16, 24, 32 | Complete core, commitment, and renderer frame lengths |
| 40 | Actual worker start in absolute CLOCK_MONOTONIC nanoseconds |
| 48 | Actual finish sampled after renderer completion |
| 56 | Binary64 bits of `Duration(elapsed_sample_ns - start_ns).as_secs_f64()` |
| 64 | Number of actual deadline CLOCK observations |
| 72 | Exact result code, zero on complete success |
| 80 | Qualification hold mode |
| 88 | **Absolute `elapsed_sample_ns`**, not a duration |

The full `HIABPLN1`, `HBCMTRES`, and `HBLMRS01` frames follow in that order.
On success, `start_ns <= elapsed_sample_ns <= finish_ns`. The renderer serializes
the sample-minus-start duration, matching the original location before JSON
serialization. The last numerical deadline checkpoint precedes this sample;
there is no extra post-renderer timeout. Every original state and Serde write
checkpoint is nevertheless observed against the original start-plus-30-seconds
deadline, and reaching the deadline is a refusal.

The complete journal uses the existing pool, physical clone/reap, clock/effect,
hold, and final pool-state frames. Journal and event storage are qualification
observations, not public JSON-RPC output.

# Actual Tokio cancellation reference

The original `create_local_file` function is the exact 242-byte slice from
target commit `737acf6f901e46c57b0b4374e323e0d1132e0d49`. The driver includes
that slice without changing its body. `verify_reference.py` binds the whole
target file, Git blob, function extent, and the unchanged minimal locked
Tokio 1.53.1 dependency project before compilation.

This is a private scheduling profile: current-thread Tokio runtime, one
blocking worker, normal cooperative budget, no taskdump configuration. It
does not qualify arbitrary Tokio scheduling, runtime shutdown, a public
handler, parent-directory work, cache publication, or the full create spec.

The input is one u64 extent followed by the native `HLCARQ01` initial request:
operation 1, raw path/content lengths, generation 1, and zero reserved words.
Output is a u64 extent followed by `HLCRER01` for an actual filesystem result,
or the separate 16-byte `HLCCAN01` record (magic and extent) for a real Tokio
`JoinError::is_cancelled()`. No HIA accepted-byte or custody metadata is
invented for the Rust result.

SIGUSR1 is blocked before runtime threads are created. A dedicated `sigwait`
thread calls the real Tokio `AbortHandle::abort`; no async signal handler
invokes Rust allocation or task operations. SIGUSR2 forwards the current
real task waker to exercise a repeated Pending poll. The observer thread is
stopped and joined at completion.

The original future is wrapped without adding an await. Its inner poll uses
a proxy waker that records the wake before forwarding the original waker.
The target's actual Tokio task has already entered its poll when POLL_BEGIN
is written. A blocking task has published its join output before it invokes
the proxy wake. A tracer can therefore distinguish cancellation before the
next poll from cancellation during an already-running poll.

Each stderr observer record is 128 bytes. It has magic `HLCARP01`, then u64
extent, event, global event serial, poll ordinal, wake ordinal, actual Linux
TID, two event details, and seven zero words. A single raw write avoids any
observer mutex being held while another thread drops the original future.

| Event | Meaning |
| ---: | --- |
| 1 | Task poll entered, before the unchanged inner future is polled |
| 2 | Inner poll actually returned Pending |
| 3 | Inner poll actually returned Ready |
| 4 | Completed operation invokes its registered waker, before forwarding |
| 5 | Actual waker forwarding returned |
| 6, 7 | Original future drop begins and ends |
| 8, 9 | Actual AbortHandle call begins and returns |
| 10 | Explicit test-only repeated wake |
| 11 | Real cancelled JoinHandle result, before stdout publication |
| 12 | Normal filesystem result, before stdout publication |
| 13 | Actual Runtime drop finished draining blocking work |
| 14 | Signal-control thread is running |
| 15 | Task exists but Runtime has not started polling it |
| 16, 17 | Tokio blocking-thread startup and stop observer |

Cancellation output is written when the real JoinHandle resolves. Runtime
drop follows publication and really waits for any in-flight blocking work.
Ready-result destructor close therefore precedes cancellation visibility;
an in-flight worker may close after visibility. This difference is checked
using actual syscall and publication ordering, not inferred from a summary.

The external tracer owns the forked child and its ptrace-reported clone/fork
descendants. It may hold actual syscall entry/exit, or one of these observer
writes. Explicit partial counts, EINTR, WriteZero and late-error injections
must retain both the actual kernel return and the injected completion. They
must never be described as natural kernel errors. Each actual process keeps
the existing 60-second deadline; the focused qualifier keeps 180 seconds.

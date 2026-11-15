# Native Local history and undo write chain

This component executes the Local save/undo call chains of the retained
`core::save_file_history` and `core::undo_edit` owners within the declared
native allocation profile below. It composes actual
canonical path traversal, shared file-lock state, HistoryStore, Local full-file
read, atomic replacement, and session view-cache invalidation. Its fixed Linux
x86-64 executable contains eight HIA images and the HIA packer's syscall/thread
boundary. It has no Python, Rust, libc, dynamic-loader, or semantic fallback at
runtime. Python and Rust below are qualification observers and the original
comparison executable.

The admitted path is a trusted internal `PathSource::Local` byte string. This
profile has no public MCP admission, authorization, SSH/SFTP, workdir resolution,
or public editing/create/delete dispatcher. The production handler registry and
whole-runtime replacement/removal qualifications remain unchanged and false.

## Exact original ownership

The original source baseline is
`a0dcdda1991ec536d5e2d252c006a778993fa566`. `write_chain_composition.json`
pins all five complete original files and records the exact imported HIA body
relocations. `write_chain_profile.json` pins the actual eight source/image
identities and the compiler dependency. The builder checks 82 reused function
bodies after reversing only their declared function-number relocations.

Save preserves the order: original synchronous Local existence check; actual
asynchronous full UTF-8 read; a fresh canonical key after the read; shared
HistoryStore push. A metadata failure follows the original `Path::exists`
false behavior. No cached first key or first read substitutes for a later
original operation.

Undo preserves the order: canonical key and lock-handle acquisition; await the
shared guard; a second canonical key; pop history; actual atomic replacement;
another canonical key for `delta::forget`; cache invalidation if a request
context exists; return the original response. The pop occurs before the write.
A failed or canceled write does not reinsert that history entry. Context absence
does not remove the original canonical-key computation. The guard is released
before dropping the acquired lock handle on terminal paths.

History retains the original ten entries per key and 64 MiB global accounting,
including stale order-queue behavior and its interaction with a new oversized
entry for the same key. The 64 MiB number is a history retention rule, not a
new file-input limit. Full-file reads and retained bodies grow using trusted
native mappings. Raw Unix paths, invalid UTF-8, NUL errors, lossy diagnostics,
symlinks, hard links, original error order, and permission restoration stay in
their original domains.

The existing `batch-plan.v1` allocation profile supplies a 512 MiB input
region, 1 GiB output region and 1,152 MiB workspace region to each blocking
I/O boundary; shared arenas and private continuations also have explicit
native allocation bounds. An out-of-profile growth is a capacity/resource
refusal, not an invented original filesystem error. This is an admission
boundary of this executable, not a replacement for the original `usize`
domain. In particular, the u32 byte-return ABI is not a proof that arbitrary
multi-gigabyte single-frame contents are supported. A later public caller
must close its admitted size/resource domain or use a segmented interface.
No out-of-profile input, or host allocation failure, is silently truncated
into a successful file result. The full-size fixtures include the original
64 MiB retention boundaries without reducing them to this profile's limits.

## Three-buffer HIA request ABI

All integers are unsigned little-endian. The entry is the standard
`f0(readbuf, mutbuf, mutbuf) -> u32`. A request is exactly 64 header bytes followed
by the raw Local path bytes.

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | ASCII `HFWRT001` |
| 8 | 8 | Operation: 1 save history; 2 undo |
| 16 | 8 | Request context: 1 the profile's shared session cache; 2 absent |
| 24 | 8 | Raw path length |
| 32 | 32 | Reserved, all zero |
| 64 | variable | Raw Unix path; exact request extent |

A completed ordinary result has a 32-byte header followed by exactly the body
length declared at offset 24. Original errors are ordinary results, distinct
from an invalid borrowed frame or a broken trusted child contract.

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | ASCII `HFWTR001` |
| 8 | 8 | Original operation |
| 16 | 8 | 0 success; 1 original error |
| 24 | 8 | Result body length |
| 32 | variable | Complete original result/error bytes |

The initial private workspace is zeroed and at least 4,608 bytes. Header fields
are fixed by `write_chain_layout.json`; body scratch begins at 4,096. In
particular, cancellation is the trusted word at 112 and requested growth is
the word at 120. The caller never supplies those words as public request data.
Original result bytes are published after the output-capacity preflight. The
direct suite checks unchanged input, exact result extent, untouched output
tail and all borrowed-buffer canaries on actual calls. Internal continuation
steps may change private workspace and committed shared state; they are not
transaction rollback promises.

| Return | Meaning |
| --- | --- |
| less than `0xffff0000` | Complete output byte length |
| `0xffffffe0` | Fixed child call pending |
| `0xffffffe1` | Shared-lock wait pending |
| `0xffffffef` | Grow private workspace to the declared size |
| `0xffffffee` | Grow output to the declared size |
| `0xfffffff7` | Cancellation observed at the original asynchronous boundary |
| `0xfffffff9` | Invalid trusted continuation/child state |
| `0xfffffffe` | Borrowed capacity refusal |
| `0xffffffff` | Invalid input frame |

The 128-byte `HFWRCALL` effect at workspace offset 256 contains sequence,
fixed child ID, request offset/length, response offset/capacity, returned code,
returned length and completion word. Its remaining six words are reserved.
The fixed adapter validates all spans, lengths, phase/sequence and full child
result framing before the controller consumes a completion. A request cannot
select arbitrary native code, a syscall number, pointer, FD or continuation.

## Fixed native composition and shared lifetime

| ID | HIA owner | Lifetime |
| --- | --- | --- |
| 0 | `write_chain` | Per native worker request |
| 1 | `file_lock_service` | Per-worker controller; shared state through ID 7 |
| 2 | `file_lock_key` | Per-worker canonical traversal/FD custody |
| 3 | `history` | One process-wide serialized HistoryStore |
| 4 | `atomic_write_shared` | Per blocking I/O operation; process-wide statx availability |
| 5 | `view_cache` | One serialized cache for the profile's context 1 |
| 6 | `local_read` | Per blocking I/O operation |
| 7 | `file_lock_state` | One process-wide serialized file-lock registry |

The 14,800-byte prefix and complete 1,453,462-byte ELF are pinned. The
`HFWCHN01` table begins at 14,720 and fixes all eight image extents/order. The
inspector checks the ELF header, RX mapping, nonexecutable stack, normalized
prefix, table, each actual embedded image, padding and complete executable hash.
The HIA packer is independently compiled and invoked; all actual compilation
and packing inputs, full outputs, untouched tails, stdout, receipts, limits
and source identities are retained. There is no assembler in the build path.

Four native workers have private controller/key mappings and guarded stacks.
Shared lock, history and view-cache arenas are protected by separate native
CAS/futex critical sections. Shared arena growth, pointer publication, and
old-map retirement occur inside the same critical section. No caller keeps an
unlocked shared arena pointer. The original registry's reference/guard/queue
state remains in HIA.

Blocking I/O uses owned native children, actual fixed syscalls and
parent-death binding. Cancellation can publish the original asynchronous
cancel result and release its guard while the already-started blocking I/O
continues; that worker drains/reaps its child before reuse. Cancellation does
not interrupt synchronous canonical traversal. A private wake epoch replaces
signal interruption for these boundaries. FD slots retire before their one
close attempt, including FD 0; close EINTR does not cause a second close.
Shared I/O backing is removed after drain so another request cannot observe
the previous request's contents or state. EOF waits for worker/child drain and
thread retirement. No guessed synthetic reap is published.

`atomic_write_shared` preserves the actual original Linux statx availability
cache across requests and workers. It retains the original late-success race:
an earlier outstanding statx success can restore availability after another
thread has observed unavailability and used fstat fallback.

The static qualification transport is a little-endian u64 request length,
u64 unique live tag, and request bytes. The u64 all-ones length followed by a
live tag requests cancellation. A reply is u64 tag, u64 actual native TID,
u32 result code and exactly its returned bytes. TID alone is removed for
comparison with Rust. This internal transport admits at most four in-flight
requests with distinct live tags. A fifth request may apply backpressure
before a later cancellation frame is read. Public multi-session scheduling,
untrusted tag admission and authentication are outside this profile.

## Actual qualification domains

The final portable invocation rebuilt the nine HIA modules (eight semantic
images plus packer), ran all six native/evidence processes, freshly compiled
the complete unchanged Rust owners with explicit Rust 1.95.0, and replayed all
three original comparison suites. It passed in 40.166679 seconds on ai395 as
job `1a1dd8c01b1-392-2107`. Every process retains the original 180-second gate.
The original recipe itself completed in 16.005574 seconds. This is a focused
component qualification, with no compiler cold or whole-runtime aggregate
claim.

| Domain | Actual execution and comparison |
| --- | --- |
| Borrowed controller | 214 controller calls + 302 leaf calls; all 516 full inputs, outputs and before/after workspaces retained; 26 requests; 31 explicitly synthetic filesystem completions |
| Shared statx state | 45,280 native calls; 7,978 synthetic transition cases; 12 refusal controls; no kernel calls attributed to this domain |
| Complete file chain | 147 actual requests per side: 63 save, 84 undo, 98 successes, 49 original errors; 26 large-boundary requests; every one of 787,555,659 content bytes per side is read and compared |
| Kernel faults/cancellation | 53 actual processes and 162 requests per side; 38 complete normalized syscall comparisons and 15 causally held cancellation cases |
| Concurrent callers | 4 actual native and 4 original processes, 34 requests per side; same-key aliases, held guard, cancel before guard release, and shared statx late-success race |
| Evidence admission | 2 valid retained-artifact admissions and 14 actual file-mutation refusals; zero new semantic or original executions |

The concurrent tests compare complete responses by tag because response
arrival order is not deterministic. They observe competing callers finishing
canonical key computation and being unable to start atomic replacement while
the guard is held. They do not relabel that observation as proof of a specific
Tokio waiter-registration instant. Queue state and FIFO behavior have their
separate native file-lock owner qualification.

Full body/error bytes, raw/normalized transport captures, every original stderr
summary, complete filesystem snapshots, raw syscalls and control completion
records remain retained. Filesystem metadata is compared on the same actual
host/fixture. Host umask differences in separate historical observations are
not falsely treated as content mismatches. The static expected-body plan is
explicitly not an execution receipt.

The helper only inspects retained bytes. The pipeline additionally requires
actual completed stdout/stderr, exact commands, source-map coverage and the
fresh recipe invocation. The Rust driver keeps the outer owned process group;
it must run under the existing 180-second aggregate or durable-process
supervisor. It does not claim an independent standalone CLI can supervise all
descendants on its own.

Earlier failures are retained separately: the shared backing-store retirement
bug, synchronous-key cancellation interrupt, historical stale-order test
expectation, formatting-only Rust check failure, and the first portable
negative-control copy's read-only-file permission failure. No previous result
was rewritten as a new execution. `write_chain_native_layout.json` is the
immutable pre-execution layout record; its author-time `PENDING` field is not
used to determine actual qualification status.

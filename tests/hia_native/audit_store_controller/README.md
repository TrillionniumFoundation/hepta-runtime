# HIA native audit lock callable

This candidate composes the qualified HIA audit controller and its HIA-emitted
Linux synchronization boundary into one callable image. It executes the
controller, applies its exact effects, grows the queue under actual queue
mutex custody and resumes the controller until completion. The effect pump
needs neither Rust nor Python at runtime.

The controller source remains byte-identical to source commit
`66b909474c7fbaf8efe29e4548b521cf006d7ac7`; its compiled image is 160,544 bytes,
SHA-256 `1c2d4e44f4d2185ef06dc1de0566f21a33f92bee61b05fa7ebed6ee9841de90a`.
The synchronization boundary remains 1,635 bytes, SHA-256
`b2a5f181d26382ab4c7d0759097b922eb4df1864636e0209b66db2e80f3c0ca9`.
FIFO policy, timeout decisions, guard ownership and poison behavior remain in
HIA. The native adapter applies those effects and manages buffer lifetime.
Assembler is an authoring input; the build executes the frozen HIA packer.

## Private callable contract

The System V x86-64 entry receives three borrowed buffers: an immutable
256-byte request, a 512-byte private actor and a 128-byte shared context.
The caller supplies valid, nonoverlapping storage for those buffers and a
separate 64-byte, eight-byte-aligned kernel state. The context borrows the
kernel state and owns its mapped queue.

The descriptor contains sixteen little-endian words: magic, generation,
kernel pointer, kernel capacity, queue pointer, logical queue capacity,
mapping extent, optional observation function, observation user pointer and
seven zero reserved words. Before initialization only the kernel
pointer/capacity and optional observation pointers are populated.
Initialization occurs before publication. The actor and queue protocols are
unchanged. Completion returns 512 and leaves the result in the actor.
Command 6 retires the queue mapping and returns zero; its caller must be the
final owner, after every actor and mutex guard has released.

Queue pointers and capacities are accessed only before publication, under
actual queue custody, or by the final owner. Growth uses `mremap`, preserves
old logical bytes, clears the new extent and restores the trailing guard.
Deadline and unwind inputs remain explicit HIA request fields.

The optional observation function copies supplied before/after views. It
makes no policy decision and supplies no native operation. The thread
fixture uses it to preserve the complete controller/boundary/queue journal.
A separate process sets both observation pointers to zero and performs each
API operation through a single native call.

Invalid sizes, capacities, reserved fields and discriminators are refused
without changing physical buffers. Invalid host pointers, corruption after
an effect starts and exhausted native allocation are outside this frozen
domain. Irrecoverable native failures terminate the process instead of
publishing a partly owned context.

## Frozen qualification

The manifest binds source, domain, recipes and readers before execution.
CI uses the pinned Hepta source and fresh B1 = B2 = B3 to compile all three
HIA modules. Complete buffers are retained for boundary and callable
emission, including all accepted and refused pack requests.

The actual-thread domain retains five unchanged original tests and four
shared additional tests, including 16 exclusive workers, 65 shared workers,
panic/poison and existing-unwind cases. The native fixture adds 128 actual
clock mappings. It retains 13 contexts, 399 actors and 774 completed
controller operations. The Rust fixture makes one native call per API
operation and contains no continuation or queue-growth pump.

The observer-free native process adds nine complete-buffer refusals and six
ordinary calls: initialize, exclusive acquire/drop, shared acquire/finish
and final mapping disposal. The callable is read/execute before invocation.
No Rust library or foreign effect callback drives this domain.

The inert reader checks the complete source closure, process commands and
budgets, every compiled/emitted byte, complete observer-free state chains
and every thread record. Twelve physical mutations, two full relocations
and two post-refusal admissions run under twelve read-only guards.
Budgets remain 60 seconds for ordinary commands, 180 seconds per semantic
or reader process, 900 seconds for builds and 15 minutes for the CI job.
Failures and interrupted attempts retain their own identities.

This is private component qualification. Public handlers, production
activation and replacement of the whole runtime need their own gates and
remain false here.

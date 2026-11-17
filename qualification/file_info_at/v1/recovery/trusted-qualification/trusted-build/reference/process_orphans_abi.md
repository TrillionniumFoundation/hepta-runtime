# Process-lifetime orphan FD inventory

This fixed native memory primitive supports the exact target regular() behavior when its first fstat raises before the caller receives the opened FD. The HIA owner decides that transition. The adapter verifies its own actual opened token, appends a record, then removes the token from its operable owner ledger without close or dup. The target descriptor remains open until the whole owning OS process exits.

## Trusted graph ABI

- hia_process_orphans_create() returns a guarded pool pointer or a negative Linux errno.
- hia_process_orphans_append(pool, fd, origin_context, origin_generation) returns zero after one append, or a negative Linux errno without appending.
- fd is 0..2147483647. origin_context and origin_generation are nonzero trusted graph bindings. No external request may select these pointers or an FD.
- The adapter must validate its own currently opened token before append. The primitive itself has no caller ledger authority and must never be exposed as an external input operation.
- Only after zero may the caller retire its token from the normal owned ledger. A negative result leaves that token with the caller and is a private resource/protocol failure, never a fabricated original syscall result.
- No close, dup, fcntl, open, read, write or FD callback occurs in this primitive. mmap, mprotect, munmap for an allocation failure, getpid and private futex are the only native operations.
- Pool creation and append must occur in the same OS process (getpid). Threads share the pool; a forked child must create its own pool. A shared-memory child with a distinct PID also needs its own pool.
- The pool and its record pages have no destroy/reset operation. Context release, context destroy and ordinary request EOF must not close an orphan or unmap this inventory. Whole-process exit retires the kernel descriptors and mappings.

## Pool layout

Each mapping is 8192 bytes: 4096 RW bytes followed by an inaccessible guard page. The pool header is HPORP001 at 0, capacity4096 at8, creator PID at16, u32 lock at24, reserved u32 at28, head page at32, tail page at40, total record count at48, record page count at56, failed allocation count at64. Other initial bytes are zero.

Each record page has HPORL001 at0, owning pool pointer at8, next pointer at16, used count at24 (0..126), first sequence at32 and zero reserved words at40/48/56. Records start at64; each is four exact u64 words: FD, origin context, origin generation, monotonic sequence. Every fully published record is immutable. Pages are linked and counts published under the pool's private futex lock. Fixture inventory reads require a quiescent producer and inspect complete bytes; production callers do not expose a public inventory API.

This is frozen source only: no assembly, native execution, original comparison or public integration has occurred in this package. The exact source must be compiled into the info/publish fixed graph and qualified there, including actual fstat failure, caller-token refusal, process FD inventory, growth and multi-context use. Allocation exhaustion, process termination while holding the lock and cross-process shared-FD-table adoption are not claimed qualified.

# Native audit record I/O callable — new source-stage successor

This package composes the exact qualified audit_record_io and audit_json HIA
images. It replaces the Python effect dispatcher with a fixed Linux x86_64
native adapter. No archive, HOT_CACHE, retention, STORE_LOCK, ACTIVE publication,
begin/finish or public qualification is asserted by this source checkpoint.

## Frozen semantic inputs

Record I/O handoff: 581b8e4d31dc9a7bb2e63ca8f8e2b79eea04989b.
Record I/O flat image: 295103 bytes,
3b290dab82a2c60982a7af947562a4cf7aa407e9399c0d877640354c13112664.
Audit JSON flat image: 161260 bytes,
76122331b305e654b6175a3d0a975d080815ee1cfcf542ea837d8aecdb83b2fc.
The complete 219-case / 459-operation retained original domain remains the
comparison source. The previous 658 direct-owner refusal controls remain under
their old source identity; this successor does not claim they executed again.

## Native private exports

All exports use SysV AMD64. There is no dynamic symbol resolution or ambient
path lookup in the adapter. The actual caller owns and initializes the private
context and retains it until dispose. It serializes calls on each context.

initialize(context, context_capacity, borrowed_directory_fd, libc_table,
           optional_observer, observer_user) -> u32
entry(input, input_bytes, output, output_capacity, context, context_capacity)
      -> u32
dispose(context, context_capacity) -> u32

The context is 98304 bytes, aligned to eight bytes and initially all zero.
The borrowed directory descriptor is never closed by this component.
The initialization table contains exactly fifteen actual libc function
addresses followed by one zero word, in this order:
__errno_location, openat, fstat, geteuid, read, write, fsync, close, linkat,
unlinkat, renameat, fcntl, fdopendir, readdir, closedir.
The table is copied into the context. The caller owns admission of these
private capabilities; arbitrary request data cannot supply this table.

initialize returns zero on success. entry consumes only a complete HAIORQ01
initial frame (128..4352 bytes, directory capability 1); HIA validates the
entire original frame. The adapter then executes every emitted HAIORS01 effect
and exact HAIOACK1 until the original HIA owner returns a terminal frame.
entry returns that complete extent and copies it into the caller's output,
whose capacity must be at least 8192. It never publishes a partial terminal
result. HIA_INVALID and HIA_CAPACITY retain their values, 0xffffffff and
0xfffffffe. A mechanical-state failure is 0xfffffffc, distinctly outside the
business-error frame. The adapter closes all owned descriptors/streams before
returning that failure, poisons the context, and does not retry policy effects.
An already busy context returns 0xfffffffd without performing work.

The private descriptor table has sixteen slots. Slot zero is borrowed directory
capability 1. Other slots carry monotonically allocated nonzero opaque tokens,
kind (file or directory) and the actual fd/pointer. Slots are reused only after
the original HIA emits close or a successful fdopendir consumes its duplicate.
Capability numbers are not process descriptors. There is no ordinary-domain
resource-exhaustion substitution; an impossible private-table state is a
mechanical failure with complete cleanup and a distinct return.

The context holds separate owner and JSON input/output/workspaces, fixed ACK
storage, names, stat and dirent observation storage. It preserves all original
bounded record limits. HIA, rather than the adapter, owns validation, retries,
partial reads/writes, file identity checks, staging rules and publication
ordering. Every actual syscall result and immediately observed errno is
converted mechanically. readdir explicitly sets errno to zero first; a
nonnull dirent wins regardless of errno, matching the original helper.
Observer calls cannot supply results or acknowledgements.

## Observation boundary

An optional observer receives (record128, user). It is invoked before and after
each actual HIA call, each filesystem call and failure cleanup. The callback
returns void; its return value is never used. Category1 is record HIA, category2
is JSON HIA, category3 is filesystem, category4 is failure cleanup.
The sixteen u64 words are: category, phase0/1, actual_return, input_ptr,
input_bytes, output_ptr, output_capacity, workspace_ptr, workspace_capacity,
context_ptr, effect_sequence, generation, actual_syscall_return,
actual_errno, detail_ptr, detail_bytes.
It observes owned borrowed memory only. A separate observer-off complete
219/459 cohort must prove the callable does not need that callback.
Complete physical buffers and actual process/FS observations are retained;
summaries cannot replace the bytes.

Transport admission refusals occur before any external effects. Malformed HIA
requests are still decided by the unchanged owner. Its output/workspace
atomicity remains qualified under its direct ABI; the outer callable may record
diagnostic counters and scratch input on that invocation, so no stronger
whole-context refusal atomicity is inferred.

## Execution and scope

The native assembly and HIA packer source were produced by source-author CI
44048463978. Runtime qualification remains pending a separately frozen CI that
compiles, packs and executes the exact two semantic images and full domains. Rust reference bytes and completed
original observations are reused only after their complete strict admission.
No local Rust or HIA execution is authorized. Each new producer keeps its
declared 60/180-second budget; CI jobs retain fifteen minutes. Old failures and
unknown processes remain unchanged.

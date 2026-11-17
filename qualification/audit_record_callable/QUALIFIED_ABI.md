# Qualified native audit record I/O callable

This package composes the exact qualified audit_record_io and audit_json HIA
images. It replaces the Python effect dispatcher with a fixed Linux x86_64
native adapter. No archive, HOT_CACHE, retention, STORE_LOCK, ACTIVE publication,
begin/finish or public qualification is asserted by this private component qualification.

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
It observes owned borrowed memory only. The separate complete observer-off
219/459 cohort proved that the callable does not need that callback.
Complete physical buffers and actual process/FS observations are retained;
summaries cannot replace the bytes.

Transport admission refusals occur before any external effects. Malformed HIA
requests are still decided by the unchanged owner. Its output/workspace
atomicity remains qualified under its direct ABI; the outer callable may record
diagnostic counters and scratch input on that invocation, so no stronger
whole-context refusal atomicity is inferred.

## Execution and scope

The native assembly and HIA packer source were produced by source-author CI
44048463978. Frozen producer f7273eb / 44061230103 freshly compiled both semantic
images and the HIA packer, reassembled the native adapter, packed it, and
completed both 219/459 cohorts and all 45 admission/recovery controls. Its final
reader failed on an incorrect one-lookup counter expectation; that original
failure remains unchanged. Pure recovery 6a32d048 / 44063722451 verified the
actual two-lookup sequence, retained-original comparison and all physical
controls. Independent full uploaded-archive read ee2bd057 / 44065002405 passed
with zero HIA/Rust executions and all 72,252 physical entries unchanged.

The callable image is 462667 bytes, SHA256
e6defdd381fa78008af05e5055141275b6807fca828e01b45afd249c2146e9c5.
Export offsets are entry 0, initialize 5840, dispose 6144. The native adapter
prefix occupies 6304 bytes, followed by the unchanged record owner at 6304
and unchanged JSON owner at 301407.

All original process budgets remain: producer capture/controls and pure readers
180 seconds, assembler tools 60 seconds, existing build 900 seconds, each CI job
15 minutes. Native execution occurred only in authorized CI. Completed original
Rust evidence was strictly read and compared; it was not rerun for this pump.
The exact frozen source ABI.md retains its pre-qualification wording for source
identity. This document records the later evidence without editing that source.

The proof is limited to the fixed ordinary Linux x86_64 private record-I/O ABI,
complete outputs/files and durable effect ordering. It does not add exact public
Serde diagnostic text, archive/HOT_CACHE, STORE_LOCK/lifetime composition,
begin/finish, asynchronous/public handlers, cross-platform or whole-runtime
qualification. The bootstrap proves the recorded fixed point; it does not
change matching_source_cold_qualified from false.

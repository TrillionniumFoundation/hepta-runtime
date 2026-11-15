# Callable local Batch boundary

The public dispatcher owns typed admission, Session, workdir, path policy and
effect permission. This engine owns the inner local caller. No public value
selects a pointer, descriptor, image, worker PID or cache binding.

`batch_engine_create(rdi=image_table, rsi=AT_SECURE)` returns an engine pointer
or negative Linux error; failed creation releases its partial mappings. The
fixed table has 22 entries. Later calls use the private engine in `r15`.
`[engine+8]` is a table of 64-byte descriptors: entry at 0, workspace pointer
and capacity at 8/16, output pointer and capacity at 24/32, zero-extended last
u32 return at 40, private boundary fields at 48/56. This is not the filesystem
extra-image descriptor layout.

`batch_call_run(rdi=frame,rsi=extent)` copies the complete input before return.
The caller may release that borrow even when work is pending. Descriptor 0's
output remains borrowed until the next engine call; the publisher must acquire
its own copy first. Return 64 exposes the complete `HBCAR002` header; its u64
body length is authoritative. Status 0 is String success, 3 String error,
2 queued lock, 4 private cancellation without a response, 6 native failure,
and 7 unit retirement. Internal effect calls, growth and delivery continuations
are consumed by the boundary without repeating completed effects.

Set private `engine+640=1` before use for workers at read slots 2/3 and atomic
slot 19. Return `0xfffffff0` means one real worker is outstanding. It has a
separate FD table and owns an independent retained input and selected arena.

| Export | Arguments besides r15 | Behavior |
| --- | --- | --- |
| `batch_call_resume` | esi=0 poll or 1 join | Actual wait4 before consuming a worker completion |
| `batch_call_cancel` | None | HIA releases the inner guard and scope; worker borrows remain owned |
| `batch_call_wake` | None | Poll the exact current file-lock continuation |
| `batch_call_retire_wait` | None | Retire a cancelled lock wait with no worker |
| `batch_engine_retire` | None | HIA DROP, initial lease release, global-state teardown; rejects live workers/borrowers |
| `batch_engine_free_maps` | None | Free mappings after successful retirement; also used for partial failed initialization |

Cancellation still requires `batch_call_resume` to reap a live worker and
deliver its late unit. A started read finishes to EOF. A started atomic
write_all finishes and closes before cancellation is observed at its original
await boundary. A late result cannot become a response to a new request.
Public cancellation notifications must follow verified SDK behavior; they do
not automatically call this private cancellation API.

For a fresh never-started engine, `batch_engine_bind_shared(rdi=global_primary,
rsi=session_primary,edx=bound)` accepts optional zero pointers or other Batch
engines from the same image table. History and file locks belong to the global
primary; cache and lease belong to the Session primary. Every call refreshes
and writes back possibly moved shared arenas. Scope and request context stay
private. Primary retirement rejects live engine borrowers.

Public integration must share the existing View slot 7 lease and slot 8 cache.
The dedicated trusted View installation remains a separate integration step;
Batch-only sharing tests do not qualify a second cache as the same Session.
Outer lifecycle ownership must retain View mappings until Batch borrows retire.

Fixture synchronization is enabled only by private engine+24=1 and trace
state; production leaves these fields zero. The private START exchange begins
before its first byte and ends after the complete terminal response, with the
unchanged 60-second deadline. Fixture setup and the separately captured native
typed projection remain inside their own unchanged 180-second suite gate.
Child carrier limits, including legacy u32 extents and atomic-write's carrier,
remain explicit unfinished representational domains, not batch business quotas.

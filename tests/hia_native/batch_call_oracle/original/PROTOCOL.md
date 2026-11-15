# Batch original capture domains

The unique local-inner input generator is `cases.py`. Its initial frozen input
contains 215 records, including two explicit asynchronous cancellation records.
The generator computes no expected output. The unchanged Rust execution must
follow admission of the corresponding complete native captures.

## Binary records

Input is `HBCCI002`, little-endian u64 record count, then records. Each record is
`u64 metadata_bytes, u64 blob_count, metadata JSON`, followed by `u64 bytes, body`
for every blob. The JSON metadata is canonical UTF-8 with sorted keys. Output is
`HBCCO002` and the same record framing. Every original response, filesystem
content, error, and relevant state value is retained as complete bytes. Blob
indices may reuse an already retained byte-identical value within one record;
hashes never replace the underlying bytes.

## Owned paths and continuity

An isolated case owns `case-NNNN` under the capture's explicit fixture root.
A case with `sequence` owns `sequence-NAME`. These paths persist for every
record of that sequence. The working directory is that owned directory plus
the raw Unix bytes from `workdir_rel_hex`. Setup/mutation paths are relative to
this directory; tool path strings are passed unchanged. `fixture_cwd_hex` may
be added by materialization and must equal this derived path byte for byte.
No result string or diagnostic is relocated by replacement.

`session` selects fixture-owned request cache instances. It is not a public
tool parameter. History and the file-lock map are shared in the same process.
`reset_history` resets the global history store; `reset_cache` clears only the
selected session. These are explicit fixture operations, not original handler
effects. With reset false, state survives between records. Snapshots retain all
current history strings/order, each session's full cache, lock availability and
strong counts, actual filesystem contents/metadata, and FD targets. FIFO
contents are never read by a generic filesystem snapshot.

## Local-inner entry

The original custom `BatchEditParams` deserializer projects the input. Its exact
serialized parameters are retained and passed to the unchanged
`execute_batch_edit`. The original request context and append_hints execute.
This domain does not execute the outer HeptaServer method, SDK dispatch,
session-workdir latch, policy, or effect admission. Those require the separately
declared public domain and native predecessor; a fixture wrapper is not proof
that these outer stages ran.

## Mutation synchronization

Hooks execute after the named real operation completes and before control
returns to the original caller. Occurrences count every actual named operation.
The native fixture must expose the corresponding completed-child/effect gate.
All hook indices must be used exactly once; missing gates cannot be silently
ignored or moved across operations.

| Hook | Actual original completion |
| --- | --- |
| `exists` | unchanged `io_exists` |
| `read` | unchanged `io_read_to_string`, including the history second read |
| `history` | unchanged `save_file_history` |
| `atomic_metadata` | actual Tokio metadata await |
| `atomic_write` | actual Tokio temporary-file write await |
| `atomic_permissions` | actual Tokio set_permissions await |
| `atomic_rename` | actual Tokio rename await |
| `cache` | unchanged `delta::note_write` |

Observed Tokio adapters delegate exactly once, preserve the received Result,
and retain the original source body intact. They do not supply a file's
contents, errno, permission, or successful outcome.

## Cancellation

The asynchronous cases wait for an actual FIFO open in a blocking worker.
`/proc` observations and the complete syscall trace bind the worker/barrier.
Dropping the real original Tokio future releases the original async file lock
and request context. An already started blocking filesystem closure may still
finish. The late read/write bytes, descriptors and actual closure termination
must be retained, followed by a real new edit on the same owner. Cancellation
is not a fabricated normal return, and the post-cancel blocking closure is not
counted as a resumed handler. The current preparation contains no successful
original replay claim for this domain.

## Source and process requirements

The source binder keeps the complete original text_editing, remote, delta,
request_ctx, effect fence, line_hash, truncation and disabled remote backend
modules as contiguous, byte-identical spans. Core history/execute and the outer
method/typed/session/config spans have exact source offsets and hashes. The
configuration installer is an explicit fixture, not the production loader.
The full HeptaServer router and remote I/O remain outside the current carrier.

Rust must be explicit 1.95.0 with its actual executable, full version stream,
RUSTC environment, locked upstream dependency subset and fresh target recorded.
Native-first causality is established from a complete admitted predecessor's
source/input/output/state/receipt hashes, not by comparing monotonic clocks
across machines. Every semantic gate retains its real 180-second deadline,
exit status, full stdin/stdout/stderr and actual selected executable bytes.
Pure readers must not inspect or reconstruct live fixtures.

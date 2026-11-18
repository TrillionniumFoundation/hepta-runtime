# Persistent Watcher fixed-eight successor — source/build stage

This is a new candidate. It preserves all Watcher decisions, native libc/atomic
mechanics, and the unchanged 58-case / 984-operation / 13-group reference domain.
Only HIA functions f26, f27, and f28 change: each fixed eight-iteration byte loop
becomes eight ordered individual checked byte accesses. Wrapping addresses,
checked shifts, the first bounds failure, and partial writes are preserved.

The frozen baseline owner and composition remain in baseline/. The unchanged
original owner author first reproduces both complete files. The unchanged
qualified symbolic helper checker then compares the full old/new function CFG
access traces and return expressions. All other 26 function ASTs and their raw
source prefix must be identical. This does not treat a data-dependent loop as a
fixed loop and does not replace checked bytes with an unchecked wide access.

## Execution boundary

prepare_fixed8.py performs source admission, symbolic proof, fresh B1/B2/B3,
fresh owner compilation, unchanged GAS adapter construction, fresh HIA packer
compilation, all eight actual packer calls, and complete inert build readback.
There are zero Watcher application or Rust executions in this stage. The old
SOURCE_QUALIFIED.json is a retained historical baseline, not the expected image
of this new owner. The new exact image is derived from and checked against the
complete same-CI compiler input/output, receipt, manifest, and bytes.

read_build_fixed8.py retains the entire compiler, GAS, packer, buffers, and
flat-image reader. Its only image-identity adaptation replaces the old fixed
owner image with the actual same-CI compiled successor, which is independently
reopened in full. It additionally recomputes the complete symbolic proof from
the frozen old/new sources and retained exact compiler parser source.

The generated assembler, HIA packer, complete flat image, and every intermediate
source/build byte are exported. A later source-bound successor must perform
complete old-capture/new-image buffer comparison and all unchanged application
domains; this source/build stage alone does not qualify Watcher, namespace
versioning, archive storage, HOT_CACHE, begin/finish, or public handlers.

## Failures remain evidence

Semantic V1 and V2 wide258 failures remain unchanged. Semantic V3's pure encoding
proof passed all 14,196 records / 6,710,163,328 full buffer bytes, 24 exact JSON
inverses, and 29 controls. Its fresh wide258 process still timed out at 60 s.
The complete failure inspection aeeb5856 / 44163454834 recorded both native
streams through step 248 and the original through step 247; no old application
was replayed. HIA before/after wall intervals include observation copies and
compression and are not a pure HIA CPU measurement.

Budgets remain 60 seconds per application group, 180 seconds per reader,
900 seconds per build, and 15 minutes per CI job. This package changes none of
those budgets and removes no case, operation, source byte, or retained buffer.

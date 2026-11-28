# Complete native evidence transport

The original native collector still verifies all eleven partitions and seals all
81 original recipes. Its 15-minute job previously reached ORIGINAL_NATIVE_READY,
then exhausted the remaining time while uploading 87,306 individual files. The
transport helper packages the same complete tree into one gzip stream. It does
not select evidence, remove caches, change the original seal, or qualify recipes.

## Complete source and portable inventory

Both inventories inside evidence.tar.gz contain every root, directory and file.
Each row records its type, mode, byte count, SHA-256, nanosecond modification time
and original in-tree hardlink relation. Source capture records also bind device,
inode, owner, group, link count and change time. Directory descriptors and
O_NOFOLLOW opens prevent a source path from crossing a link.

The successful original native seal already admits only owned regular files and
real directories. The transport preserves that domain; symbolic links and
special nodes are refused, never silently omitted. Empty files, empty
directories, hidden names, executable modes and original Unix filenames remain
represented.

The producer hashes the complete source before packing, rechecks each object as
its bytes enter the archive, then reads the full source again. The two complete
physical inventories must be identical. Equal file contents share one transport
object. Restoration creates separate files for unrelated equal contents and
recreates only the hardlink groups present in the original tree.

## Independent binding and safe restoration

The successful producer publishes the archive SHA-256 through its job output.
Every original recipe group and the final aggregate receives that independent
digest along with the unchanged source commit, invocation and original native
seal digest. An artifact's own receipt cannot choose those expected identities.

The reader verifies the complete compressed digest before materializing any
result. It checks canonical inventory JSON, complete member order and size,
every object hash, both full inventories, and the end of the tar/gzip stream.
Missing, extra, duplicate, linked, sparse and traversal members are refused.
Restoration creates a fresh owned tree through directory descriptors; it never
calls tar extraction. After restoring modes, modification times and original
hardlink groups, the full restored portable inventory must equal the admitted
inventory. The existing original native readers and recipe commands then run
unchanged.

The upload action receives an already compressed archive with compression-level
0, supported by its existing pinned action revision. All original 15-, 45- and
60-minute job budgets and every original qualification command remain unchanged.
Failed packing retains its initial receipt and any partial archive; it cannot
publish a successful archive identity or release dependent recipe jobs.

## Executed controls and measurement

Seventeen controls cover complete round trips, the original inventory reader,
independent byte-identical files, hardlinks, modes, Unix names, empty members,
source mutation, identical-byte inode replacement, wrong bindings, malformed
inventories, altered objects, missing/extra/duplicate members, archive links,
traversal, truncation, trailing payload, and existing or symlinked destinations.

A real AI395 measurement used the complete published Shell reference output and
its historical source: 13,588 files, 1,027,769,429 logical bytes. Its 6,088 unique
objects occupied 601,643,854 bytes and compressed to 279,156,248 bytes. Packing
took 8.992 seconds and verified restoration took 5.207 seconds. The unchanged
original native inventory reader returned exactly the same complete result for
the source and restored trees.

This measurement is distinct from the hosted 87,306-file aggregate. Its full
size, upload completion and unchanged original recipe gates require the actual
hosted workflow. The retained initial timeout remains a failure. This transport
does not claim whole-runtime replacement or removal of the old implementation.

The source-bound local validation record is
qualification/evidence_transport_v1/verification.json.

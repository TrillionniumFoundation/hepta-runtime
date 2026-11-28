# Native archive store and held directory leases

This private HIA component implements archive creation, anchor and marker checks,
directory binding, and shard lookup from `request_results.rs`. Its caller supplies
two already authorized, held directory capabilities: the state root and legacy
result directory. Root path validation and reopening, production request admission,
audit validation, result completion, mutex contention, and mutex poisoning remain
separate obligations. No production handler is activated by this component.

## Implementation

`request_archive_store.hepta` owns the operation order, cleanup, identity comparisons,
256 shard initialization, lease generations, and all reply decisions. It calls the
frozen HIA archive publisher, archive metadata reader, typed storage JSON decoder,
and binary codec. Its seven imported serializer/helper functions retain the exact
original HIA IR after function-name relocation; the composition manifest pins them.

The static Linux x86-64 boundary supplies descriptor-relative system calls and
dispatches the pinned HIA images. It contains no JSON parser, policy, record
transformation, host subprocess, hosted interpreter, Rust runtime, or libc dependency.
The HIA packer writes the final ELF and patches its five call displacements. A fresh
build compiles six images: store, publisher, metadata, typed JSON, codec, and packer.

The standalone transport takes two directory paths to establish the supplied
capabilities. Both are opened with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`. This
transport entry does not substitute for the original caller's component-wise root
path walk. Differential fixtures keep that caller root path stable during new
archive acquisition. Existing archive and shard handles are also tested through
rename, replacement, and unlink while they are held.

## Request and response

The outer transport reads an unsigned 64-bit little-endian byte count and that
many request bytes. It writes a 32-bit return code, followed by a 64-byte body
when the code is 64. `0xffffffff` is an invalid private frame or lease state;
`0xfffffffe` is insufficient output/workspace capacity. Neither is a production
JSON error representation.

The request is `HRASQ001` followed by five little-endian 64-bit words:

| Offset | Meaning |
| --- | --- |
| 8 | Operation |
| 16 | Create flag, 0 or 1 for operation 1; zero otherwise |
| 24 | Required archive or shard lease; zero for operation 1 |
| 32 | Payload byte count |
| 40 | Reserved zero |
| 48 | Payload, only for operation 2 |

| Operation | Behavior |
| --- | --- |
| 1 | Acquire an archive; optional first-time creation |
| 2 | Acquire its shard for an exact 64-byte lowercase hexadecimal request id |
| 3 | Verify all 256 pinned shards, dropping each temporary shard handle |
| 4 | Release the held shard |
| 5 | Release the held archive; an independently held shard remains valid |
| 6 | Check the held shard's private mode and report its current identity |

One owner supports one archive and one shard lease at a time. A second archive
acquisition requires both to have been released. Shard acquisition and full shard
verification require an archive and no held shard. Archive and shard generation
counters are independent, monotonic, nonzero, and reject exhaustion. Stale leases
are rejected before any filesystem operation.

The body is `HRASR001` and seven 64-bit words: diagnostic, OS errno, any-lease-present,
archive lease, shard lease, device, and inode. The final pair is nonzero only on a
successful archive acquisition, shard acquisition, or shard inspection. Failed
operations preserve previously acquired leases and clear that returned pair.

Diagnostics 16–30 preserve the inherited private metadata/publisher categories.
Diagnostic 23 carries the actual Linux errno. Additional categories are:

| Diagnostic | Original refusal |
| --- | --- |
| 31 | Anchor missing while a legacy marker proves previous history |
| 32 | Archive namespace already present without an anchor |
| 33 | Root, legacy, store, or archive identity changed |
| 34 | Directory is not owned by the effective user with exact mode 0700 |
| 35 | Invalid archive request id |
| 36 | Selected shard identity differs from its anchor pin |

## Ordering and retained capabilities

An absent anchor triggers the initialization token and a second anchor read. The
owner then checks the legacy marker and archive namespace before deciding whether
creation is allowed. Creation durably adds the store, archive, and 256 hexadecimal
shard directories. Each `make_directory` call preserves mkdir, parent fsync, open,
and private-mode validation order. It captures all 260 directory identities,
publishes the original compact anchor JSON, and reads the actual anchor back.

Temporary creation handles close before initialization unlock. Binding then reopens
the store and archive, compares root/legacy/store/archive identities in the original
short-circuit order, and ensures the legacy marker matches the actual anchor digest.
Only the archive descriptor survives successful acquisition. Acquiring a shard
opens it relative to that held descriptor and compares its identity with the selected
pin; it never enumerates unrelated history. A held shard can outlive its archive.

Failed initialization does not remove created directories or recreate history. The
publisher retains its original temporary-file cleanup semantics. Metadata uses its
frozen 16-entry FIFO anchor cache and verifies the actual bytes before cache reuse.
The serial initialization token models uncontended ownership in this owner; it does
not qualify a process-wide contended or poisoned Rust mutex.

## Effect contract and storage

The owner requires 4 MiB workspace and 64 output bytes. Requests are at most 1072
bytes. State includes an immutable request snapshot, the complete 4480-byte anchor
reply, separate lease counters, and a three-bit handle set. Every yield is a 96-byte
`HRASA001` action with a strictly increasing sequence. Resumption checks the exact
original request, action arguments, acknowledgment sequence, child input bytes,
child result shape, reserved fields, and bounds.

Filesystem effects are open-directory (2), stat/effective uid (3), mkdir (4), fsync
(5), close (6), nonblocking namespace probe (8), lock (11), and unlock (12). Native
child effects are metadata (100) and publisher (101). Descriptor slots 0 and 1 are
caller-owned root and legacy capabilities; 2, 3, and 4 are owned store, archive,
and shard handles. Closing temporary or error-path handles never closes a retained
shard or caller capability.

The ELF maps separate 4 MiB workspaces for store, publisher, and metadata and
separate 1 MiB workspaces for typed JSON and codec, with a final guard page. The
outer request region is read-only during execution. Parent and child file slots
are distinct. Reply validation checks that temporary files, the store handle, and
the initialization token have been released, and that actual retained descriptors
match the HIA lease state before emitting any response.

## Evidence boundaries

The frozen reference extracts the original Rust functions without modifying their
bodies and rebuilds their 22 exact locked dependencies with Rust 1.95.0 on ai395.
The baseline compares 123 real fixture cases, 1235 requests and 1285 observations
per implementation, including all 256 shard lookups and six actual initializations.
Each observed device/inode pair is checked against that process's real held
`/proc/<pid>/fd` entry before those two words are projected for cross-fixture
comparison. Every fixture identity remains pinned to prevent inode-reuse ambiguity.

Anchor projections preserve the remaining file bytes and their serialization
layout. Newly created anchors are checked against all 260 actual directory
identities, and their marker is checked against SHA-256 of the complete actual
anchor bytes. Only verified identity numbers and their corresponding digest are
projected between independent fixtures. Raw replies, fixtures, process observations,
identity maps, and projected comparisons are retained independently.

The kernel fault suite adds controlled errors and owned-fixture races using seccomp
notification. Unselected operations continue in the actual kernel; the observer
does not implement the filesystem semantics or synthesize application replies.
Its execution status and case counts must be taken from the checkpoint evidence,
not from the mere presence of its fixture definitions.

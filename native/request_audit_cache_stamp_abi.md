# Hot-cache methods with actual directory stamps

This private Linux x86-64 composition executes `cache_hot_owned`,
`hot_snapshot_cached`, and `update_cached_completion` through real descriptor
metadata and the complete HIA Namespace owner. All 24 functions of the frozen
cache policy are imported without changing their HIA instructions. Two new
functions admit the supported scope and provide private state inspection.

## Scope and wire

The existing `HRACQ001` 64-byte header and canonical `HRAJJ001` record vectors
are retained. Operations 0, 1, 2, 4 and 5 have the frozen cache ABI. Operation
3, the cold snapshot path, is rejected before execution because this bundle
does not yet contain complete Archive acquisition and seeding. Operations 1,
2 and 4 select a borrowed file token from 1 through 17.

| Operation | Behavior |
| --- | --- |
| 0 | Inspect cache initialization, size and poison flag |
| 1 | Compute a real stamp, then store the supplied owned record vector |
| 2 | Compute a real stamp, then report an exact complete-stamp match |
| 4 | Compute a real new stamp, then update the first matching old stamp and record ID |
| 5 | Qualification-only typed poison transition |
| 6 | Qualification-only inspection of an insertion-order cache position |

Operation 6 uses the header's directory field as an index from 0 through 15.
Its remaining fields are zero and the request has exactly 64 bytes. It
requires at least 266,432 output bytes. It returns the ordinary `HRACR001`
header. An existing entry sets value to 112, record count to its vector size,
then appends its complete 112-byte `HRAST001` followed by the normal length
prefixed record vector. A missing position returns only the 64-byte header.
A poisoned cache returns diagnostic 43. This observation protocol is private
qualification support, not a public MCP operation.

Inputs are at most 1 MiB, the cache workspace is at least 8 MiB, record vectors
contain at most 512 canonical projections, and each projection is at most
512 bytes. Cache slots retain the existing sixteen-entry insertion order.
Malformed private input returns `0xffffffff`, capacity refusal returns
`0xfffffffe`, and invalid private state returns `0xfffffff9`. Rejections leave
the output untouched. Inspection cannot interrupt a suspended cache call.

## Real child execution

The unchanged cache kind-100 effect is fulfilled by the frozen ArchiveStamp
image and its shared Namespace image. No scripted reply is used in the
standalone executable. The same metadata-cache word is shared between Stamp
and Namespace across all seventeen borrowed files. The cache work buffer,
stamp work buffer and Namespace work buffer remain distinct.

The syscall prefix accepts exactly seventeen administrator-owned fixture
paths, opens them with `O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW`, and
holds them for the process lifetime. This is a qualification descriptor table.
A production caller must supply equivalent private custody; these paths are
not a new public path-admission API. The stamp wrapper borrows a table entry,
releases its alias without closing the file, and keeps Namespace watch pins
under the existing owner. Frozen metadata and Namespace dispatch instructions
are unchanged except for symbol relocation.

The executable contains three HIA images: cache, Stamp and Namespace. A fourth
HIA image is the ELF packer. Runtime execution requires no Python, Rust or
libc. The raw file descriptors and syscall calling convention are confined to
the fixed native adapter.

## Verification and remaining scope

A fresh Rust 1.95.0 reference executes fourteen unchanged source blocks,
including the complete original Namespace module and the three original
cache methods. All source members of twenty-two locked registry packages are
verified. Thirty-eight ordinary and eighteen kernel-controlled paired
processes execute 288 requests per implementation. Complete response bytes,
stored record vectors and held descriptor observations match. Twenty-four
selected kernel controls and thirty separate interface controls passed.
The interface controls include twenty-seven rejections and three explicitly
synthetic completions.

Covered behavior includes the sixteen-entry bound, insertion order, queries
that do not promote entries, aliasing of the same inode, full old-stamp
equality, first-record-ID replacement, `None` versus zero elapsed time,
128-bit acceptance timestamps, signed filesystem times, and metadata errors
preceding cache poison checks. The reference uses real `OnceLock` and `Mutex`
state and real private poison panics. Native unwinding and concurrent lock
timing are not qualified by the single-owner process profile.

Cold snapshots, actual Archive seeding, cross-owner storage custody, complete
request-ticket admission/completion, public dispatch, and whole-runtime
replacement remain unfinished. This bundle does not authorize old-stack
removal or production activation.

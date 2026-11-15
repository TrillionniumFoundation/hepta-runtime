# Native bounded audit enumeration

This component implements the production `directory_members` and
`entries_bounded` path for maximum values from 0 through 512. The original hot
cache uses 512; the owner limit used elsewhere is 128. It composes the frozen
audit read and typed JSON owners. It does not claim the archive, global store
lock, active registry, public request dispatch, or complete audit storage.

## Request and response

All integers are unsigned little endian. The request is exactly 16 bytes:

| Offset | Value |
| --- | --- |
| 0 | `HRAEQ001` |
| 8 | Maximum record count, 0 through 512 |

Before any effect, the owner requires a 4 MiB workspace and output capacity of
at least `32 + maximum * 520` bytes. A short output or workspace returns
`0xfffffffe`; malformed input returns `0xffffffff`. Rejection does not write
the output. The static carrier supplies 1 MiB output capacity.

The normal response begins with a 32 byte header:

| Offset | Value |
| --- | --- |
| 0 | `HRAER001` |
| 8 | Diagnostic; zero is success |
| 16 | Original OS errno for diagnostic 23, otherwise zero |
| 24 | Number of records; zero on error |

Each successful record is an eight byte projection length followed by a
complete `HRAJJ001` typed audit Record projection. Projections preserve the
entire u128 accepted time, state, optional u64 elapsed time, and all three
UTF-8 strings. Records are sorted by accepted time and then request ID using
the original byte ordering. The response has no uninitialized padding.

Diagnostic 32 is the original name-count retention invariant. Diagnostic 33
is an unexpected non-staging member or excess record count. Diagnostics
8, 17–19, and 23–28 retain the frozen read owner's meanings. Numeric diagnostic
equivalence is qualified; exact public error formatting is not.

## Filesystem order and custody

The caller supplies one already held audit-directory descriptor. The owner
does not add a private-directory check that the original function lacks.
It opens `.` relative to that descriptor, duplicates the open scan descriptor,
performs the `fdopendir` checks, and consumes actual Linux directory entries.
The scan capacity follows the original libc behavior: the directory block
size clamped to 32768 through 1048576 bytes. The kernel ABI and x86-64 Linux
layout are the qualified platform.

The HIA owner skips inode-zero entries, validates UTF-8, skips `.` and `..`,
and refuses the next name when the collected count is already `maximum + 32`.
Every name is collected before any staging cleanup. A directory-read error
therefore leaves staging unchanged. An ENOENT from directory reading is the
original end-of-stream behavior. Other failures are preserved without an
extra retry. The duplicate is closed before the original scan descriptor.

After both scan descriptors close, all dot-prefixed captured names pass to
the frozen read owner's cleanup operation. Only after that loop completes
are the non-dot captured names checked for `.json`, read, validated, and
sorted. These phases use the captured name list. An entry added after the
scan is first observed by a later enumeration, subject to the existing read
owner's own staging recovery. Completed cleanup is not rolled back by a
later error or process termination.

Read and cleanup requests use `HRARQ001`; their `HRARR001` replies are checked
for magic, lengths, diagnostic/errno consistency, and canonical typed Record
layout. A private copy binds every suspended child request. The child closes
its operation descriptors before returning. The root descriptor remains held
across requests; every other descriptor is closed before a response.

## Persistent action boundary

`f0(readbuf, mutbuf, mutbuf) -> u32` is the entry. `0xfffffff0` suspends for one
descriptor effect or child call. Workspace offset 256 contains `HRAEA001`,
sequence, six action words, acknowledgement sequence, result, errno, and a
reserved zero word. The six action words are independently saved at offset
160. The entry checks those words, the input snapshot, all buffer lengths,
sequence, and acknowledgement before resuming. OS errors require a zero
result. Sequence overflow is refused.

Parent actions are stat (1), close (9), open scan (10), duplicate (11), flags
(12), getdents (13), and read-child invocation (100). Parent scan slots are
3 and 4. The parent and read child share the descriptor table only in
disjoint phases. Child action 100 requires all scan slots to have closed.
The carrier restores the child workspace before each parent entry and
selects the correct owner when acknowledging an effect.

| Workspace region | Offset | Capacity or layout |
| --- | --- | --- |
| Directory bytes | 65536 | Up to 1 MiB |
| Child request | 1179648 | At most 279 bytes |
| Child reply | 16384 | 512 bytes |
| Captured names | 1310720 | 544 slots of 264 bytes |
| Record projections | 1572864 | 512 slots of 520 bytes |
| Input snapshot | 2097152 | 16 bytes |
| Sort indices | 2098176 | 512 u64 values |
| Immutable child input copy | 3145728 | At most 279 bytes |

The static ELF maps input at 4096, output at 1056768, parent workspace at
3 MiB, read workspace at 7 MiB, and JSON workspace at 11 MiB. A final guard
page starts at 12 MiB. It has no dynamic interpreter, runtime Python, Rust,
or libc requirement. The HIA packer emits the complete static ELF; the fixed
machine-code boundary contains framing and checked descriptor syscalls.

## Qualification and limits

The ai395 job `1a1dfd203a8-392-289a` rebuilt all four HIA images and compiled
the reference with Rust 1.95.0, 19 unchanged original blocks, and 13 original
locked registry packages. All 931 archived package members were checked
against their registry checksums, and source files were rechecked after use.

The actual runs compared 105 filesystem cases and 210 requests, 36 kernel
fault/mutation cases and 107 requests, and five controlled process-death
cases with 15 initial/recovery requests, per implementation. Their complete
response bytes, filesystem observations, and selected held descriptor
lifetimes matched. This is 332 requests in 151 processes per implementation.
The separate 26 borrowed-buffer controls are synthetic and have no original
execution or filesystem effects.

The complete evidence archive has 12063 members and 72384045 raw bytes. It was
downloaded with immutable version pins and chunk hashes, and every archived
byte and mode was verified. Eight inaccessible or socket fixtures are
explicit metadata-only records. Selected reports are expanded; complete
comparison observations remain in the verified archive.

This result does not qualify store-wide concurrency, archive acquisition,
hot-cache publication, active-reader pinning, or public runtime activation.
The component is evidence toward replacement, not permission to delete the
old production runtime.

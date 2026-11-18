# Descriptor-bound Linux file information

This extension gives the HIA IO owner operation 3: a complete-file SHA-256
fingerprint followed by descriptor-bound Linux metadata capture. The
operation remains read-only. Its production form is the closed native
composition: IO image 3 calls only the pinned SHA image 2 and requests only
the fixed descriptor effects described here. Neither a Python semantic
dispatcher nor a Rust runtime implements these results.

The original reference is `main(op="info")` and `fingerprint()` in
`src/mcp/runtime/binary_file.py`, with capture and summary in
`src/mcp/runtime/file_metadata.py`, at runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`. The retained source hashes are:

| Source | SHA-256 |
|---|---|
| `binary_file.py` | `c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12` |
| `file_metadata.py` | `24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3` |

## Invocation and authority

The native entry retains the three-buffer ABI
`f0(readbuf, mutbuf, mutbuf) -> u32`. Operation 3 requires at least 8 MiB
of workspace and 75,776 bytes of output capacity. A smaller capacity is
refused before opening a target. The composition binds the IO owner to
module 3, flags 3, and call mask 4; only codec module 2 is callable by this
owner. The compiler's individual-image limits are unchanged.

The existing administrator-owned root is established during startup. It is
never supplied as authority by an MCP request. Every target is traversed
from that held descriptor with no-follow component opens. File information
does not add write, network, process-execution, remote-host or SSH authority.
Opaque descriptor handles remain generation checked in the fixed adapter.

The startup root is at most 4,095 bytes. A target path can contain up to
4,096 UTF-8 bytes because traversal opens separate components. Path
normalization, traversal refusal, root refusal and final `.hepta-` sidecar
refusal are inherited from the existing IO owner. Repeated separators and
single-dot components follow operation 1's normalization rather than
operation 2's canonical-path requirement.

The configured root descriptor has process-lifetime custody. Renaming or
replacing the configured root pathname does not rebind that descriptor.
This explicit local profile differs from starting a fresh remote helper
and reopening the root pathname on every original call. Within an operation
3 request, the final parent descriptor is held across fingerprinting and
metadata reopen, matching the original helper's custody.

## Request

The existing `HIARD001` request header is 112 bytes, followed by the target
path bytes. All integers are unsigned little-endian words.

| Byte offset | Field |
|---|---|
| 0 | Eight bytes `HIARD001` |
| 8 | Request identifier, echoed without imposing global monotonicity |
| 16 | Operation, exactly 3 |
| 24 | Offset, zero |
| 32 | Limit, zero; operation 3 has no total file-size limit |
| 40 | Expected-version flag, zero |
| 48–103 | Seven expected-version words, all zero |
| 104 | Exact path byte count |
| 112 | Path bytes, no trailing terminator in the input frame |

Operation 3 has no `expected_version` parameter. Malformed requests return
status 10 without file effects. Request identifiers are independent of the
adapter's monotonic effect and module-call sequence numbers.

## Success response

The outer response is the existing 128-byte `HIARR001` header. Status and
errno are zero. The payload length is at offset 32. Offset, following offset
and EOF at offsets 40, 48 and 56 are zero for this operation. Seven raw
fingerprint stat words occupy offsets 64–119:

`device, inode, size, mtime_seconds, mtime_nanoseconds, ctime_seconds,
ctime_nanoseconds`.

Seconds retain their signed two's-complement bits. The separate stat-version
HIA codec produces the original five-field textual version. The initial
fingerprint mode, masked with 07777, is at offset 120.

The fixed payload prefix is 128 bytes, beginning at outer offset 128:

| Payload offset | Field |
|---|---|
| 0 | Eight bytes `HIAINF01` |
| 8 | Capture UID, a zero-extended Linux `u32` |
| 16 | Capture GID, a zero-extended Linux `u32` |
| 24 | Capture mode, including special bits, masked with 07777 |
| 32 | Capture link count |
| 40 | Xattr record count, at most 256 |
| 48, 56 | Reserved zero words |
| 64–95 | Raw 32-byte complete-file SHA-256 |
| 96–127 | Raw 32-byte Linux ACL SHA-256 |

Each following record contains an eight-byte name length, that many name
bytes, and a raw 32-byte value digest. Names contain 1–255 bytes, have no NUL,
and are valid UTF-8 scalar strings. Records are strictly sorted by unsigned
UTF-8 byte order, which agrees with scalar-string ordering for this domain.
No raw xattr value is returned. The maximum outer response is
`256 + 256 * (8 + 255 + 32) = 75,776` bytes.

The initial fingerprint mode and capture mode are distinct observations.
They must not be merged by a formatter. This permits the original interval
between reopened-version comparison and metadata capture's first stat.

## Ordered state ownership

1. Resolve and retain the final parent descriptor. A target directly under
   the configured root receives an owned duplicate of the root descriptor.
2. Open the target with no-follow flags, require a regular descriptor, and
   take the fingerprint's initial stat.
3. Read the same descriptor in chunks of up to 1 MiB until a zero-byte read.
   HIA sends every returned byte to the pinned incremental SHA codec. The
   initial `st_size` neither stops reading nor limits the hash. The result
   size still comes from the initial stat, as in the original helper.
4. Take the final fingerprint stat and compare the seven-word version.
   Close the fingerprint descriptor before reopening the final name relative
   to the retained parent descriptor.
5. Require the reopened descriptor to be regular and compare its version
   with the fingerprint. Then take metadata capture's own initial stat.
   There is deliberately no second comparison of this capture-first stat
   against the fingerprint.
6. Fetch the xattr name list, then retrieve each value in the kernel's list
   order. Check the 256-name and 4 MiB value budget after each retrieval,
   preserving which failure is observed first. In particular, retrieve a
   257th value before returning the count-budget failure.
7. Take the capture-final stat and compare only with capture-first. Hash
   the retained values, derive the ACL digest, validate scalar names, and
   sort the summary records after capture has completed.
8. Close the metadata descriptor and then the retained parent. Publish a
   success response only after required closes have completed. For operation
   3, a later close error replaces an earlier error, following the original
   nested finalizers. Operations 1 and 2 retain their prior behavior.

Hardlinks, SUID/SGID/sticky bits and readable existing capability/xattr
metadata are allowed. The restrictions used by writers and by operation 2
are not imposed on this inspection operation. Linux ACL bytes are the
`system.posix_acl_access` value, or empty bytes if that name is absent.

Linux non-UTF-8 xattr names can become surrogate-escaped Python strings in
the original helper and subsequently fail its Rust JSON boundary. This
native profile explicitly refuses such names; it does not normalize, drop
or replace them. macOS ACL APIs and macOS metadata behavior remain outside
this Linux owner.

## Added closed effects

The existing effect envelope remains at workspace offset 256. Result,
errno, opaque returned handle and completion sequence occupy offsets
320, 328, 336 and 344; completion flag 352 is one. The adapter validates
the action-specific spans before performing a syscall. The caller supplies
workspace offsets, never raw addresses.

| Action | Allowed operation and span |
|---|---|
| 4 | Existing `fstat`, additionally permitting the 144-byte stat buffer at 800 |
| 7 | `read` from an admitted file handle into offset 16,384, size 1–1,048,576, argument zero |
| 8 | `flistxattr` on the file handle into offset 2,125,824, capacity 65,536 |
| 9 | `fgetxattr` into offset 16,384, capacity 65,536, with the NUL-terminated name at offset 2,191,360 |
| 10 | Start the fixed inspection guard before target effects; handle, offset, size and argument are zero |
| 11 | `F_DUPFD_CLOEXEC` of the configured-root handle only; remaining arguments zero |
| 12 | Finish the inspection guard after response serialization; size is the complete current output extent, 128–75,776, and other arguments are zero |

The adapter accepts the added actions only for the pinned IO image with its
8 MiB workspace profile. Regular file reads remain descriptor-bound across
chunks. The existing open, close and generation rules still apply. The
kernel's 65,536-byte Linux xattr value/list limits fit the fixed buffers.

### HIA deadline transitions

The guard-capable IO owner yields action 10 at state 55, after framing and
capacity admission but before target traversal. Guard state `w[2192]` is
zero. A successful worker acknowledgement has zero result, errno and returned
handle; HIA changes the guard state to one and performs the ordinary metadata
path. A parent-side `ETIMEDOUT` acknowledgement produces status 15; other guard
setup/transport errors produce status 19. These failures do not import a
partial child state or advance the parent's codec-call sequence.

After all required closes, HIA serializes the typed response, changes guard
state to two, stores its extent at `w[2200]` and yields action 12 at state 56.
For this fixed action the size refers to the current IO output buffer rather
than a caller-selected address. A successful parent handoff acknowledges the
same extent with zero errno and returned handle. HIA then returns to idle
state and publishes that exact extent. A finishing error discards the prepared
result and emits status 19 without starting another finish action.

IO effect sequence `w[24]` and codec-call sequence `w[2184]` must agree with
the corresponding fixed-adapter counters after a completed handoff. The root
handle at `w[72]` retains parent custody. Request handles at offsets 80, 88,
96 and 216 must all be retired before a completed handoff. The fixed guard
must distinguish parent descriptors from worker descriptors, reject partial
handoffs and preserve ownership of any worker whose reaping is uncertain.
Its actual monotonic clock, cancellation and blocked-syscall qualification
are required separately from these HIA state controls.

## Workspace regions

| Offset | Extent and role |
|---|---|
| 2,048 | File-info state, file/ACL digests, persistent codec-call sequence |
| 16,384 | 1 MiB raw file-read buffer; also xattr-value syscall buffer |
| 1,064,960 | Codec request, at most 1 MiB plus 152 bytes |
| 2,117,632 | 128-byte serialized incremental SHA state |
| 2,121,728 | 128-byte codec response |
| 2,125,824 | 65,536-byte xattr name list |
| 2,191,360 | 256-byte NUL-terminated current name |
| 2,195,456 | 256 fixed 64-byte attribute descriptors and digests |
| 2,211,840 | 256 eight-byte summary sort indices |
| 2,228,224 | At most 4 MiB retained attribute values |
| Workspace end minus 256 | Existing checked module-call footer |

All regions are disjoint. The codec's own workspace belongs to its separate
module; its code and state are not aliased with the IO owner's buffers.

## Errors and qualification

Errors have exactly the outer 128-byte response header and no payload,
fingerprint, xattr names or digests. Newly relevant statuses are:

| Status | Meaning |
|---|---|
| 7 | Fingerprint version changed |
| 8 | Stat or file-read error, with errno |
| 9 | Close error, with errno |
| 13 | Reopened descriptor version differs from fingerprint |
| 14 | An xattr name is outside the scalar UTF-8 domain |
| 15 | Inspection deadline expired |
| 16 | Xattr list/value syscall or structurally invalid name-list result |
| 17 | Metadata count/value budget exceeded |
| 18 | Metadata capture's version changed |
| 19 | Deadline setup failed |

Errno-bearing text remains an explicit local diagnostic profile rather than
a claim of exact remote-helper stderr formatting.

`test_file_info_io_state.py` executes the actual IO and SHA images with
explicitly synthetic effect completions, including direct unchanged-helper
controls for metadata budget/error order. It does not claim OS effects.
`test_file_info_io_faults.py` executes the complete static ELF and introduces
selected syscall faults or races only in owned temporary fixtures. Its
supervisor neither reads child memory nor implements result semantics.
`test_info_service.py` supplies exact original-helper result comparisons,
including real Linux xattrs and ACLs. The separate hard-deadline qualification
must pass before operation 3 is treated as closed.

`test_file_info_deadline_state.py` exercises the HIA guard transitions with
synthetic acknowledgements. It verifies timeout/setup recovery, prepared-result
suppression and acknowledgement refusal. It makes no wall-clock or worker
cancellation claim.

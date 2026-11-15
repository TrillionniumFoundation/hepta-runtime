# Archive metadata reads

This component executes the original `read_anchor` and `read_archive_marker`
file operations through HIA, the pinned typed storage JSON decoder and the
pinned binary codec. Its static ELF has no interpreter, Rust, Python or libc
runtime. The caller supplies an already authorized directory descriptor.
The standalone qualification boundary opens its explicit directory argument;
it does not authorize that path or walk its ancestors.

## Private request and response

Integers are unsigned little-endian. Requests have exactly 24 bytes:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `HRAMQ001` |
| 8 | 8 | Operation: 1 reads the anchor; 2 reads the marker |
| 16 | 8 | Zero |

Operation 1 reads `.request-results-v2-anchor.json`. Operation 2 reads
`.request-results-v2.json`. File opens use `O_RDONLY`, `O_NONBLOCK`,
`O_NOFOLLOW` and `O_CLOEXEC`. The caller directory remains held for the
session. Every opened metadata file closes before its reply.

The 64-byte response header is followed by its digest and typed projection:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `HRAMR001` |
| 8 | 8 | Diagnostic class |
| 16 | 8 | OS errno, or zero |
| 24 | 8 | Request operation |
| 32 | 8 | Presence: zero or one |
| 40 | 8 | Projection length |
| 48 | 8 | Digest length |
| 56 | 8 | Parsed anchor cache entries, at most 16 |

A successful anchor response contains 64 lowercase hexadecimal SHA256 bytes
and a 4,352-byte `HRSTJ001` anchor projection. A successful present marker
contains its 320-byte projection and no digest prefix. An absent marker is
successful with zero presence and no payload. An absent anchor returns
`ENOENT`. These are private typed responses, not public MCP response bodies.
The standalone transport prepends an eight-byte request length and a
four-byte response length. Private malformed requests return `0xffffffff`;
insufficient buffers return `0xfffffffe` through the module ABI.

## Original read and cache behavior

Both operations first require a regular file owned by the effective user,
mode exactly 0600, link count one, and initial size at most 98,304 bytes.
Anchor reads then take a second metadata snapshot, read at most 98,305
bytes, reject excess, and compare a third metadata snapshot. The stamp
contains device, inode, size, nanosecond modification time and nanosecond
change time. Marker reads take at most 1,025 bytes and reject more than
1,024; the original marker operation has no after-read stamp check.

Every successful anchor read hashes the actual bytes before consulting the
parsed cache. A matching stamp with a different digest is refused. Cache
misses require schema 2 and exactly 256 shard identities, then append to a
16-entry FIFO. A hit does not promote an entry. Eviction only bounds parsed
cache memory. It does not modify stored history. Marker decoding requires
schema 2 and a 64-byte lowercase hexadecimal binding.

| Diagnostic | Meaning |
| --- | --- |
| 0 | Successful read or absent marker |
| 16 | Initial file identity, permissions, links or size refused |
| 17 | Anchor grew beyond the read limit |
| 18 | Anchor changed during its read |
| 19 | Original cache mutex unavailable; not qualified by this serial owner |
| 20 | Same cached stamp with different actual bytes |
| 21 | Typed JSON decode refused |
| 22 | Anchor schema or shard count refused |
| 23 | Original OS operation failed |
| 24 | Marker exceeds 1,024 bytes |
| 25 | Marker schema or binding syntax refused |
| 26 | Private child module contract refused |

Exact `serde_json::Error::Display` wording is outside this projection.

## Effect boundary and children

The owner uses a 4 MiB workspace, with the sequenced 96-byte `HRAMA001`
effect at offset 256. The effect contains magic, sequence, operation, slot,
span offset, span length, argument and capacity in its first 64 bytes. The
boundary acknowledges the same sequence at offset 64, result at 72, errno
at 80 and zero at 88. The HIA owner checks the preserved request, effect
arguments, sequence and child request bytes on every resume. `0xfffffff0`
means an effect is pending.

| Effect | Meaning |
| --- | --- |
| 1 | `fstat` and effective UID |
| 2 | Open the selected constant metadata name |
| 3 | Read into the declared bounded workspace span |
| 9 | Close the held metadata descriptor once |
| 100 | Invoke the exact typed JSON child |
| 101 | Invoke the exact SHA256 codec child |

Directory slot zero and metadata slot one are boundary capabilities. They
are not caller-selected operating-system descriptor numbers. JSON requests
use `HRSTQ001`. SHA requests use `HRCODEC1`, operation 2 and a zero reserved
word, followed by the actual file bytes. The static HIA packer accepts
`HRAMELF1`, three image lengths and the owner, JSON and codec images. The
manifest pins the prefix, call relocations, sources and all four compiled
HIA images, including the packer.

## Executed qualification and remaining scope

Fresh Rust 1.95.0 and HIA builds on ai395 passed 1,649 file/cache cases:
3,504 requests and 3,595 observations per implementation. Complete response
bytes, fixture metadata and contents were compared. Live owned-process
descriptor inspection confirmed the original directory stayed held and
metadata files closed before every baseline response. A further 23 cases
executed 46 requests per implementation with actual owned-process syscall
notifications: EIO, EINTR, file growth, in-place writes, replacements,
unlink, chmod and after-read metadata changes. Every selected fault was
reached and the resulting response bytes and filesystem states matched.
The original fixture retains 18 exact source blocks and verifies all 1,131
archive members of 22 locked registry packages before and after execution.

This qualifies the described serial read component. It does not qualify
cache mutex poisoning, concurrent cache interleavings, archive publication,
marker creation, directory binding, audit storage, public dispatch, whole
runtime replacement or old-stack removal. The same-stamp/different-hash
branch is implemented; the observed filesystem's timestamps did not
provide a real coarse-timestamp mutation case for that branch.

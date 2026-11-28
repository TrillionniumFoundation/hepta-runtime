# Audit record I/O owner — source-stage private contract

Status: authoring only. No native, Rust, callable or public qualification is claimed by this checkpoint.

Target: d3d75c30719db966b004756f610007a7c723729e, src/mcp/runtime/request_audit.rs
(68414 bytes; SHA256 b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da).

This synchronous private owner implements read_record, cleanup_staging, remove_record and
save_raw_with_sync with real descriptor effects. STORE_LOCK and directory capability custody
remain with the enclosing caller. The owner never resolves a user path, accepts an MCP owner,
opens the archive by ambient path, publishes ACTIVE, or changes HOT_CACHE. Those caller and
archive edges are separate successors. It uses the qualified audit JSON owner for all Record
decode and successful encode operations; it does not implement a second JSON codec.

## Entry and owned memory

f0(readbuf input, mutbuf output, mutbuf workspace) -> u32.

All words are little-endian u64. No pointers occur in a frame. A native wrapper supplies a
nonzero generation and a nonzero borrowed directory capability. A capability identifies
one actual retained descriptor in the wrapper's private table, not an arbitrary process FD.
All newly opened descriptors and directory streams remain owned until their explicit CLOSE
or CLOSEDIR effect. The directory capability is borrowed and is never closed by this owner.

Initial request magic is the exact eight bytes HAIORQ01. Its 128-byte header contains:
magic@0; operation@8 (1 read, 2 save, 3 remove, 4 cleanup); generation@16; directory@24;
flags@32 (save: bit0 replacing, bit1 sync_directory; remove: bit1 only; others zero);
payload_bytes@40; payload_offset@48=128; and zero words@56..120.
Payload is a complete UTF-8 filename for read/cleanup, or a complete HAJPR001 Record for
save/remove. The latter operations admit the caller invariant: request_id and owner are
64 lowercase hex bytes, tool_name is 1..64 lowercase ASCII/underscore bytes. They preserve
the full six typed fields, including both accepted-u128 words and optional elapsed-u64.

The complete initial frame is copied into private workspace before an effect is published.
Workspace requires 16384+initial_extent bytes, output requires 8192 bytes. These capacities
cover the original bounded 2048-byte record read, its complete typed projection and all
private names; neither requirement changes the source's on-disk 2048-byte limit.
An ABI refusal returns 0xffffffff; insufficient buffers return 0xfffffffe. Refusals leave
the complete output and workspace unchanged. No effect is executed on either return.

## Responses and effects

Every accepted invocation returns the complete extent of HAIORS01:
magic@0; kind@8 (0 success, 1 failure, 2 filesystem effect, 3 JSON effect);
sequence@16; generation@24; operation@32; argument0/1/2@40/48/56;
payload0 offset/length@64/72; payload1 offset/length@80/88;
error_family@96; error_code@104; complete_extent@112; reserved@120=0.
Present payloads are contiguous from offset128; absent pairs are zero. Unused fields are zero.

Filesystem operations are fixed: OPEN=1, METADATA=2, EUID=3, READ=4, WRITE=5, SYNC=6,
CLOSE=7, LINK=8, UNLINK=9, RENAME=10, DUP=11, OPENDIR=12, READDIR=13, CLOSEDIR=14.
OPEN adds the source's O_NOFOLLOW|O_CLOEXEC and receives component bytes, the directory
capability, flags and mode. READ/WRITE publish one actual syscall request; HIA owns retries,
partial progress and the read limit. READDIR is exactly errno=0, readdir, errno observation;
the native adapter preserves the complete name bytes and inode, and never filters entries.
The HIA owner owns UTF-8, dot-name and matching-staging decisions. Metadata is the full
source-used type/mode, uid, nlink, size, device and inode projection from the retained FD.
The effect adapter does no admission, record matching, cleanup, JSON or retry policy.

A kind3 JSON effect carries the exact existing HAJRQ001 frame (op1 decode or op3 encode).
The fixed native adapter calls the exact qualified audit_json image with independent owned
buffers, preserves the entire child return/input/output/workspace, and returns the complete
child result. There is no table of expected responses and no Rust fallback.

HAIOACK1 is a 128-byte header plus complete payload:
magic@0; generation@8; sequence@16; effect kind@24; operation@32;
status@40 (0 success, 1 OS error, 2 JSON invalid); errno@48; value@56;
payload_bytes@64; complete_extent@72; and zero words@80..120.
Only the exact current generation/sequence/kind/operation is admitted. Kind3 status2 is
valid only for the frozen codec's actual invalid return. Every error, length, metadata and
capability shape is validated before changing workspace. A repeated or cross-operation ACK
is an ABI refusal and cannot re-execute a syscall.

## Error projection and scope

The private result preserves the distinctions actually consumed by audit callers:
OS errno (including NotFound), write-zero, fixed audit validation messages, record-JSON
rejection, and directory-entry UTF-8 rejection. Existing original error objects and their
complete display strings are retained by the original observer. This ABI carries their
source-used category as an opaque error value; it does not assert a replacement for every
Serde diagnostic Display string. A later caller which exposes those strings must compose
an exact diagnostic owner before its own qualification. No current public qualification is
claimed here.

Save validation occurs before entering the persisted closure. If the newly opened temporary
inode fails validate_file, it is closed but not unlinked. Once persisted work begins, any
failure closes the temporary FD before the original best-effort staging unlink. A failed
directory fsync can leave an already published record; it never triggers deletion of that
record. Non-replacing publication uses linkat then unlinkat; replacing publication uses
renameat. The full original record is reread before replacement binding checks or removal.
Cleanup verifies the complete staging inode and, at nlink2, the published dev/ino binding
before unlink+directory fsync. Every successful deletion remains visible after later failure.

Rust builds/replays and HIA execution occur only in independently frozen CI jobs. Every new
ordinary or control process keeps its declared 60/180-second budget; the CI job remains
15 minutes. Full source, buffers, process streams, actual filesystem observations and all
failed attempts are retained. Public, complete audit caller and runtime activation flags
remain false.


## Exact filesystem reply projection

METADATA success has value=0 and a 64-byte payload: mode@0, uid@8, nlink@16,
size@24, device@32, inode@40, zero@48/56. Mode and uid are u32 projected into u64;
the other source-used values retain their full u64 widths. EUID success has no payload
and the full u32 value. OPEN/DUP/OPENDIR success returns a new nonzero capability.
OPENDIR consumes the successful duplicate only after its actual call succeeds.

READ success returns value=payload bytes, bounded by the exact pending request.
WRITE success returns its actual count with no payload. READDIR always uses status0:
value0 plus no payload means the actual null pointer (errno still determines EOF/error);
value1 carries inode@0 then all bytes before the actual dirent NUL terminator, at most
4096 name bytes. The HIA owner, not the adapter, interprets UTF-8 and scan filtering.
A nonnull readdir result wins even when errno is nonzero, exactly as directory_scan_result.
CLOSE preserves the errno observed immediately after the actual libc close; its failure
is ignored as by File::drop, except that the original fdopendir-failure path reads that
post-close errno. CLOSEDIR is also performed and its return ignored as by the source Drop.

Filesystem failure status1 carries errno1..4095, value0, and no payload; EUID and READDIR
never use status1. JSON-invalid status2 carries value0xffffffff and no payload.
JSON-decode success carries a complete HAJPR001 Record no larger than2176 bytes.
JSON-encode success carries complete UTF-8 JSON no larger than4096 bytes; the owner
then applies the original 2048-byte persisted-record check. The current save/remove
caller invariant bounds the admitted Record projection to320 bytes, without removing
that source-level serialized-size check.

Record-I/O errors are kind1 with no payload: family1 OS errno; family2 fixed source
validation code; family3 Record JSON rejection; family4 directory-name UTF-8 rejection;
family5 WriteZero. Family2 codes are: 1 filename, 2 staging entry, 3 staging identity,
4 staging inode, 5 staging hard-link binding, 6 record inode, 7 record read size,
8 record identity, 9 hot-cache binding, 10 directory metadata, 11 receipt binding,
12 serialized record size. No external error string is accepted as a native decision.

# Archive anchor publication and marker initialization

This private serial owner implements original `publish_anchor`, `new_id`, and
`ensure_archive_marker` behavior through HIA and fixed Linux descriptor
effects. It reuses the qualified archive metadata reader, typed storage JSON
decoder and binary codec as pinned HIA children. The static executable has
no Rust, Python, libc or dynamic interpreter runtime. Its caller supplies
an already authorized directory: the root for anchor publication, or the
legacy result directory for marker initialization.

## Private protocol

All words are unsigned little-endian. The request is `HRAPQ001`, an operation
word at offset 8, payload length at 16, and payload at 24. Operation 1 takes
at most 98,304 bytes of typed ArchiveAnchor JSON. Operation 2 takes exactly
64 lowercase hexadecimal binding bytes. The production archive caller
supplies a SHA256 digest for operation 2.

Operation 1 preserves typed anchor fields, arbitrary u8 schema values and
the shard vector represented by the typed input. The subsequent archive
reader, not publication, enforces schema 2 and exactly 256 shards. Input
decoding precedes filesystem effects, as does constructing the original
typed argument in the reference caller. Invalid frames or typed arguments
return `0xffffffff`. The internal production anchor has 256 shards and is
inside these private argument bounds.

A normal response has exactly 48 bytes:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `HRAPR001` |
| 8 | 8 | Diagnostic class |
| 16 | 8 | OS errno, or zero |
| 24 | 8 | Request operation |
| 32, 40 | 8 each | Zero |

The standalone transport uses `u64 request length + request` and
`u32 response length + response`. It preserves one owner and its child
sessions across requests. The module requires 4 MiB of workspace and at
least 48 output bytes; insufficient capacity returns `0xfffffffe`.

## Filesystem ordering

Publication opens `/dev/urandom` with the original File-open behavior,
including EINTR retry, reads exactly 32 bytes with interrupted-read retry,
and closes that descriptor. Lowercase hexadecimal encoding forms
`.result-anchor-<64 hex bytes>.tmp`. It opens that name exclusively with
mode 0600, no-follow and close-on-exec flags. Umask remains effective.
Typed JSON serialization occurs while this file is held; a serialized
anchor over 98,304 bytes is refused and the temporary name is cleaned up.

For an admitted anchor, the owner writes all bytes, synchronizes the file,
hard-links the temporary name to `.request-results-v2-anchor.json`, unlinks
the temporary name, and synchronizes the root directory. The file descriptor
stays open through link, unlink and parent synchronization. On failure after
creation, best-effort temporary-name cleanup happens while that file is
still held, then the descriptor closes. A publication never overwrites an
existing anchor or repairs partial history automatically.

Marker initialization first reads `.request-results-v2.json` with the exact
metadata reader. An existing valid marker must match the expected digest.
An absent marker enters the serial initialization section and repeats the
read before exclusive creation. It writes the original compact schema-2
marker JSON, synchronizes the file, then the legacy directory. Its file
closes before leaving the initialization section. A failed write leaves
the partial marker in place, matching the original function.

The standalone boundary owns an atomic initialization token for this single
serial actor. This qualification does not establish a contended global
Mutex, poisoning behavior, or shared initialization ownership across
multiple concurrent actors.

## Effects and children

The sequenced 96-byte `HRAPA001` action resides at workspace offset 256.
Its words are magic, sequence, kind, slot, span, count, argument, capacity,
acknowledgement sequence, result, errno and zero. Each resume checks the
original request bytes, action fields, sequence, reserved words and child
request bytes. `0xfffffff0` means a pending effect. Directory slot zero is
held by the caller; local slot one holds the random source or publication
file, with no overlap with a nested metadata read.

| Effect | Meaning |
| --- | --- |
| 2 | Exclusive mode-0600 open of the checked temporary or marker name |
| 3 | Read the remaining random bytes |
| 4 | Write the declared remaining serialized bytes |
| 5 | Synchronize the held file or directory, retrying EINTR |
| 6 | Hard-link the checked temporary name to the constant anchor name |
| 8 | Unlink the checked temporary name |
| 9 | Close the local descriptor once |
| 10 | Open the constant `/dev/urandom` path |
| 11, 12 | Enter and leave the serial initialization section |
| 100 | Invoke the pinned typed storage JSON child |
| 102 | Invoke the pinned metadata reader for a marker |

The metadata child retains its own checked action sequence, workspace and
descriptor protocol. Its JSON and codec dependencies are shared compiled
images. The HIA packer accepts `HRAPELF1`, four lengths and the publisher,
metadata, JSON and codec images. Its separate compiled image emits and
relocates the fixed static ELF prefix. All five HIA source/image identities
are pinned in the build manifest.

Diagnostic 0 means success. Classes 16, 21, 24 and 25 preserve metadata
validation, typed JSON, marker-size and marker-schema refusals. Class 22
means serialized anchor size refused; 23 carries an OS errno; 26 is a
private child-contract failure; 27 is unexpected EOF while reading the
random source; 28 is a zero-length write; 29 is marker binding changed;
30 represents unavailable initialization state. Exact serde diagnostic
wording and original mutex poisoning remain outside this private projection.

## Executed qualification

The final v3 fresh ai395 qualification used Rust 1.95.0, 23 unchanged original
source blocks and 22 original locked registry packages. All 1,131 packaged
source members and the original functions were verified before and after
execution. All five HIA images were freshly compiled. The baseline compared
1,644 cases, 3,295 requests and 3,297 observations per implementation:
complete response bytes, filesystem contents, modes, links, inode
preservation and owned descriptor lifetimes matched.

A further 45 owned-kernel fault cases executed 83 requests in 50 processes
per implementation. These include seven actual RLIMIT_FSIZE short-write
pairs and five requests killed without a response, followed by independent
explicit recovery requests. EIO/EINTR, EOF, zero writes, temporary and anchor
collisions, marker double-check races, failed cleanup and publication death
boundaries were exercised. Every selected fault was reached. Observation
verified each temporary name against the bytes actually read from the
owned child's random source, and verified the publication file was held
through link, unlink, cleanup and directory synchronization. Only these
verified nondeterministic temporary names are projected to ordinal names
for filesystem comparison; response bytes are compared without changes.

The v2 run found an actual native defect: random-source open did not retry
EINTR. V3 changed only the resume function; the other 26 HIA functions are
identical. The failed v2 inputs and process output remain in the complete
evidence archive alongside the successful baseline and final run. The
archive has 49,479 members, all verified locally after retrieval. Eighteen
deliberately unreadable regular fixture files are represented explicitly
by stable metadata and read refusal; no claim is made to have read them.

This component does not qualify full archive directory binding, all-shard
preparation, result or audit storage as a whole, public request dispatch,
general future cancellation, whole-runtime replacement, production
activation or old-stack removal.

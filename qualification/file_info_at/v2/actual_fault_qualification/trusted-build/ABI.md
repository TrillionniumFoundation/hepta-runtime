# Borrowed-parent file_info controller

This source author freezes the original Linux binary_file.py info branch as a
separate HIA owner. Native composition and actual original comparison are still
required. The qualified 67-function fingerprint child and 63-function metadata
child remain byte-identical; this controller does not add modes to either child.

## Parent capability and source ordering

The graph supplies one borrowed parent directory FD, and retains exactly that
descriptor throughout fingerprint, reopen, regular fstat, version fstat,
metadata_capture, metadata_summary and the final owned-file close. The parent
is never duplicated, closed or resolved from a path by this controller. The
basename and original q.path UTF-8 bytes are separate inputs; the original path
is carried unchanged as the successful JSON path field, with JSON escaping.

The exact effect sequence is:

1. Invoke binary_read_body_invoke_at with mode 2 and the same borrowed parent.
2. Open the basename relative to that parent with O_RDONLY | O_NOFOLLOW |
   O_NONBLOCK | O_CLOEXEC and mode 0600.
3. fstat and check regular type, as original regular().
4. A separate fstat, actual stat_version HIA child and equality to the saved
   fingerprint version. Mismatch is the original ValueError.
5. Invoke metadata mode 1 on the same owned file FD.
6. Pass that actual owned snapshot to metadata mode 2 without another capture.
7. Close the owned file exactly as the original finally.
8. Return the complete original JSON value. The original fingerprint, metadata
   and path values are not derived from expected test output.

No comparison is added between step 4 and the first stat inside step 5. Content
and metadata can therefore change in that original window. The metadata owner
retains its own two-stat capture comparison and exact xattr ordering/budgets.

Original regular() has no finally around its first fstat. A non-EINTR fstat
exception in step 3 occurs before its return and before the caller's variable
assignment. This source explicitly transfers that opened FD into an inaccessible
process-lifetime orphan record, without close or dup. Context release/destroy
must not close that orphan; the OS closes it at process exit. This is separate
from the ordinary invalid-regular-type path, which closes and then raises
ValueError. A close failure replaces a pending error, as in the original
finally. EINTR is retried for open/fstat, but close is not retried.

## HIA interface and packet

f0(readbuf, mutbuf, mutbuf) -> u32.
0xffffffff is invalid protocol; 0xfffffffe is output shorter than 64 bytes.
Normal calls return 64, with the full response extent in header word 56.

HINFQ001 has a 96-byte header, all scalars little-endian u64:

| Offset | Start |
| --- | --- |
| 0 | HINFQ001 |
| 8 | command 1 |
| 16 | zero sequence |
| 24 | mode 1 |
| 32 | borrowed parent FD |
| 40 | basename byte length |
| 48 | original path byte length |
| 56,64,72,80 | zero |
| 88 | total payload length |

Payload is basename followed by original path. Both are valid UTF-8. Basename
contains no slash; an embedded NUL is left to the unchanged fingerprint child
so its original ValueError is preserved. The parent FD is 0 through INT_MAX.
For the native exported invocation the packet FD word must be zero; only the
fixed graph register injects the actual parent capability.

Resume command 2 carries the outstanding sequence at 16, actual syscall result
or complete child output length at 24, zero words 32 through 80 and reply bytes.
Negative syscall results carry no payload. Accepted replies repeated for output
growth must match the full saved bytes, sequence and result. There is one
outstanding request. Entire input/work/output capacities remain observable.

## Response and capability operations

HINFR001 has 64 bytes: magic, kind, sequence, operation, a, b, c, payload length.
Kind 0 is final compact UTF-8 JSON, kind 3 is a final nested exception frame,
kind 4 requests workspace growth and kind 5 output growth. Growth extent is at
32, all other nonmagic/nontype words zero. Terminal unused words are zero.

Kind 1 issues fixed capability operations:

| op | a | payload | effect |
| --- | --- | --- | --- |
| 1 | same borrowed parent | basename plus NUL | fixed read-only openat |
| 2 | current owned file | none | fstat, returning all 144 Linux x86-64 bytes |
| 3 | current owned file | none | close, consuming ownership even on late error |
| 4 | current owned file | none | ORPHAN_OWNED bookkeeping; no OS close or dup |

Only op 1 may use the borrowed parent. Ops 2 through 4 consume or use the actual
current openat-owned capability; no input-selected arbitrary FD is permitted.
Op 4 calls the single shared hia_process_orphans_append(pool, fd, origin_context,
generation) primitive, and only its successful ACK may remove
the owner ledger entry, and ACK with result 0/no payload. It is not an OS call.

Kind 2 issues exact fixed children:

| op | a / b | payload | child result |
| --- | --- | --- | --- |
| 1 | same parent / zero | HBRDFD01 mode 2, external FD word zero | complete HBRDS001 |
| 2 | zero / zero | 72-byte HSTVER01 | actual version UTF-8, at most 122 bytes |
| 3 | file FD / 1 | HMDTQ001 mode 1, external FD words zero | complete HMDSR001 |
| 3 | zero / 2 | HMDTQ001 mode 2 plus actual HMTSS001 | complete HMDSR001 |

Child result is copied in full before its borrow is released. The same metadata
context may be reused for summary only after capture release. Raw stat child
input/output/workspace and all nested callable buffers must be retained by an
observed fixture. No expected value can provide a child response.

## Terminal errors and caller duties

A kind 3 payload is one complete unchanged HBRDS001 or HMDSR001 kind 3 exception
frame. Fingerprint and metadata error frames are propagated intact. The info
owner's own ValueErrors and open/fstat/close errors use HBRDS001. HMDSR001
integer-FD filenames preserve metadata's actual field. A downstream qualified
dual-structure formatter must consume the nested frame; old HBRDS001 named=2
is still invalid. This author does not execute or qualify that formatter.

The native ABI to implement is file_info_at_create(callback, context, process_orphans_pool),
file_info_at_invoke(ctx, borrowed_parent_fd, packet, length),
file_info_at_release(ctx) and file_info_at_destroy(ctx). A final output remains
borrowed until explicit release. Active and borrowed contexts reject destroy.
Borrowed parent and process-lifetime orphan records remain outside the owner
close ledger. No SSH, host/path authorization, public tool registration,
async task lifecycle or whole-runtime claim follows from this private ABI.

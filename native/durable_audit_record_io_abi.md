# Audit Record I/O, private ABI 1

This HIA actor owns the complete original Linux audit Record read and staging
cleanup policy. It is a private callee. It does not resolve a public owner or
acquire the audit store lock. Its caller supplies a retained, already admitted
audit directory lease under the original global store guard. It never accepts
an operating-system descriptor in a public JSON request.

The flat six-argument HIA ABI consumes immutable input and private output and
workspace. Input is `HRAIO001`, then little-endian u64 operation (1 read Record,
2 cleanup staging), filename byte length, zero; the raw filename follows.
Workspace is at least 65,536 bytes and output at least 4,096. Input is captured
and compared on every resume. Terminal replay is refused. Return values are
output length, `0xffffffe0` private effect, `0xffffffff` malformed input/state,
or `0xfffffffe` insufficient capacity.

The output `HRADIO01` has a 192-byte header: diagnostic at 8, errno at 16,
Record-payload length at 24, total length at 32, operation at 40. Eleven u64
metadata values at 64 are mode, uid, current euid, nlink, size, device, inode,
mtime seconds/nanoseconds, ctime seconds/nanoseconds. A successful read appends
the actual `HRAJR001` Record result. Cleanup has no Record payload.
Diagnostics 1..4 are Record JSON, identity, size, filename; 16 private Record
inode; 17 staging inode; 18 staging/published hard-link binding; 23 OS error;
24 staging prefix; 25 UTF-8; 26 invalid private effect data; 27 staging ID.
OS errors retain errno and cannot become absence.

## Private effects

At workspace 256, `HRADAS01` occupies twelve u64 words: magic, sequence,
kind, logical slot, workspace span, count, argument, capacity/parent,
acknowledged sequence, result, errno, zero. The first eight words are copied
to a private shadow and compared on resume. Errors require result zero and
errno 1..4095. Result bounds are checked per action. There is no retry of an
unknown effect. All filesystem names are from this actor's captured frame.

| Kind | Exact operation |
| --- | --- |
| 1 | openat on the retained directory or declared scan parent |
| 2 | fstat on the actual held descriptor plus current euid; eleven-word result |
| 3 | read on the held Record; bounded 2,048 + 1-byte refusal probe |
| 4 | unlinkat the validated staging name |
| 5 | fsync the actual directory |
| 6 | close one owned descriptor, consuming ownership before the call |
| 7 | duplicate scan descriptor 4 into private logical slot 5 |
| 8 | getdents64 on slot 5; 32,768-byte chunk |
| 9 | F_GETFL on the actual duplicate |
| 10 | F_SETFD(FD_CLOEXEC) on that duplicate |
| 100 | exact fixed Record HIA child; input at 44000, output at 48000 |

Slot 0 is borrowed. Slots 1..5 are actor-owned and cannot alias public numbers.
The broker must bind these logical slots to its own actual descriptors and
reject undeclared roles. Record opens use O_RDONLY|O_NONBLOCK|O_NOFOLLOW|
O_CLOEXEC; directory opens use O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC.
Cleanup preserves original nlink 1/2 handling, complete published-inode
matching, UTF-8 before filtering, staging order, and the original file-size
limits. Read/fsync retry only known EINTR. Close is never replayed after EINTR.
getdents follows the original Linux glibc EOF/ENOENT behavior and does not
silently retry EINTR. A fresh directory description prevents a caller's prior
seek from hiding members.

## Qualification scope

The complete original Rust functions are compiled under their locked graph as
an independent oracle. The 63 real filesystem comparisons include complete
records, errors, and post-operation directory contents. Thirty extra controls
include actual held-inode path replacement, growth and truncation, explicit
known-error effect injection, forged acknowledgements, changed input, capacity,
and terminal replay. Explicit fault injections are labeled separately from
actual kernel outcomes. The Python broker is qualification scaffolding only.
This component does not by itself qualify a public Runtime handler or replace
the native descriptor engine.

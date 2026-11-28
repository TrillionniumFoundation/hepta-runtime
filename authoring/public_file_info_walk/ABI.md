# Public file-info remote walk

This Linux x86-64 one-shot helper runs the original file-info operation with HIA
business logic and fixed syscall adapters. It does not load Python or libc.
Configured host admission, root selection, SSH, the public response envelope and
the 30-second transport deadline are owned by the calling public gateway.

## Stdin and stdout

The fixed HFRDQ001 start frame has a 96-byte header. Scalars are little-endian u64.

| Offset | Meaning |
| --- | --- |
| 0 | HFRDQ001 |
| 8 | command 1 |
| 16 | zero |
| 24 | mode 1 |
| 32 | root UTF-8 byte length |
| 40 | original path UTF-8 byte length |
| 48, 56, 64, 72, 80 | zero |
| 88 | exact root length plus path length |

The payload is the complete root followed by the original path, without a length
prefix or terminator. Success writes the complete JSON value plus LF to stdout
and exits zero. A business failure writes the original exception class, colon,
space, original exception string and LF to stderr and exits one. The gateway
performs the original JSON decoding and final result serialization. Malformed
private framing and private resource failures exit 111 without business output.

The measured reference profile is recorded in verification.json. The current
CPython 3.14 path converter reports an embedded NUL as
"open: embedded null character in path". The new HIA walk emits that result at
the corresponding directory open or final regular open conversion point. The
unchanged nested fingerprint owner never receives a final basename containing
NUL. All other nested child errors retain their complete structured frames.

## HIA decisions and directory ownership

The walk retains the original PurePosixPath normalization helpers, absolute and
traversal checks, root containment, sidecar check and directory-component order.
It opens slash and each parent directory with the original read-only,
O_DIRECTORY, O_NOFOLLOW and O_CLOEXEC flags. The original unnormalized path is
retained for the result field.

A final HINFQ001 call borrows the actual directory descriptor. The existing
file_info_at, fingerprint, metadata, codec, stat-version and structured-error
HIA images remain unchanged. Their complete result is copied before release.
The parent is closed after the nested call, including failure. A later close
failure replaces the pending exception in the original order.

When closing the old directory fails inside parent(), the original Python code
has not assigned the newly opened child to fd. The new walk retains that exact
behavior: it records the child as a process-lifetime orphan, attempts the
original old descriptor close once more, and returns the final exception. The
native adapter authorizes this one repeated close only from its own immediately
failed close token. Input bytes cannot select arbitrary descriptors. FD zero is
represented by an explicit FD-plus-one token and is tested.

The fixed caller reserves the complete framed child-input extent plus its
response header in both info and fingerprint output arenas before starting
them. This admits long basenames without presenting a started command as a new
command after initial output growth. The six qualified HIA children are not
modified.

## Internal owner protocol

The HIA owner has (readbuf, mutbuf, mutbuf) -> u32. It returns 64 for HFRDR001
headers, INVALID=0xffffffff for invalid private state and CAPACITY=0xfffffffe
when output is shorter than a header.

HFRDR001 has kind at 8, sequence at 16, operation at 24, arguments at 32/40/48
and payload length at 56. Kinds 0 and 3 are terminal JSON and a complete nested
HBRDS001/HMDSR001 error frame. Kinds 4 and 5 request workspace and output growth,
with required capacity at 32 and all other non-kind fields zero.

Kind 1 selects only fixed native effects: 1 opens slash, 2 opens a named directory
relative to an owned parent, 3 closes an owned descriptor, 4 transfers an owned
child to the shared process orphan pool, and 5 performs the one admitted repeat
of a failed close. Kind 2/op 1 invokes the fixed info child with the owned parent
borrow and a complete HINFQ001 frame. Replies use HFRDQ001/command 2 and the
outstanding sequence, actual signed result at 24, zeros at 32..80 and complete
reply bytes after byte 96. Replayed capacity continuations must retain all reply
bytes, sequence and result.

## Native execution and controls

All mutable arenas are guarded RW mappings. The actual HIA linker and image
packer bind the seven runtime images; native code contains no semantic fallback.
The standalone helper arms parent-death SIGKILL and rechecks its original parent
before reading stdin. A real blocked-read test keeps the stdin writer alive in
the controller, kills the original parent, then observes and reaps SIGKILL.

Build variants production, observed, fd-zero and close-error use fixed build
constants. Production contains no journal or fault-installation path. Observed
variants retain every owner/child input and complete workspace/output capacities.
The close-error fixture installs a real seccomp filter on the actual owned
descriptor; the original reference installs the same kernel restriction.
Neither side substitutes a synthetic syscall result.

The builder requires the original frozen source modes and full source manifest,
the admitted B3 compiler, exact author reproduction, no unresolved relocations,
the actual linked segment layout and exact image-pack output. Run:

    python3 -I -B scripts/hia_native_public_file_info_walk.py \
      --source REPOSITORY --hepta PINNED_HEPTA \
      --bootstrap ADMITTED_BOOTSTRAP --output FRESH_BUILD
    python3 -I -B tests/hia_native/test_public_file_info_walk.py \
      --source REPOSITORY --build FRESH_BUILD --output FRESH_CONTROLS

The original qualified child source and earlier failure evidence remain intact.
This scope does not claim network SSH, the default public gateway, other
platforms, memory-exhaustion parity or replacement of the entire runtime.

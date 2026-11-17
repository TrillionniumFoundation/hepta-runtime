# Private namespace fingerprint: producer v1

## Target and present scope

The complete target is src/mcp/runtime/namespace_version.rs at
d3d75c30719db966b004756f610007a7c723729e. The unchanged 1563-byte fingerprint
function and its full 12833-byte parent are bound in reference/ORIGINAL_SPANS.json.
The surrounding watcher, both globals, ContentWatchSet, limits and tests are
retained for the next composition. This source preparation does not qualify any
namespace semantics, watcher, caller, or public route.

The HIA owner controls exactly this fallback: openat of "." using
RDONLY|DIRECTORY|CLOEXEC (589824), fdopendir, repeated unsorted readdir, SHA updates,
closedir, and error selection. Each non-dot entry hashes name length as LE u64,
all raw name bytes, actual inode as LE u64, and the one-byte dtype. No file payload
is opened. The imported seven SHA helpers are the complete qualified
bellman_commitment functions, with only function relocation and inverse AST
equality; the complete binary_codec f13 supplies read64 unchanged.

## HIA frames

All integer words are little endian. Initial HNFRQ001 is exactly 64 bytes:
magic, op1, nonzero generation, nonzero borrowed directory capability, four zero
words. Output must have at least 128 bytes, workspace at least 16384. A reused
workspace must be a valid completed state and the new generation must increase.
There is only one outstanding effect.

HNFACK01 is a 96-byte header plus the complete borrowed raw dirent when present:
generation8, sequence16, operation24, status32, errno40, value48, payload bytes56,
complete extent64, and zeros72/80/88. Status0 is success, 1 is an actual OS error,
2 is end-of-directory and is legal only for readdir. Failed effects normally
require errno1..4095, zero value and no payload. Successful close/closedir retain
the actual ambient errno, including zero. The fdopendir-failure cleanup path
constructs its target error only after close, matching the original byte order.

A successful dirent contains the full actual d_reclen bytes, between20 and4096.
d_reclen at raw offsets16/17 must equal that extent, and d_name at19 must contain
a NUL within it. HIA skips exactly "." and ".." and uses no sorting. Other bytes,
including d_off and record padding, are preserved in evidence and not hashed.

HNFRS001 is always128 bytes: kind8 (0fingerprint,1error,2effect), sequence16,
generation24, operation32, arguments40/48, zeros56..79, error family80/code88,
and digest96..127. Terminal operation is1. Success has the complete32-byte digest
and no error; error has family1 and the actual errno, with zero digest. Code0 is
allowed for the source's close-before-last_os_error case. Effects zero all bytes
56..127 and use this table:

| Operation | Actual boundary and ownership |
|---|---|
|1|openat of "." from borrowed directory capability, flags589824|
|2|fdopendir consumes the owned file only on success|
|3|readdir on the owned DIR, errno explicitly zero before each actual call|
|4|close the still-owned FD after fdopendir failure; forget after attempted close|
|5|closedir after EOF or readdir error; ignored Drop error, forget after attempt|

Malformed frames, wrong live generation/sequence/op, reserved words, extents or
invalid phase combinations return 0xffffffff before HIA mutation. Capacity
failure returns0xfffffffe. A successful step returns128. No synthetic directory
entries or successful completion may be supplied by a production initial input.

Workspace0..1183 is the imported SHA state. Header2048..2303 contains the
continuation; digest2304..2335; copied raw dirent8192..12287; hash length12288..12295.
SHA update reads these disjoint ranges of the same exclusive workspace. HIA
stores all actual data before its next effect.

## Native fixed callable

The generated flat image exports entry, initialize and dispose; exact byte
offsets are emitted by the assembler and bound by the HIA packer composition.
The context is32768 bytes and must initially be fully zero. It is exclusively
borrowed for an entire invocation. This stage does not claim concurrent context
sharing or mutex admission.

initialize(context,capacity,borrowed_directory_fd,table,observer,observer_context)
returns0 on success. The fixed native table contains six actual libc symbols,
in order: openat,fdopendir,close,readdir,closedir,__errno_location, followed by
one zero word. The table is copied into the context; the caller must keep the
actual native code loaded. Root FD is borrowed and never closed. Function
addresses are trusted private capabilities bound to their actual libc object
during qualification, never request fields or fixture effect responders.
A zero observer requires a zero observer_context.

entry(input,input_len,output,output_capacity,context,context_capacity) accepts
the64-byte initial frame, root capability1, nonoverlapping regions and an
increasing generation. It invokes the actual HIA owner and carries each effect
to the actual libc function. Owned file is private capability2, owned DIR is3.
The libc DIR entry borrow is copied completely before another readdir or any
observer callback. Thread-local errno is obtained for each invocation, saved
immediately after each real boundary, and restored across HIA/observer calls.
The final ambient errno is restored before returning.

A completed entry returns128 and copies all128 response bytes. Native initial
shape/capacity rejections return INVALID/CAPACITY without changing supplied
buffers. Reentrant active context returns0xfffffffd. An impossible owner or
boundary contract poisons the context, releases only its actually held owned
resources, and returns0xfffffffc; this is never a target business error.
The caller cannot treat corrupted private context state as a public input.
dispose(context,capacity) requires quiescence, never closes the borrowed root,
and zeros the complete context.

Metadata0..255, borrowed owner input256..4447, output4608..4735,
observer record4864..4991 and owner workspace8192..24575 are disjoint.
Canaries follow the current input, complete output and complete workspace.
Output is always fully captured before/after; no digest-only evidence.

The optional observer receives a128-byte record pointer and opaque context.
Record kind0 is reserved, kind1 is HIA, kind2 is libc; phase8 is0before/1after,
raw return16; first pointer/length24/32, second40/48, third56/64;
native context72, effect sequence80, generation88, actual return96/errno104,
remaining words112/120zero. HIA records expose the full input/output/workspace.
Libc records expose the whole128-byte effect, full4192-byte ACK area and256-byte
native capability header. The observer may only copy these borrows. It does
not supply outcomes, run filesystem work or select continuation. Production
must also be exercised with observer absent.

No runtime Python or Rust is needed by this callable. A host providing the same
real platform ABI is required; linking it into a static public engine remains
a separate integration obligation. This is not process-wide watch qualification.

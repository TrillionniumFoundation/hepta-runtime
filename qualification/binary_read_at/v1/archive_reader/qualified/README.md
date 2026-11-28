# Borrowed directory binary read qualification

The source manifest freezes every input, reader, original source, complete HIA
source, native bridge and process controller before the first application call.
The only executable implementation is the fixed HIA body plus its native
syscall/codec bridge, built by 905769e4 with the exact frozen Hepta fixed point.
The successful complete build archive is downloaded, every ZIP/TAR object and
every restored logical byte/mode/path is read, and the actual build reader is
run under the read-only guard before any filesystem operation is invoked.

The domain has 59 paired inputs: 52 use the new borrowed-parent entry and seven
use the unchanged path entry after borrowed calls. Twenty-one pairs contain
actual filesystem mutations at synchronous barriers before actual OS calls.
Two pairs reduce the child process's real RLIMIT_NOFILE to leave exactly one
descriptor available. The borrowed parent is never duplicated or closed by the
implementation. Its caller checks the same directory inode after the result
loan, after release, and after selected context destruction.

For 38 immutable cases, the original and HIA call read the same real fixture
and compare the full structured result exactly. The 21 mutable pairs have
separate actual files. Their only comparison rebinding is the exact requested
path and the version of each fixture's retained initial stat. Full raw results,
inode/stat records, before/after bytes, notification packets, acknowledgements,
and mutation receipts remain retained. No effect result is supplied by a fake
backend. The external fixture actor changes actual files; each original call
and each HIA raw syscall still obtains its actual OS result.

The original fingerprint function is unedited. The inline private-read branch
is copied by AST into a two-argument wrapper; its complete AST equality and
digest are bound to the original source. This extracts a branch whose actual
caller already owns the parent directory. The original's os proxy delegates
every call unchanged and only emits a fixed notification before calling it.
A separate process owns the mutation and resource-limit changes.

The native private fixture emits every complete body/child arena and raw OS
request/resume, with all growth attempts and unchanged tails retained. Two
independent contexts are exercised. Eight actual protocol refusals preserve
all 4096 context bytes. Eight observer-disabled calls must produce identical
results with no journal or hook output. Physical reader controls reject eight
distinct corruptions and admit two complete relocated captures.

Ordinary application producers are limited to 60 seconds, pure readers and
archive operations to 180 seconds, and the workflow to 15 minutes. A failure
retains all captured evidence and is never relabelled as success. This gate
does not activate a public route or claim async/full-runtime replacement.

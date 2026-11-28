# Current local text publication policy — private candidate

This owner is a source candidate for the target d3d75
src/mcp/fs/text_file_write.rs publication body. It is not a public route,
a configured-path authority, or a completed asynchronous implementation.
The existing typed owner remains a separate qualification.

## Entry and retained state

The common borrowed entry is (readbuf, mutbuf, mutbuf) -> u32.
Three disjoint buffers are required. A successful return of 64 describes the
header only; the complete produced extent is 64 + the payload length at +56.
Bytes after that complete extent are untouched.

Input begins with HTPBQ001 and eight little-endian u64 words.

| Word | Start (operation 1) | Resume (operation 2) |
|---|---|---|
| 0 | HTPBQ001 | HTPBQ001 |
| 1 | 1 | 2 |
| 2 | zero | exact outstanding sequence |
| 3 | create=1 / replace=2 / append=3 | raw syscall return or HIA child byte count |
| 4 | path byte length | zero |
| 5 | content byte length | zero |
| 6 | expected digest byte length | zero |
| 7 | sum of three lengths | response payload length |

A start payload is complete UTF-8 path, content, expected digest, in that order.
The path has already passed the real caller/configuration/path boundary.
This candidate does not infer configuration or identity from this frame.
Each field is bounded by 16 MiB at this private framing boundary; body policy
still limits content to the original 64 KiB. Expected digest syntax and
the source read/output bounds are decided in HIA.

A negative Linux return is encoded as its two's-complement u64 value.
Successful fstat/fstatat carries the complete Linux x86-64 144-byte stat.
Read/getrandom/OS-text and codec results carry their complete produced bytes.
No syscall result is inferred from a requested operation.

Workspace starts with a private retained state header. The input and output
arenas must remain borrowed until each action has been consumed. Output growth
re-enters with the same retained input and complete zero-extended workspace.
A consumed callback can only be retried with the same sequence/return/length;
the application phase has already advanced before a later action can grow.
No external operation is repeated to satisfy capacity growth.

New start is permitted after a final result. It is not permitted while a
previous body has a pending action. Cancellation/future-drop and concurrent
callback delivery are not implemented by this private interface.

## Output

Output begins HTPBS001. Words are kind, sequence, operation, a, b, c, payload
length. Kinds:

| Kind | Meaning |
|---|---|
| 0 | Complete body JSON text, success |
| 1 | Fixed raw OS action |
| 2 | Actual binary_codec child action |
| 3 | Complete body error text |
| 4 | Workspace growth: required size at +32 |
| 5 | Output growth: required size at +32 |

Kind 0/3 has operation/a/b/c zero. It retains the last issued sequence.
Kinds 4/5 have every field zero except magic/kind/needed.
0xffffffff is invalid private framing or an impossible child response;
0xfffffffe means the output header itself does not fit.
The internal 0xfffffffd is never exposed: it advances an HIA phase.

## Fixed mechanical OS actions

These operations implement raw platform effects. HIA owns ordering, tests,
retry policy, expected digest comparison, cleanup and result construction.

| Op | Effect |
|---|---|
| 1 | open "/" with RDONLY, DIRECTORY, NOFOLLOW, CLOEXEC |
| 2 | openat parent directory with the same flags |
| 3 | openat existing file RDONLY, CLOEXEC, NOFOLLOW, NONBLOCK |
| 4 | openat staging WRONLY, CREAT, EXCL, NOFOLLOW, CLOEXEC, mode 0600 |
| 5 | close fd |
| 6 | fstat fd |
| 7 | fstatat parent/name, AT_SYMLINK_NOFOLLOW |
| 8 | flock directory, LOCK_EX |
| 9 | geteuid |
| 10 | flistxattr(fd, null, 0) |
| 11 | read(fd, requested count) |
| 12 | getrandom(requested count, flags=0) |
| 13 | fchmod(fd, mode) |
| 14 | write(fd, complete offered span) |
| 15 | fsync(fd) |
| 16 | renameat2 within the held parent; flag is 0 or RENAME_NOREPLACE |
| 17 | unlinkat(parent, generated staging name, 0) |
| 18 | platform OS-error text for the captured errno |

Paths are complete NUL-terminated borrowed byte spans. The rename payload is
the two complete names; c is the first name's length including NUL.
Fd liveness is retained from the exact returned fd, never fabricated.
The host must keep its effect response until HIA consumes it.

Kind 2 carries a complete HRCODEC1 request to the existing exact HIA SHA owner:
op3 initializes state, op4 updates it in at most 1 MiB chunks, op6 returns
64 lowercase hexadecimal bytes. This is not a host-language hash decision.

## Exact cleanup and scope

The policy closes the opened source before staging. A stage closes before
the target path is rechecked. The generated temporary name is unlinked after
every staging closure outcome; the unlink error is intentionally ignored.
Directory fsync happens after rename and before the cleanup attempt.
Final path identity is checked against staged dev/inode/size before success.
All held fds are dropped before a final body result.

Success rendering preserves the target's complete sorted JSON field order
and binds its version to the actual seven observed stat fields. The caller's
delta::forget happens only after successful body completion and is not yet
connected here. Editor history is not introduced into this tool.

This package initially qualifies source authoring and fresh compilation.
It makes no body semantics, original comparison, public route, full SDK,
concurrency, cancellation, or old-stack-removal claim.

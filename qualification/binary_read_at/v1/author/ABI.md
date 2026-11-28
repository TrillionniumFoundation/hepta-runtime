# Borrowed-parent binary read entry

The existing HBRDQ001 entry and all 63 qualified functions are preserved.
Only f0 is relocated to f63, and a new f0 dispatches its original protocol there.
Four new functions implement dispatch, descriptor start, exact resume and flow.

A graph-only HBRDFD01 start is 96 bytes plus one UTF-8 basename. Words are:
command at 8 = 1; sequence at 16 = 0; mode at 24 = 2 (fingerprint) or 3
(private_read); parent descriptor at 32; basename length at 40; reserved words
48 through 80 = 0; exact payload length at 88. A slash is outside this basename
protocol. Empty names, NUL, dot components and .hepta- names keep their actual
open/type-check behavior. Complete HBRDQ001 command-2 resumes and all
HBRDS001 results, growth and structured errors use the established ABI.

The callable's new fixed export is
binary_read_body_invoke_at(context, borrowed_parent_fd, immutable_packet, length).
The packet's parent word must be zero at this native API. Only the trusted
register argument supplies the capability; the owned input copy receives it.
No public packet can select a process FD, native address or image.

The caller retains ownership of the same parent FD throughout the call.
No duplicate is allocated. The child records borrowed authority separately
from its eight owned file slots, opens regular files relative to that FD,
and closes only its own files. The native effect boundary refuses closing
the borrowed parent. Release, business error cleanup and fatal-context disposal
also leave it open. Native offsets 344/352 track the transient borrow and clear
before exposing a final loan. HIA workspace offset 424 binds the descriptor
continuation; the full existing resume-byte equality check is preserved.

This package authors source only. Actual native compilation, directory-rename
and file-mutation races, descriptor-exhaustion equivalence and public composition
must be qualified separately before installation.

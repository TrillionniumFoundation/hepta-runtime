# Native public multi-file helper

## Purpose and ownership

This one-shot Linux x86_64 executable carries the unchanged qualified
`multi_read_body` and its parent-directory, codec, stat-version, UTF-8 diagnostic
and structured-error images. The caller provides roots that its configured
operator-host policy has already authorized. This private wire is not permission
to nominate an arbitrary remote host or bypass the public path policy.

The complete original reference program is the literal Rust `SOURCE` in
`src/mcp/runtime/multi_read.rs`: its fixed `__name__` assignment, file_metadata.py,
binary_file.py, multi_read_host.py, and the final run_multi_read() call, in order.
The new HIA terminal owner obtains the error prefix from that original Python
body and retains the three original byte-copy/u64 helper ASTs exactly.

The six qualified HIA children and three native capability sources remain
byte-for-byte unchanged. They own all path validation, error precedence,
descriptor walk, independent confirmation walk, strict UTF-8 decoding, version
and SHA-256, JSON escaping, per-file bounds and complete MCP serialized budget.
The new terminal HIA module owns the original error prefix and final newline.

## External request

The input is exactly one complete `HMRDQ001` frame followed by EOF. All fields
are little-endian u64. The 96-byte header is:

| Offset | Field |
| --- | --- |
| 0 | Eight bytes HMRDQ001 |
| 8 | Command 1 |
| 16 | Zero sequence |
| 24 | Limit presence bits: bit 0 file limit, bit 1 response limit |
| 32 | File count |
| 40 | File limit, or zero if absent |
| 48 | Response limit, or zero if absent |
| 56–80 | Five reserved zero words |
| 88 | Complete records byte length |

Records preserve caller order. Each is root byte length, path byte length,
root UTF-8 bytes, path UTF-8 bytes. Public composition sets presence bits to
3 and supplies its admitted effective limits. The unchanged body also supports
its qualified absent-limit form, with defaults 16,384 and 65,536.

The body checks 1..16 files, file limit 1..65,536 and response limit
1,024..262,144 before entry access. It validates every path and duplicate before
opening the first source. All paths are absolute, non-aliased, strict Unicode,
at most 4,096 UTF-8 bytes and NUL-free. The root may be exactly slash.
Malformed private frames are infrastructure failures. The complete transport
input must be at least 96 bytes and strictly smaller than 1 MiB.

## Terminal output

A successful process writes the complete original compact, sorted UTF-8 JSON
followed by LF to stdout, leaves stderr empty and exits 0. A business failure
leaves stdout empty, writes the complete original error to stderr and exits 1:

`multi-file read rejected: ` + exception class + `: ` + exception message + LF.

There is no partial earlier file content on an error. The unchanged body returns
either the complete HBRDS001 exception or the complete HUTFD001 diagnostic.
HBRDS001 passes through the unchanged structured-error HIA module. HUTFD001
already contains the complete class and message; it is not formatted twice.
The new HIA module supplies the common prefix and LF for both forms.

The native caller validates the complete fixed child response and every output
extent. It copies the terminal payload into an owned frame, releases and destroys
the body context, then writes the HIA-produced bytes with EINTR/short-write
handling. The underlying original close/error/orphan ordering remains in the
unchanged qualified graph. The shared orphan primitive is never traversed for
close. OS process exit owns final reclamation.

Private malformed, mapping, fixed-call or transport failures exit 111 and do not
pretend to be an original business result. Exhaustion equivalence is not claimed.

## HIA terminal ABI

`public_multi_read_result` has the standard (readbuf, mutbuf, mutbuf) -> u32
entry. Its HMRFQ001 input is 24 bytes plus payload: kind 0 for success or 1 for a
complete formatted error at byte 8, exact payload length at byte 16. Inputs
outside 24..268,435,455 bytes, wrong magic/kind/length return INVALID (ffffffff).
Insufficient output returns CAPACITY (fffffffe). Both refusals leave the complete
output and workspace unchanged.

Success returns 32. HMRFR001 has kind at 8, complete output byte length at 16,
reserved zero at 24 and the terminal bytes after 32. Output beyond that span is
unchanged. Workspace is unused and unchanged. The native caller reserves output
before invoking this pure function and passes no writable code or address choice.

## Native boundary and process lifetime

The new boundary owns guarded zero-filled mappings, a single input stream, one
fixed multi-read context and one shared orphan pool. All six child call edges
and the terminal edge are fixed by the actual HIA image packer. Every old child
source/image is pinned. Assembly is mechanically flattened with an exact inverse,
assembled without unresolved relocations, linked by the actual HIA linker and
packed by the actual HIA image packer. The original no-WX/segment checks remain.

Before reading stdin, the process records its real parent, installs Linux
PDEATHSIG=SIGKILL and rechecks the parent identity. This prevents a helper waiting
on stdin from surviving its original parent. Actual qualification holds the
pipe's writer in a separate controller, kills the helper's original parent and
observes SIGKILL plus waitpid reaping; EOF is excluded from that control.

Build-only variants expose an observational FD3 journal, or close stdin after
the complete request to allow a real target capability to receive FD 0. Neither
variant is the production executable. HPMRJ001 journals have a 64-byte header:
owner 1 body / 2 source parent / 3 confirmation parent, event, complete span
length, actual context state/generation/owned count, and monotonic observation
sequence. Every passed span is retained in full; the callback supplies no
syscall result, address, file descriptor or policy.

## Build and qualification

Use `scripts/hia_native_public_multi_read.py` with explicit source, admitted
Hepta compiler tree, admitted copied B3 bootstrap, fresh output and optional
`--variants production`. It reauthors the new HIA result and checks complete
qualified source custody before and after nine actual HIA compilations.

The added process controls compare 100 original processes with 100 native
processes byte-for-byte, exercise 18 malformed private requests, retain complete
body/parent journals, check exact response-budget boundaries, test the actual
terminal HIA capacity/tails and verify parent-death reaping. The captured
reference interpreter is CPython 3.14.4 on Linux x86_64.

This helper qualification does not replace public typed admission, configured
host/path policy, the original SSH timeout/error redaction, or the public second
serialization budget check after Value parsing. Those remain explicit gateway
composition gates. It does not claim other-platform or complete-stack closure.

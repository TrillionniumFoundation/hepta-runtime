# Binary write planner to parent adapter

This isolated three-buffer HIA owner binds an existing complete successful write
plan to the actual unchanged planner and emits the parent's `HBPWQ001` request.
It performs no filesystem effect, audit, SSH, path normalization or public routing.
The fixed child is the byte-identical `binary_call_plan.hepta` at SHA256
`fc8624cc760735a0fdaea46fb5c7434c09cc1fe96d8b218d510a3858fe3305bc`.
The carrier must call that child with the complete bytes emitted by HIA. It may
interpret only structural framing and capacity requests; it does not parse JSON
or select application fields. Resume is private to that fixed child boundary.

## Requests and continuation

`HBWAQ001` has a 48-byte header: command at 8, sequence at 16, actual child return
code at 24, trailing size at 32 and auxiliary length at 40, all little-endian u64.
Start command 1 has zero sequence and return code. The auxiliary word gives the
complete phase-2 `HBPLQ001` length; the remainder is the expected complete ready
`HBPLR001`. Only successful typed kind-3 input and successful configured-root
feedback are eligible. This does not change earlier typed/root/caller failures.
The owner checks structural bounds before storing either packet.

`HBWAR001` has a 64-byte header: kind at 8, exact sequence at 16, payload size at
24, detail at 32 and three zero words. Kind 1 is the actual complete planner child
request. The carrier invokes only the fixed planner; its original growth protocol
must finish before resume. The resulting command-2 packet carries the actual
return code and complete returned bytes, with auxiliary zero. The HIA owner
compares every byte, including the whole JSON payload, with the expected ready.
An actual invalid planner return has no published bytes. Kind 3 preserves a
complete mismatching child result with detail 2, or reports actual invalid return
with detail 1. No parent request is emitted in either case.

Kind 2 contains the parent request. Its 96-byte `HBPWQ001` header has command 1,
sequence zero, mode 1, root/path/version/base64 lengths at 32/40/48/56,
expected-version-present 1 at 64, zeros at 72/80, and total trailing bytes at 88.
The payload order is root, path, expected-version, Base64. Public write's original
String version is always present, including the empty string. No FD or function
address is carried. NUL, slashes, invalid Base64 and version spelling are copied
unchanged for their original downstream owners to decide.

The complete result remains borrowed until command 3 releases the matching
finished sequence. Start while waiting or finished, stale resume, duplicate
resume, release before completion, repeated release and sequence overflow refuse.
A released owner may start a new monotonically numbered call. This protocol owns
only the adapter's immutable bytes and child continuation, not parent effects.

## Buffers and refusal

Output shorter than 64 returns `0xfffffffe`. Invalid private input returns
`0xffffffff` without changing output or workspace. `HGRWS002` and return
`0xffffffd0` request workspace or output growth with the exact capacity, preserving
all workspace and the output tail after the 32-byte growth header. Growth must
retain existing workspace and append zeros. Initial metadata bytes 0..255 must
be zero; the remaining workspace is private caller storage. No published output
tail is changed. Input/output retain the existing 128 MiB profile, workspace
256 MiB, and the compiler's original source/function/block/operation limits.

The adapter is not authentication or an independently callable filesystem API.
The future owning runtime must bind the fixed child, host, audit, transport,
cancellation and parent lifetime. All overall/public activation flags stay false.

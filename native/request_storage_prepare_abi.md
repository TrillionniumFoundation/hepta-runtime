# Native result-storage readiness

`request_storage_prepare.hepta` composes the original Unix `prepare_at` readiness
sequence: open the legacy result directory through a component-wise root walk,
walk the root again for archive acquisition, create or validate the anchored
archive, and verify every one of its 256 shard identities. The standalone Linux
x86-64 executable receives the root bytes in its request. No directory descriptor
is supplied by the harness or preopened by a hosted runtime.

This is a private readiness component. Production startup integration, request
admission, audit validation, result completion, public wire error text, contended
initialization, mutex poisoning, and other operating-system targets remain
separate obligations. A successful component qualification does not authorize
removing the production Rust stack or marking a public handler as ported.

## Invocation

The executable takes no command-line arguments. An outer little-endian unsigned
64-bit length prefixes each request. It emits a little-endian unsigned 32-bit
return code, followed by a body only when the code is 32. It can process repeated
requests in one process; each call repeats the actual directory and shard checks.

| Request offset | Field |
| --- | --- |
| 0 | Eight bytes `HRSPQ001` |
| 8 | Operation 1 |
| 16 | Root byte count |
| 24 | Original Unix root path bytes |

Requests range from 24 to 1,048,552 bytes. Root bytes are therefore at most
1,048,528 bytes. Invalid UTF-8, relative roots, dot or dot-dot components, embedded
NULs, missing components, and symlink components follow the native acquisition
owner's original-order path checks and real system calls. An empty root reaches
the ordinary invalid-root diagnostic. Invalid framing returns `0xffffffff`;
insufficient output/workspace capacity returns `0xfffffffe`.

The 32-byte body is `HRSPR001` and three 64-bit words: diagnostic, OS errno, and
success flag. Success is exactly diagnostic zero and flag one. The other flag
value is zero. This binary error projection is a private composition ABI; it is
not the production JSON or human-readable error representation.

| Diagnostic | Meaning |
| --- | --- |
| 1 | Root is not UTF-8 |
| 2 | Root is not absolute or contains `.` or `..` components |
| 3 | A component contains NUL |
| 16–30 | Inherited metadata and publication categories |
| 23 | Actual Linux errno is returned in the next word |
| 31–36 | Inherited archive-history and directory/shard-binding refusals |
| 34 | Private directory mode or ownership refused |
| 37 | Archive acquisition unexpectedly returned no archive |

## Operation and lifetime order

Two separate acquisition states implement the two original root walks. The first
returns the legacy directory and releases its walk descriptors. The second returns
the root capability used by the archive owner. The archive owner's publication,
metadata, identity, and temporary-handle behavior is unchanged from the frozen
archive-store component.

After archive acquisition, the readiness owner releases that second root capability
*before* verifying the shards. This matches `open_archive_store` returning its
archive while dropping its local root. It then verifies all 256 shards using the
held archive descriptor, releases the archive, and releases the legacy directory.
Failure cleanup follows the same owned-handle order. No fixture descriptor remains
open when the response is emitted.

The acquisition derivative `request_store_acquire.hepta` uses `HRDAQ001` requests,
`HRDAR001` replies, and `HRDAA001` effects. Its first two operations retain the
original root/legacy acquisition behavior. Flag one requests capability acquisition
without the private ABI's extra identity-reporting `fstat`; this preserves the
original caller's syscall order. Flag zero retains identity-reporting behavior.
Inspection and release remain operations 3 and 4. The original frozen directory
component and its ABI are unchanged. The derivative imports its four original
UTF-8 and word helpers by exact IR relocation.

## Native graph

The graph consists of readiness, acquisition, archive store, archive publisher,
archive metadata, typed storage JSON, and binary codec images. A fresh build also
compiles the HIA ELF packer, making eight fresh images in total. The packer writes
the fixed Linux boundary and patches seven relative call displacements. It splits
fixed-prefix stores across independent functions to respect the unchanged cold
compiler's 2,048-SSA-name per-function bound. The rejected single-function packer
and its compiler receipt are retained as evidence; all seven semantic images and
the complete fixed-prefix bytes are unchanged by this authoring correction.

Readiness requires 4 MiB workspace and at least 32 output bytes. It stores the
outer request snapshot, independent legacy/root/archive leases, immutable child
request snapshots, and an increasing effect sequence. Its `HRSPA001` effect is
96 bytes: effect 100 calls the selected acquisition state and effect 101 calls
the archive owner. Child requests and replies are bounded and checked before
resumption. Unexpected child-contract state fails the private invocation.

The static boundary allocates distinct 4 MiB workspaces for readiness, legacy
acquisition, root acquisition, archive store, publisher, and metadata, plus the
separate typed JSON and codec workspaces. It protects the outer request against
writes and places a guard page after the mapping. Directory alias slots used by
the archive graph do not own or double-close the acquisition descriptors. Final
reply checks require all owned slots, aliases, and the initialization token to
be empty. The executable requires no interpreter, Python, Rust runtime, libc, or
host subprocess.

## Qualification boundaries

The reference extracts 36 unchanged source blocks, including the complete original
`prepare_at` function, and uses 22 exact locked registry dependencies rebuilt with
Rust 1.95.0 on ai395. The baseline has 121 cases, 278 requests and 323 observations
per implementation. It covers creation, repeat readiness, lost or replaced history,
private modes, selected shard changes, malformed metadata, UTF-8 paths, symlink
refusals, and root strings longer than the kernel's single-path buffer.

Responses are compared as complete bytes. Independent fixture device/inode pairs
and their corresponding anchor digest are projected only after their actual
bindings have been verified; serialization layout and the other file bytes remain
part of the comparison. Every reply is independently checked through the real
child's `/proc/<pid>/fd` entries for descriptor release. Raw source inputs, binaries,
wire bytes, identity maps, file snapshots, and process results remain available.

The additional kernel suite selects real filesystem operations for errors or
controlled mutations. It also checks whether the root is still held at each first
shard open, and replaces the root between the two actual walks while the old legacy
directory is held. Its exact execution result belongs in the checkpoint; fixture
definitions alone are not evidence of execution. Initialization mutex contention
and poisoning remain explicitly unqualified.

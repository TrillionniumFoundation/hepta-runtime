# Audit v12 metadata descriptor protocol

This component ports the fixed original `read_intent`, `read_anchor`, and
`recover_metadata_link` paths from
`src/mcp/runtime/request_archive_store.rs` at Runtime
`abc9ecb95ee9538518ec3f36c47b881974107021`.
It does not implement archive layout creation, the redb index, or the ten public
durable-request handlers.

## Native actor

The entry follows the existing six-argument flat HIA ABI. Supply a fresh,
zeroed workspace of at least 1,048,576 bytes and an output of at least
4,384 bytes. A request is exactly 32 bytes:

| Offset | Value |
| --- | --- |
| 0 | ASCII `HRAAMQ01` |
| 8 | u64 little endian operation: 1 intent, 2 layout anchor |
| 16, 24 | Zero u64 |

The actor captures the entire request and exact capacities at initialization.
It is one-shot. A terminal invocation cannot be replayed.
A private effect returns `0xffffffe0`; terminal results contain
`HRAAMR01`, diagnostic, OS errno, failure point, operation, total length,
presence, and whether a known metadata alias was recovered.
Fields are u64 little endian, starting at offsets 0 through 56.
Offset 64 holds the original ten-u64 metadata stamp:
device, inode, length, mode, uid, link count, mtime seconds/nanoseconds,
ctime seconds/nanoseconds. The original comparison does not contain gid.
Offsets 144 through 159 are zero. A present result appends the independently
parsed `HRAATR01` typed record at 160. Missing and error results are 160 bytes.

## Private effect and retained root

The caller supplies one already-held audit-directory descriptor. It is
borrowed for the actor's lifetime and is never closed or exported.
The private 12-word action starts at workspace offset 256:
magic `HRAAMA01`, sequence, kind, slot, input offset, input length,
argument/output offset, capacity, acknowledgement sequence, result, errno,
zero. The first eight words and the full original request are checked before
effects and again at acknowledgement.

| Kind | Mechanical operation |
| --- | --- |
| 1 | openat of the exact selected metadata, legacy, dot, or validated alias name |
| 2 | fstat into the existing eleven-field physical metadata wire |
| 3 | geteuid |
| 5 | read |
| 7 | close |
| 8 | F_DUPFD_CLOEXEC of the newly opened directory scan |
| 9 | getdents64 |
| 10 | unlinkat of the exact captured matching alias |
| 11 | fsync |
| 100 | Execute the actual typed archive-record HIA parser |

The six private descriptor slots are borrowed root, metadata file, legacy
anchor file, fresh root-dot scan, duplicate scan descriptor, and candidate
alias. The engine owns only slots 1 through 5. It closes those slots in
reverse order on destruction. `take` always returns EPERM.
No descriptor number comes from public JSON.

The fixed, position-independent engine has five ordinary SysV entries:
`create(0, workspace, capacity, root_fd)`, `step(context)`,
`child_ack(context, result, errno)`, `take(context, slot)`,
and `destroy(context)`. Create returns an owned private context or a
negative errno. Step returns zero for a completed syscall or one for a
typed child request. Pending children block step and destroy. Child
acknowledgement checks the entire immutable action, original request, and
all actual child-input bytes. The alias name is copied into private engine
storage before the syscall.

The HIA packer accepts the exact 24-byte
`HRAMPQ01` + u64(1) + u64(0) frame. It emits `HRAMPK01`, total size,
code size, and five code offsets, followed by the complete engine bytes.
Production execution uses those actual HIA-emitted bytes in a sealed
read-only executable mapping. GNU assembly is an independent byte oracle.

## Policy order

The HIA actor preserves the original order: open and private-file checks;
read at most 65,537 bytes; compare the original ten-field stamp; parse the
actual complete typed record; read and bind the original legacy anchor;
check format, root, legacy, and the original shard-count rules; then recover
a known hard-link publication remnant, if needed.

Recovery opens a fresh directory description and duplicates it for the
directory scan. It validates UTF-8 for every directory entry and scans to
the real end without an application entry limit. Only the selected
`.archive-v12-init-` or `.archive-v12-anchor-` prefix, exactly 64 lower-case
hex digits, and `.tmp` suffix may identify a candidate. A candidate must
match the held metadata file's device and inode. Only one matching
two-link candidate can be unlinked. Missing, unknown, partial, or ambiguous
aliases remain errors. Complete scanning and root fsync precede the final
one-link check.

The legacy-anchor read intentionally preserves its original helper
contract; it does not silently add the separate PinnedAnchor positional
read or namespace fences. Filesystem and typed-parser errors are retained
as distinct private results. Read or recovery failures do not restart an
effect or rebind a descriptor.

## Qualification scope

The source includes a complete frozen-original Rust oracle adapter and
an actual native qualification. The oracle uses the original release
profile, default features, Cargo.lock, all 360 registry packages, and all
29 original archive-store test methods. Component controls and filesystem
comparisons are separately recorded. They do not establish public
durable-request or redb qualification.

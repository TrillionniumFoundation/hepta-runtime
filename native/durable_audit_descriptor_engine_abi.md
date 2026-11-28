# Audit descriptor engine and native code emitter

The Linux x86-64 engine implements only the closed Root, Record I/O and Hot
filesystem action contracts. It does not parse records or decide ownership,
permissions, ordering, retention, staging cleanup, or query policy. Those
decisions remain in the HIA actors. Public JSON cannot supply a descriptor.

## Construction

The complete independent mechanical assembly is
`scripts/durable_audit_descriptor_engine.S`, SHA256
`990a1dbd3a90d6a0a6154e9d0031b860b58b178b12201e7d382b8196ca715a8c`.
Its independent ELF extraction has no relocation or external library
dependency. The fixed code record contains all 3423 emitted bytes and the five
entry offsets; no installed assembler is required.

`durable_audit_descriptor_packer.hepta` accepts exactly 24 bytes:
`HRAEPQ01`, unsigned little-endian version 1, and zero. It writes exactly
3487 bytes, whole SHA256
`0420003cb2777ee6ca733d792aa9c9197dbc0d0330a79c1cdfaf1f7208a4951a`:

| Offset | Meaning |
| --- | --- |
| 0 | HRAEPK01 |
| 8 | Whole length 3487 |
| 16 | Flat code length 3423 |
| 24 | create offset 0 |
| 32 | step offset 245 |
| 40 | child_ack offset 2874 |
| 48 | take offset 3066 |
| 56 | destroy offset 3184 |
| 64 | Complete position-independent machine code |

The flat SHA256 is
`d8aafa16374d1ba86085b84c3e54496a6d8bace2d06099a8b18e04255727914b`.
The HIA emitter's complete actual output was compared against the independent
mechanical compilation before use. The original author failure and first
qualification-driver failure remain separate evidence.

## Private calls

All arguments use the ordinary System V x86-64 calling convention.
`create(mode, workspace, capacity, borrowed_fd)` returns a private mapped
context or a negative errno. Modes 0, 1 and 2 are Root, I/O and Hot respectively.
The context is not a public capability. Each context binds the actual HIA
workspace, capacity, action magic, sequence, owned descriptor slots and known
pending child. Borrowed slot zero is never closed or exported.

`step(context)` performs exactly the next acknowledged HIA action. It returns
zero for a completed kernel operation or one for a fixed native child call.
A second step while that child is pending returns EBUSY without repeating the
operation. The first eight action words are frozen before dispatch.
`child_ack(context, result, errno)` requires those exact original words,
sequence, bounds and error shape. The HIA caller independently verifies its own
snapshot again.

`take(context, slot)` transfers an allowed owned Root descriptor exactly once.
`destroy(context)` closes only owned descriptors and refuses an unresolved
pending child. A failed unmap retains the context rather than inventing cleanup
success. Closing a descriptor is never retried after EINTR.

Closed kernel actions are openat, fstat/effective uid, bounded read, unlinkat,
fsync, close, F_DUPFD_CLOEXEC, getdents64, F_GETFL, F_SETFD, the slash-root open and
the fixed hot-directory mkdirat. Action 100 yields a declared native child.
There is no write, rename, general subprocess, arbitrary syscall, or arbitrary
public FD facility.

## Qualification scope

The unchanged original filesystem comparisons ran all 63 I/O, 92 Root and
40 Hot cases through this engine. Thirty-one additional controls cover actual
descriptor transfer, pending-child cancellation, malformed and changed ACKs,
cleanup and independent sealed mappings. The original engine's capacity-ACK
counterexample is a mechanical-layer counterexample; the HIA caller's separate
snapshot already rejected it, so it is not reported as a former public bypass.

History then ran against the actual HIA-emitted flat code. The QA loader seals
a memfd, verifies every byte, and maps it RX. Python transports fixed calls in
this qualification harness. Final runtime routing and the native shared-state
synchronization boundary remain separately qualified obligations.

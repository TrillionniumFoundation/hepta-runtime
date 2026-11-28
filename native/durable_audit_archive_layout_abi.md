# Durable audit physical layout v1

This component owns physical v12 layout admission, durable initialization,
interruption recovery, and retained topology validation. It does not implement
the process-wide Archive weak registry, shared content-watch generations,
redb transactions, or the public durable-request router.

The caller supplies already-open private root and legacy directory descriptors
and a successfully opened retained v11 PinnedAnchor component. All private child
calls use that same root lease. No public JSON field can supply a descriptor.

## HIA actor

The flat six-argument HIA ABI uses a read-only 32-byte request, at least 4480
output bytes and a zero-initialized 1 MiB persistent workspace.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes HRAALQ01 |
| 8 | Operation |
| 16 | Query sequence, starting at one and increasing exactly by one |
| 24 | Zero |

Operation 1 loads the actual layout and preserves the original 64 MiB legacy
directory threshold. Operation 2 initializes or resumes the exact durable
protocol. Operation 3 fences the retained root, legacy anchor, named legacy,
and active topology. Operation 4 validates all 256 retained shard directories.
Operation 5 evaluates the original needs_exclusive_open order.

A pending effect requires the identical complete request on reentry. Successful
queries return 256 bytes for a flat epoch or 4480 for a retained layout; errors
use the same response shape and retain a previously established layout.
Invalid input returns 0xffffffff, insufficient capacity 0xfffffffe, and a private
effect yield 0xffffffe0. Replays, altered capacities and altered pending input
are rejected.

The response HRAALR01 has diagnostic, errno, point, operation, total bytes,
loaded flag, query sequence at offsets 8..56. Root and legacy identities occupy
64..95; child diagnostic and point occupy 96..111; exclusive is at 112.
A loaded result includes the original ten-word anchor stamp at 128 and the
complete 4224-byte HRAATR01 typed anchor at 256.

## Private effects

A 12-word HRAALA01 action occupies workspace 256. Its first eight words are
frozen at workspace 384. The words are magic, action sequence, action kind,
slot, span, count, argument, capacity, acknowledged sequence, result, errno,
and zero. The HIA actor checks the complete frozen request and acknowledgement.

| Kind | Closed action |
| --- | --- |
| 1 | openat with an explicitly permitted component and flags |
| 2 | fstat into the complete eleven-word stat frame |
| 3 | geteuid |
| 4 | fstatat with no-follow metadata |
| 7 | close an owned slot |
| 8 | F_DUPFD_CLOEXEC for a fresh directory cursor |
| 9 | getdents64 into the requested bounded buffer |
| 10 | unlinkat for the fixed initialization intent |
| 11 | fsync a permitted held directory |
| 16 | mkdirat, mode 0700, for the fixed root or two-hex shard |
| 21 | Successful no-op durable checkpoint boundary |
| 100 | Exact metadata HIA child |
| 101 | Exact retained PinnedAnchor fence child |
| 102 | Exact publication HIA child |

Private children receive captured request bytes at 131072 and respond at
262144. Metadata has 32-byte input and at most 4384-byte output; anchor fence
has 32-byte input and 192-byte output; publication has at most 4256-byte input
and 128-byte output. The syscall engine freezes the entire child input, action,
and outer query until its one acknowledgement. It cannot evaluate JSON,
choose recovery policy, or substitute child success.

Checkpoint action 21 is always a successful mechanical no-op. Qualification
can stop after an actual checkpoint acknowledgement to model the original
Rust injected interruption. No product input or environment enables a test cut.

## Mechanical descriptor capability

The HIA packer accepts HRALPQ01 followed by u64 one and zero. It emits HRALPK01,
total length, flat length, and five explicit offsets followed by the fixed PIC
code at byte 64. The independent GNU assembler is only a byte/symbol oracle.
Production execution uses the HIA-emitted bytes in a fully sealed read-only
executable mapping.

SysV entries are create(0, workspace, capacity, root_fd, legacy_fd),
step(context), child_ack(context, length, errno), take(context, slot), and
destroy(context). The external caller invokes them serially on its one owner
event loop. A pending child blocks step and destroy with EBUSY until its exact
acknowledgement. take always returns EPERM.

The 65536-byte private context holds magic HRAALG01, dead flag, workspace
pointer/capacity, last action sequence, pending flag, child length, and 264
descriptor slots. Slots 0 and 1 borrow root and legacy. Slot 2 holds the shard
root; slot 3 is transient work; slots 4..7 hold nested fresh scans; slots
8..263 hold the 256 shard directories. Explicit ownership bytes at 4096
distinguish borrowed descriptors from owned ones. Destroy closes only owned
slots and retains both borrowed descriptors for their caller.

The engine does no path retry, action replay, alias adoption, registry caching,
directory policy evaluation, or JSON interpretation. Invalid acknowledgements
leave the pending child and all owned descriptors intact. The actual child
must be resolved before its owner can acknowledge cancellation and destroy.

## Qualification domains

The original full lock/default-feature release graph and all 29 archive-store
methods remain an independent Rust oracle. The layout oracle adds only
stateful forwarding methods to that unchanged original source.

Current native layout qualification separately tests actual HIA children,
HIA-emitted descriptor code, complete physical files, every original durable
checkpoint, and the 256-shard retained set. Original registry/watch/redb/public
behavior is not inferred from this component's result.

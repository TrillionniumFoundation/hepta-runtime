# Request audit directory stamp

This private Linux x86-64 owner executes the unchanged behavior of
`private_directory_metadata` followed by `namespace_version::version` and
assembles the complete `ArchiveStamp`. The qualification entry receives one
administrator-selected file at startup. A composing runtime must already own
the borrowed file and serialize its workspace access.

## Request and reply

The callable uses `(readbuf input, mutbuf output, mutbuf workspace) -> u32`.
Workspace capacity is at least 1 MiB and output capacity is at least 160 bytes.
The request is exactly 16 bytes: `HRASQ001`, followed by little-endian `u64(1)`.
Malformed input returns `0xffffffff`; insufficient capacity returns
`0xfffffffe`. Those rejections leave the output untouched.

The completed reply directly satisfies the frozen hot-cache kind-100 child
contract. It begins with the 48-byte `HRACC001` header:

| Byte offset | Field |
| --- | --- |
| 8 | Diagnostic: 0 success, 16 private-directory refusal, 23 OS error |
| 16 | OS errno, zero for non-OS results |
| 24 | `ErrorKind::NotFound` bit |
| 32 | Payload length: 112 on success, zero on error |
| 40 | Reserved zero |

An error returns 48 bytes. Success returns 160 bytes with this complete
112-byte `HRAST001` payload:

| Payload offset | Field |
| --- | --- |
| 8, 16 | Device and inode |
| 24, 32 | Signed modification seconds and nanoseconds, preserving all 64 bits |
| 40, 48 | Signed change seconds and nanoseconds, preserving all 64 bits |
| 56 | Namespace kind: 1 watch, 2 fingerprint |
| 64, 72 | Watch identity and generation; both zero for fingerprint |
| 80–111 | SHA-256 fingerprint; all zero for watch |

Directory type is tested before `geteuid`. Ownership and the full `0o7777`
permission mask are checked; the required mode is exactly `0o700`. Metadata
is captured before the Namespace operation, matching the original ordering.

## Suspended effects and custody

`0xfffffff0` suspends the owner. Its 96-byte action at workspace byte 256
contains `HRASA001`, a monotonic sequence, kind, descriptor slot, span, count,
argument, capacity, acknowledged sequence, result, errno and reserved zero.
Descriptor slot zero is the parent's borrowed file. The syscall dispatcher
admits only the precise metadata operations and phase-specific spans.

The metadata cache is at workspace byte 120: 0 unknown, 1 statx available,
2 statx unavailable. The original statx → fstatat → NULL probe → fstat
selection and first-error behavior are retained. The exact frozen shared
Namespace child accepts this cache at request byte 24 and returns it at reply
byte 64. Its 72-byte reply is validated before the cache is consumed.

The Namespace child's request is at workspace byte 8192, its reply at 12288,
and the immutable request copy at 16384. The adapter borrows the descriptor
without closing it, maintains the child's pinned watches, and releases only
its own descriptor aliases. The canonical request, capacities, action fields,
acknowledgement and child request are checked at resumption. The workspace is
private owned state, not an untrusted serialized input format.

## Native composition and verified scope

The executable contains the new stamp image and the byte-pinned shared
Namespace image. A separate HIA packer constructs the ELF. Its fixed prefix
contains syscall and framing adapters; it has no Python, Rust or libc runtime
dependency. Frozen Namespace syscall dispatch is unchanged except for label
relocation. The wrapper borrows parent descriptor slot 128.

Fresh original comparison executed on ai395 with Rust 1.95.0 and all 22 locked
registry packages verified. Seventy paired processes handled 219 requests per
implementation, including 53 selected kernel controls. Complete replies and
held descriptor observations matched. Forty-one additional borrowed-buffer
controls passed, including 38 rejections and three explicitly synthetic
completions. Synthetic controls are not counted as real filesystem evidence.

This closes the qualified private descriptor stamp path. Full Archive
acquisition, cross-owner metadata-cache custody, cache/Archive integration,
concurrent owner interleavings, native language unwinding, public dispatch and
whole-runtime replacement remain separate unfinished work.

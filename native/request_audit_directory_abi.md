# Native audit directory acquisition

`request_audit_directory.hepta` implements the original Linux `audit_root`
and `open_store`/`open_named_store` acquisition sequence, private-directory
inspection, and explicit retained-File lifetime operations. Source SHA256:
`1a199dda8908a87b319b8bdd4114912bbbf783e27886c8804aa789ee54631fe6`.
Its 17 functions include four exactly relocated `text_budget.hepta` helpers.

The caller already holds authority to access the supplied root. A lease number
identifies this instance's one held directory; it is not an authorization token.
Audit STORE_LOCK, archive opening, request identity checks, Record I/O and public
dispatch remain outside this owner.

## Private request and response

Entry is `(readbuf input, mutbuf output, mutbuf private) -> u32`. Output is at
least 64 bytes; private state is at least 4 MiB. Integers are little endian.
Input is 48 through 1,048,576 bytes.

| Offset | Request |
|---|---|
| 0 | ASCII `HRADQ001` |
| 8 | 1 acquire root; 2 acquire/create `request-audit`; 3 inspect; 4 release |
| 16 | Flag below |
| 24 | Zero for acquisition; exact live nonzero lease for inspect/release |
| 32 | Exact root-path byte length |
| 40 | Reserved zero |
| 48 onward | Raw root path for acquisition; empty for inspect/release |

Acquisition requires an empty instance. Flag zero reports device/inode; one
returns only the held capability, avoiding an extra identity-reporting metadata
call. Original routines return File; that extra read belongs to this observation
ABI. Inspect flag one rechecks private ownership and permissions before reporting
identity; zero reports identity without that private check. Release requires zero.

Generations begin at one and increase only on successful acquisition. They never
wrap. Stale leases are refused without discarding the live directory. Release
drops the exact retained descriptor without reopening a path.

Responses have ASCII `HRADR001`, diagnostic at 8, errno at 16, live lease at 24,
device at 32, inode at 40, and zero words at 48 and 56. Capability-only acquisition
and errors report zero identity. Failed inspection retains its lease.

| Diagnostic | Meaning |
|---|---|
| 0 | Completed operation |
| 1 | Root not UTF-8 |
| 2 | Invalid absolute root or dot component |
| 3 | Component contains NUL |
| 16 | Private directory type, owner or exact mode refused |
| 17 | Ancestor has no search bit |
| 23 | Original OS error, with errno preserved |

Malformed frames return `0xffffffff`; insufficient buffers return `0xfffffffe`.
State magic is `HRADW001`. Continuations return `0xfffffff0` with an `HRADA001`
action at private offset 256. Immutable input bytes, buffer lengths, increasing
sequence, fixed action words and matching acknowledgement remain bound. Invalid
continuation state requires retiring the entire mapping.

## Filesystem order

Roots must be valid UTF-8 and absolute, without `.` or `..` components. Repeated
separators are ignored. Linux opens `/` and intermediate components with O_PATH,
O_DIRECTORY, O_NOFOLLOW and O_CLOEXEC; the final component uses O_RDONLY instead
of O_PATH. Before every component open, the current ancestor's metadata must have
at least one execute bit, including for privileged callers. Component NUL
validation follows that metadata/search check, preserving original error order.

Each parent descriptor stays live until its child is open, then is dropped.
Genuine paths longer than PATH_MAX remain descriptor-relative. The final root
must be a directory owned by the effective UID with exactly mode 0700, including
special bits. Execute-only ancestors can be traversed without listing permission.

Hot-store acquisition performs that whole root check, calls mkdirat with 0700,
accepts only EEXIST, and fsyncs the root after actual creation. It then opens the
store without following symlinks, verifies its private metadata, and drops the
root before returning the held store. This audit hot store has no retained-result
legacy-anchor presence check. Fsync retries EINTR; other metadata/open/mkdir errors
propagate. Failure closes newly acquired walk descriptors. Inspection failures
retain the existing held lease.

Action kinds are slash open 1, final/store open 2, metadata 3, mkdir 4, fsync 5,
close 6, descriptor transfer 7 and O_PATH ancestor open 8. Metadata argument zero
also obtains effective UID for a private check; one performs metadata only.
Two walking slots and one retained slot are disjoint. The fixed Linux boundary
checks names, input-component bytes, slots, lengths and flags before syscalls.

The HIA packer emits the 1,750-byte fixed descriptor boundary and the HIA image.
The final static ELF is 89,604 bytes, SHA256
`fbf34963bbb3b9418538f8d6ec9906ff240c7661af188106117f23c5a168562f`.
It has no interpreter, libc dependency or Python/Rust runtime dispatcher.

## Actual qualification

The reference includes ten unchanged audit acquisition blocks and two unchanged
device/inode observation helpers from `request_results.rs`. Rust 1.95.0 freshly
builds the original functions with locked `anyhow` and `libc`. Complete crate
archives/members, source blocks, helper files and input files are checked before
and after execution.

Job `1a1df5ff95f-392-271d` passed in 8.30 seconds. Its fresh HIA component/packer
and original reference matched 155 cases, 483 requests and 495 observations per
implementation. Only independently verified device/inode values are projected;
all remaining response bytes match. Every live lease is checked against the real
process descriptor, stable generation, descriptor number, path, links, owner and
mode. Coverage includes exact modes, umasks, invalid UTF-8/dot/NUL paths, Unicode,
symlinks, wrong inode kinds, execute-only and non-searchable ancestors, paths over
PATH_MAX, held-directory rename/unlink/recreation and stale leases.

The same job passed 23 additional real-kernel cases and 138 requests per
implementation. Every selected EIO/EINTR fault reached its syscall. Root opens,
root metadata, mkdir, root sync, hot-store opens and metadata are covered. Root
replacement during sync/open continues through the already held renamed root;
later acquisition uses the replacement root, matching the original. Supervisors
execute actual owned children and kernel operations, with no directory semantics
or native-response emulation.

Permission-denied enumeration or metadata is explicitly recorded; inaccessible
children are not asserted absent. Earlier adapter-span, duplicate-TMPDIR and
snapshot-permission failures remain preserved as failures. The semantic HIA
source is unchanged from its initial local compilation. Full audit/result
storage, concurrency, other platforms, production activation and old-stack
removal remain unqualified.

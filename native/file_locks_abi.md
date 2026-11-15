# Native file-lock components

This bundle contains two real HIA owners and two HIA ELF packers. The key
executable performs canonicalization through a fixed Linux x86-64 syscall
boundary. The state executable retains its private map, leases and FIFO wait
queues across framed requests and grows its mappings when necessary. Neither
executable loads Python, Rust, libc or another interpreter at runtime.

The bundle is an internal component qualification. It does **not** activate an
MCP handler. A shared concurrent native service, native key-to-state composition,
and the complete edit/create/delete/undo persistence chain remain separate work.
The current Rust production stack remains present. Remote key formatting is
covered; remote SSH/SFTP execution is not.

## Original source ownership

The original reference is runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`.

| Original source | Ownership in this bundle |
| --- | --- |
| `src/mcp/fs/text_editing.rs` | Complete `FILE_LOCKS`, `lock_key_for`, `lock_key_for_source`, and `acquire_file_lock` block; map cleanup plus original Arc/Tokio mutex behavior exercised by the reference harness |
| `src/mcp/fs/remote.rs` | Complete `PathSource` enum and unchanged `lock_key` body |

The original `std::fs::canonicalize` call is synchronous and happens before the
outer map mutex. If full-path canonicalization fails, the original canonicalizes
the raw parent only when both parent and file name exist, appends the original
file-name bytes, and converts the result with Rust's lossy UTF-8 policy. If that
also fails, it converts the original path bytes. Neither Python `pathlib` nor a
lexical normalizer substitutes for this operation.

The native key policy preserves GNU/Linux canonicalization behavior, including
relative cwd resolution, symlinks, the 40-link boundary, trailing directory
requirements, raw Unix bytes and NUL handling. It implements the generic
descriptor-based cwd recovery needed when the direct syscall cannot return the
path. The qualification compares the actual original executable on the same
host and fixtures, with complete retained syscall traces. It records the
observed libc and kernel; it does not assert untested platform parity.

Remote keys are exactly `host + ':' + decimal(port) + path`. The user and both
explicit-option flags do not affect that key. The original oracle actually
evaluates all eight metadata combinations per remote request.

The original sweep condition is `map.len() > 1024`, evaluated before every
acquire lookup. It removes entries whose sole strong reference is the map.
**1024 is a sweep threshold, not a quota.** Retained leases, held guards and
pending acquisitions keep their entry alive. Cancellation removes a queued
waiter; cancelling or dropping a reserved waiter passes the reservation onward.
The original outer map mutex is never held across an await.

## Private lock-state ABI

All integers are little-endian. A request is 64 bytes followed by its UTF-8 key.

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 8 | `HRFLOCK1` |
| 8 | 8 | Operation |
| 16 | 8 | Lease identity, or zero |
| 24 | 8 | Key byte length |
| 32 | 32 | Reserved zero bytes |
| 64 | variable | Key bytes, present only for acquire |

| Operation | Meaning |
| --- | --- |
| 0 | Initialize a fresh zeroed private state |
| 1 | Acquire a lease for an already-derived exact key |
| 2 | Clone an existing lease |
| 3 | Poll lock acquisition; held or pending result |
| 4 | Cancel an unheld acquisition, including a reserved waiter |
| 5 | Unlock a held lease |
| 6 | Drop a lease, cancelling/releasing it as needed |
| 7 | Inspect map and retained-lease counts for the internal caller |
| 9 | Close only after all leases are dropped; wipe the entire declared workspace |

Operation 8 and other undefined operations are refused. Identifiers are private
capability bookkeeping, not public request authority. The state must have one
exclusive native caller while an invocation runs. The serial fixture does not
prove a cross-thread publication or serialization mechanism.

The 64-byte result is `HRFLKR01`, followed by seven u64 values: operation,
status, lease, node identity, map count, strong-reference count, and the waiter
woken by this transition. Status 0 is a completed transition; 1 is pending;
2 asks the trusted boundary to grow the workspace. For status 2, the node field
contains the required workspace size and the entire existing workspace remains
unchanged. The boundary copies all private state into the larger zeroed mapping
and retries the same request. This is a resource continuation, not a new map
limit or a semantic error.

The map uses a full key equality comparison after its hash lookup. Keys may
contain NUL. The private allocator reuses/coalesces idle storage after a sweep.
Reservations prevent a new arrival from overtaking an existing queued waiter.

## Canonical-key ABI

The request begins with `HRLKKEY1` and seven u64 words: operation, path length,
host length, port, and three reserved zeros. Path bytes begin at offset 64;
host bytes follow the path. Operation 1 is Local and requires an empty host and
zero port. Its path is an arbitrary Unix byte string. Operation 2 is Remote and
requires separately valid UTF-8 path and host plus a u16 port. There is no
path normalization or implicit slash in Remote formatting.

Successful output is `HRLKY001`, operation, UTF-8 key length, and a zero u64,
followed by the exact key. Full and parent canonicalization failures select the
original fallback key; they are not converted to a new application error.

The fixed boundary owns two private directory-FD slots. HIA describes exact
relative spans and fixed effect kinds; the caller cannot pass a raw descriptor.
FD 0 is valid. A slot is retired before one close attempt; close is never
retried after EINTR. Fatal state/ABI/transport failures independently close any
still-live slots. A valid result requires both slots to be retired.

The `HFLKEYFX` 128-byte effect record starts at workspace offset 512. Its fields
are magic, monotonic sequence, kind, four arguments, result value, errno,
auxiliary device/inode/mode, completion marker, block size, and two reserved
zeros. Fixed kinds are getcwd, readlink, faccessat2, faccessat, no-follow stat,
access stat, parent open, fstat, close, F_GETFL, F_SETFD, getdents64 and rewind.
The adapter admits only the corresponding phase, fixed flags, exact C-derived
buffer spans and slot constraints. Invalid descriptors do not become arbitrary
syscalls.

Workspace begins with a 1024-byte header and four C-byte regions plus a 1 MiB
directory region. C starts at 1024. Growth moves live regions from high to low,
so changing C cannot overwrite a region that is still needed. Output growth
resumes a terminal HIA result phase and does not repeat filesystem effects.
The HIA workspace must remain private and unmodified between completions.

## Native transport and resource bounds

Each static ELF accepts `u64 request_bytes + request` on stdin and writes a
u32 result followed by exactly that many bytes for a successful response.
Reserved refusal codes have no payload. Clean EOF at a frame boundary exits 0;
partial EOF exits 74. Unexpected argv exits 64. Invalid child contracts exit 70;
mapping failure or size overflow exits 71. Transport failure exits 74. Each HIA
return must be zero extended from u32; dirty high bits are refused.

Both ELF adapters start with 4096-byte input mappings. State workspace starts
at 4096 bytes with a 64-byte output region. Key workspace starts at 1,056,768
bytes with 4096-byte output. These are initial mappings, not semantic quotas.
Growth retains guard pages; input becomes read-only during HIA execution. The
code image is RX and the stack is nonexecutable. The output-length carrier
reserves values at and above `0xfffffff0`; a larger result cannot be represented
by this component ABI and must be reported as capacity refusal, never silently
truncated or relabelled as an original semantic error.

Direct-image qualification uses the existing `history.v1` loader profile
(128 MiB input, 128 MiB output, 256 MiB workspace). This is a test-call carrier;
the ELF adapters grow their own mappings and do not impose that profile as a
new map threshold. No existing common loader/build profile was changed.

## Mandatory qualification

`scripts/hia_native_file_lock_build.py` compiles all four HIA sources with the
pinned d3 compiler, retains complete actual compiler/packer inputs, outputs,
stdout, stderr and receipts, and inspects the exact RX ELF prefix and embedded
image. Cache hits perform those same identity checks. The two source-composition
files bind 13 complete imported functions to their original HIA bodies.

The state suite executes 51,972 direct image calls, including 51,829 retained
reference rows, 57 unchanged-state growth refusals and the typed/state/capacity
controls. It then executes those same 51,829 requests across 23 sessions through
the real growing state ELF. All input and output bytes are retained.

The key suite executes 89,715 real ELF requests: 89,499 Local and 216 Remote.
This includes all one/two-byte path values, complete 5 MiB ASCII and invalid
UTF-8 paths, symlink-size boundaries and reuse after workspace growth. It also
executes 101 direct admission/completion calls, four native packer calls for
invalid-image fixtures, and 16 real transport/control processes.

`tests/hia_native/compare_file_locks_original.py` must actually build the locked
Rust owner and replay the whole state corpus. It runs a fresh native/unchanged
Rust key corpus on the same fixtures, then all 112 real paired kernel controls.
The key bulk performs 91,227 original owner evaluations because all eight
metadata projections are executed for each Remote row. Kernel controls retain
both complete event streams, explicit injected errno/value completions, actual
stdout/stderr, and the exact before/after filesystem snapshots. Only opaque
process instruction addresses and descriptor numbering are normalized; no
different owner event is discarded. Source, artifact and corpus checks do not
count as new original/native semantic executions.

Completed native process stdout is required by the aggregate helper. Native
phase success leaves original Rust status pending; a historical remote PASS
does not substitute for the mandatory fresh Rust recipe. Test fixtures are
retired only after their full raw names, permissions, contents and symlink
targets have been retained. All original 180-second suite/recipe budgets and
the kernel controls' 15/20-second inner limits remain unchanged.

## Remaining ownership

These two internal ABIs expose no network protocol and confer no authorization.
The next controller must canonicalize before map acquisition, publish a shared
state capability under native serialization, and preserve lease and cancellation
lifetime across actual file operations. In particular, original Tokio file
work may continue after the awaiting caller is cancelled; holding a file guard
until all worker effects drain would silently change that original ordering.
Atomic write, history, truthful view-cache updates, undo and final response
rendering require their own connected owner chain. None is declared closed by
this bundle alone.

# Linux native effect-owner fence

This component implements the Linux admission, predecessor replay and permit
lifecycle owned by `src/mcp/runtime/effect_owner_fence.rs`. Its executable runs
five HIA native images and a fixed Linux syscall adapter. Python builds and
qualifies the artifact; it is absent from the executable. The original Rust
module remains unchanged and is compiled as the comparison owner.

The component is not an administrative ownership-transfer protocol. It does
not install RuntimeConfig, advertise an MCP tool, route HTTP requests, replace
the original tool handlers, or prove that every external effect ingress is
fenced. Those activation flags remain false. The framed executable is the
qualification and integration boundary for one process-local owner instance.

## Source and execution ownership

| Image | HIA source | Responsibility |
|---|---|---|
| 0 | `effect_owner_fence.hepta` | Owner admission, process/PTY predecessor checks, replay cache decisions and commit |
| 1 | `effect_fence_fs.hepta` | Typed descriptor effects, original retry rules, private-file admission and metadata capture |
| 2 | `fence_json.hepta` | Exact typed OwnerDocument / LegacyJobKey projection |
| 3 | `binary_codec.hepta` | SHA-256 |
| 4 | `effect_fence_manager.hepta` | Futures, queue, cancellation, private permits, borrows, completion and retirement |

The compiler commit is `d3e2c90173cf733e42b299d0c4274df4b593a12f`.
`effect_fence_profile.json` fixes each source, actual image, byte extent and
direct-call target. The HIA packer hashes all five supplied image bodies before
writing any executable output. The build verifier also extracts the actual
embedded bytes and checks the normalized fixed adapter prefix. A self-consistent
replacement manifest is insufficient to authorize another image.

The artifact is a static Linux x86-64 ELF with an RX load segment, a
non-executable stack and no interpreter. The production pool profile has 512
workers, matching the default in the original locked Tokio implementation. A
separate immutable one-worker packer exists only to qualify work that has been
submitted but remains queued. It is not a configurable request privilege.

## Trusted startup input

The executable accepts exactly `--state-root ADMINISTRATOR_PATH` and reads the
three original environment variables during startup:

* `HEPTA_EFFECT_OWNER_FENCE_DIR`
* `HEPTA_EFFECT_OWNER_SELF`
* `HEPTA_EFFECT_OWNER_FENCE_REQUIRED`

The original environment/required-switch ordering, partial-configuration
refusal, invalid owner encoding and unconfigured legacy bypass are preserved.
The state path corresponds to the successfully loaded administrator
RuntimeConfig's `state_dir`; the standalone boundary receives that trusted
dependency through argv. Native configuration installation and configuration
load errors are a separate dependency, not silently replaced by this adapter.

Startup bytes and completion/EOF events are created by the fixed native
entrypoint. An ordinary frame cannot supply a configuration event, replace a
root, reset the owner or initialize a private scope. Configuration is immutable
for this native instance. Arbitrary later Rust `set_var` calls and multiple
independently configured Tokio runtimes in one process are outside this startup
profile. A production bridge must keep these bytes out of request-controlled
JSON and must not treat an owner hash or serialized boolean as authority.

## Framed lifecycle interface

Each request is a little-endian u64 byte length followed by a 64-byte header and
the indicated host/key bytes. The maximum frame is 8 MiB. No raw pointer, native
FD, syscall number, module address or caller-selected effect buffer is accepted.

| Offset | u64 field |
|---:|---|
| 0 | Eight bytes `HFFASY01` |
| 8 | Command |
| 16 | Existing future or permit ID, or zero |
| 24 | Owner method: 1 admission, 2 process identity, 3 PTY identity |
| 32 | Key present: exactly 0 or 1 |
| 40 | Host byte length |
| 48 | Key byte length |
| 56 | Reserved, zero |
| 64 | Host bytes followed by key bytes |

| Command | Meaning |
|---:|---|
| 1 | Create an unpolled admission future |
| 2 | Submit/poll an existing future |
| 3 | Cancel/drop the caller's future |
| 4 | Create a process/PTY query borrowing an existing private permit |
| 5 | Release the caller's permit; actual drop waits for outstanding borrows |
| 6 | Await a future, submitting it on its first poll |
| 7 | Qualification counters; grants no authority |

An ordinary response is 64 bytes: `HFFASR01`, then u64 transport status, future
ID, permit ID, owner error code, errno, epoch and predecessor-present. Status 0
is a completed transport operation; status 2 rejects an invalid/stale private
handle; status 4 reports an allocation/resource failure of this native adapter.
Resource failure is not relabelled as an original Rust out-of-memory result.
The owner result is independent of transport success. Code 0 is success;
nonzero codes represent the original fixed error category and underlying errno.
The actual Rust comparison adapter uses the same code/errno representation.
Query errors retain the admitted epoch and predecessor flag. A failed admission
grants no permit. Releasing a permit returns zero owner result fields.

Command 7 returns 80 bytes: `HFFAST01`, then historical futures created,
submitted, started, completed, cancelled, released, currently running, queued
and held permits. These counters are observations, not authority claims.

IDs are monotonically allocated nonzero u64 values and are never reused.
Private record slots are reclaimed only after their context, permit, borrow and
parent ownership have ended. A private hash index resolves live IDs. Storage
grows with the live set, not with an ever-growing history of completed futures.
The lifecycle qualification includes more than 16,384 historical creations,
8,193 simultaneous live unpolled records, stale-ID refusal and exact growth.

## Admission and path custody

The HIA owner performs the original component walk, private directory and
private regular inode checks. On Linux it preserves the original flags,
including `O_NOFOLLOW`, `O_CLOEXEC`, `O_NONBLOCK` and the original distinction
between read-only and writable records. Root and controller state must exist,
belong to the effective UID, and have low permission bits 0700. Records must be
regular, current-UID owned, single-link and low permission bits 0600. Special
permission bits are treated as in the original checks, not silently rejected.

The shared owner flock is acquired before reading the owner record. Reading,
reopening and full metadata comparison preserve the original order, including
the later lock-inode and root/state/predecessor pathname checks. The successful
permit retains independently opened authority, state, predecessor and lock
descriptors for the entire submitted effect. A pathname check alone is not a
substitute for the live flock.

Rust's root `File::open` and `read_to_end` EINTR behavior is distinguished from
the original raw `openat` and `flock` calls. Partial reads advance real file
offsets. Descriptor slots retire before `close`; close failures remain ignored
as in the original `File::drop`. The qualification contains real owned inode
replacement, metadata change, root rebinding and actual partial-read controls.
Injected syscall errors are labelled as such rather than described as natural
kernel failures.

## Typed records and predecessor checks

OwnerDocument uses its original typed struct semantics and
`deny_unknown_fields`. It is not parsed through a generic JSON Value map:
known duplicate fields, including duplicate optional nulls, are rejected;
the original map/sequence forms and optional values are preserved.
LegacyJobKey retains the original `IgnoredAny` behavior for unknown values,
including the cases where a whole-input strict UTF-8 precheck would incorrectly
reject data that serde skips. The native typed parser is separately qualified
against the locked original serde implementation.

The process replay owner preserves the original limits: 65,536 job names,
1 MiB per job, 128 MiB total job bytes and an elapsed-time check strictly greater
than 30 seconds. It preserves sorted enumeration, exact field/filename binding,
host and idempotency validation, SHA-256 of host + NUL + key, duplicate refusal,
second enumeration and final metadata/path checks. The bound is not enlarged
for tests. The kernel comparison actually waits past the original 30-second
limit on both implementations without changing their clocks.

The PTY predecessor check uses the original digest-derived name and inode,
directory and root identity rules. An existing valid private terminal record
blocks replay even when its contents are not JSON. Missing terminals and
unconfigured/no-predecessor paths keep their original bypass behavior.

## Shared replay cache

All contexts in one native process map a private, sealed-size cache memfd. The
cache decision, immutable snapshot and commit remain HIA-owned. A fixed atomic
and futex adapter serializes the complete query/scan/commit interval at one
canonical mutex address; the host does not make cache acceptance decisions.

Normal result errors release the cache guard without poisoning it. A worker
failure while the guard is held poisons the process-global cache. Subsequent
queries through both existing and newly acquired permits return the original
cache-unavailable category. The Rust qualification deliberately panics while
holding the real original Mutex, then checks its actual permanent refusal and
live flock retention. No deterministic success response replaces that run.

The original cache distinction is retained: a changed registry directory stamp
after a successful seal refuses; an in-place change to a job file without a
directory stamp change is not retroactively rescanned. Failed scans do not
replace a previously authenticated cache snapshot.

## Cancellation, workers and release

Creating an unpolled future performs no filesystem work and creates no worker.
First poll queues it. Cancellation after submission never removes an already
queued validation or kills a running worker. Every submitted closure still
validates the original owner; a successful abandoned permit is then dropped.
EOF cancels callers and drains all submitted work. Background completion
continues during partial stdin input and output backpressure.

Workers use fixed `clone` flags with shared VM and descriptor table, private FS
TLS, private stacks and separate HIA arenas. Queries borrow the admitted
descriptor chain and register their temporary descriptors above a checked
boundary. Cleanup never crosses that boundary. A permit is dropped only after
its last borrow completes, even if the caller released it earlier.

Workers exit with `SYS_exit`, not process-wide exit. The parent waits for the
kernel `CHILD_CLEARTID` word to become zero and applies the required acquire
ordering before retiring the stack/context. The observed controls bind both
the virtual address and monotonically allocated job ID, so reused mapping
addresses cannot stand in for another allocation's retirement.

The native HIA trap boundary uses an alternate stack and SIGILL handler restricted
to an actual worker and the pinned HIA-image RIP interval. It handles the
controlled HIA failure as the original worker-unavailable category, closes only
owned descriptors and poisons a held cache guard. The worker unblocks only
SIGILL after installing its alternate stack; inherited masks on the parent and
other signals are preserved. Actual inherited-blocked-mask tests are mandatory.
Arbitrary external signals, adapter faults, SIGSEGV or Rust allocation aborts
are not claimed to be equivalent to a caught Rust-language panic.

## Qualification and integration

`build_effect_fence_bundle()` produces both immutable profiles. The seven native
suites require 36 completed unittest groups with zero skipped, failed, expected
failure or unexpected-success groups. They retain 128 actual executable
processes, 49,757 native frames, 249 owner-level comparison responses, 98 real
HIA packer calls and complete syscall/control receipts. Evidence-only controls
add no native or original semantic cases.

The original recipe requires eight actual subprocess checks: exact-toolchain
format check and locked Cargo build for each of the two oracle crates; complete
serial and paired-kernel replays; all five original acquisition test bodies;
and the explicit real Mutex-poison control. No previously captured PASS is a
replacement for this recipe. Development B1/B2/B3 fixed-point reuse is reported
separately from the repository's required fresh cold compiler gate.

To activate a real new-effect handler, its trusted HIA controller must acquire
and privately retain a permit before allocating an effect identity or submitting
work, perform the applicable process/PTY replay check, and release only after
submission and durable intent handling have finished. Reconnection, tool
cancellation and failure paths must preserve that same ownership. Read-only
lookups of completed old-owner jobs keep the original non-gated behavior.
The CLI/framed control surface must not be exposed as an MCP authority-granting
tool. The migration inventory must retain unported call sites and full-runtime
replacement flags until these actual handlers and their configuration lifetime
are connected and independently qualified.

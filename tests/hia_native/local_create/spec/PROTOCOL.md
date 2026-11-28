# Local Create qualification profile

This component follows the unchanged `create_file_spec` Local branch at target
`737acf6f901e46c57b0b4374e323e0d1132e0d49`. The reference retains 21 exact original
items from eight target files and the actual target registry checksums. Its
fresh Rust 1.95.0 build uses Tokio 1.53.3 and Anyhow 1.0.104. The older private
write leaf profile remains independently bound to Tokio 1.53.1.

## Execution and source custody

The ordinary native phase runs 38 complete filesystem/cache cases and 15
owned-process scheduling cases. Each root has its original 60-second deadline;
each complete suite or original command retains 180 seconds. The original phase
executes six recorded processes: compiler version, Cargo version, locked Cargo
metadata, fresh locked release build, all 38 ordinary cases, and all 15 held
cases. No reference process runs during a readonly admission or control.

Both implementations use the same source-declared owned fixture paths, contents,
cache seeds and post-result cache queries. Each side retires its fixtures only
after capturing all bytes and draining its owned workers. Full requests,
responses, every regular file, complete cache contents, syscall results,
requested write payloads and process receipts remain available. Comparison
reopens and compares the actual byte streams rather than treating their hashes
as a substitute for byte comparison.

The native build reader reconstructs all seven member images and the exact
static ELF from the actual HIA packer call, including the complete unused output
tail and workspace. The component state reader separately admits every declared
typed caller/cache and mkdir-await control. Ordinary/held suites and all their
negative controls are additional required domains of that same module.

## Private transport

All requests have an outer little-endian u64 frame length. Before the one Create
request, an independent fixture transport initializes the existing ViewCache
owner with `HVCACH01`; it can set entries and poison the mutex. After Create,
only cache inspections follow. The runtime Create body does not implement a
second cache algorithm.

`HLCSPQ01` has a 64-byte header: operation 1 at byte 8, context selector 1 or 2
at byte 16, raw Unix path length at byte 24, UTF-8 content length at byte 32,
nonzero generation at byte 40, and zero reserved words at bytes 48 and 56.
Path bytes and content bytes follow. Path NUL and invalid UTF-8 remain actual
filesystem cases; content must be UTF-8.

`HLCSPR01` has operation 1, result kind 0 or original error kind 1, and the full
UTF-8 message length at bytes 8, 16 and 24. The message follows at byte 32.
Cancellation is the separate outer scalar `0xfffffff7`. Native `HLCSNA01`
observations retain both complete cache arenas, including unused zero tails;
original `HLCSCS01` observations retain the complete sorted map and poison state.

## Held boundary semantics

The tracer admits only its own launched process and descendants reported by
that owned process. It holds actual synchronous metadata/canonical calls,
whole-worker mkdir syscalls, ready completions, or an already running poll.
The original functions are unchanged. Cancellation uses the original Tokio
AbortHandle through an observer control thread. Native cancellation uses its
existing SIGUSR1 supervisor bit. Repeated Pending uses actual mechanical wake
signals and the existing poll entry, without synthesizing readiness.

Synchronous exists and canonical work do not gain an await. A cancellation
requested while that poll is running is applied at its actual Pending return;
a Ready result in that turn wins. A started mkdir is one whole worker operation
and may finish after cancellation becomes readable, after which Create never
opens the target. The successful tail closes, canonicalizes, notes Create and
returns in the same poll, even without a request cache context.

Native action 10 is a queue acknowledgement before bridge admission. It is not
a safe place to hold the parent while waiting for a worker syscall. When a
same-turn cancellation is already deferred, action 6 with life DROPPED is an
explicit cancellation-publication barrier after admission. The reader records
that meaning and never labels it POLLING. Every started worker is drained and
actually reaped.

Syscall-entry observations can precede pipe commit. A held writer lets another
owned thread commit first. The reader requires every complete journal record
exactly once and an interleaving preserving each owned thread's exact write
order. This is separate from the temporal custody of actual hold/release,
syscall completion, cancellation visibility, future drop and worker reaping.

## Scope

The fixed serial Local scheduling profile is qualified independently of Remote
SFTP behavior, public routing, session ownership, arbitrary Tokio cooperative
budgets, runtime shutdown and the outer TextEditor gateway. All public-handler,
whole-runtime, production activation and old-stack removal flags remain false.
The original Rust sources remain necessary until those surrounding contracts
and all other runtime capabilities are qualified.

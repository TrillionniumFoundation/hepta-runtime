# X230 R16 experiment protocol

This protocol was prepared before the R16 release ABBA run. Results, including
failures and negative experiments, are retained independently of adoption.

## Source and executable identity

The reference is the R14 qualified release, also used by R15's allocator-only
experiments. Its runtime SHA256 is
`51480b3cf630a95419d3afeb571eec17c90cffa5944101920d05333673de031d`.
The repository parent is `a784b92df7c84e6047343b436222716eb4b532d6`
on `perf/x230-r11-20261103`, PR 87.

R16 changes two Rust files: immutable lexical parsing of fixed pin paths and a
single 16 KiB buffer reused inside one complete pin-set verification. It does
not cache descriptors, inode validity, bytes, digests, authorization, or successful
verification. All component opens, complete content hashes, owner acceptance,
agent checks, cancellation checks, and physical resource retention remain.

The exact 219-input source map must agree before and after qualification. Format,
all-target/all-feature Clippy, isolated tests, their independent audit, and the
release build must all pass before a candidate executable is measured.

## Native observation comparison

- Both arms use `MALLOC_ARENA_MAX=1` and `TOKIO_WORKER_THREADS=2`.
- A is the preserved reference; B is the exact qualified candidate.
- Four new controllers run in ABBA order. Each also has a normal restart check.
- Concurrency is 1, 4, 8, and 16; each cell has 24 balanced warmup calls and
  192 measured calls, balanced over six aliases and status/read operations.
- The topology is the historical profile's verified six distinct host groups.
  In that profile `main` is a Linux host. Current connector alias meanings are
  not substituted for the historical configuration.
- The fixtures are completed jobs. This comparison measures observation, not
  new launches, successful cancellations, or complete cluster CPU.
- Full response bytes and indexes, raw monotonic endpoints, raw controller CPU
  counters, resource traces, missing samples, and the original report are kept.
- There are no automatic RPC retries and no success-only denominator. Any
  unexpected refusal, failed call, cleanup failure, or changed input fails the
  relevant campaign. A failed campaign is preserved rather than overwritten.

Controller CPU per completed call and successful calls per second are considered
together with p95/p99 latency and controller/observed-descendant resource peaks.
Per-round results remain visible; two processes per arm cannot establish broad
statistical significance. Changes comparable to within-arm variation are
inconclusive. A further comparison is justified only to resolve a concrete
uncertainty, and is reported separately rather than pooled after the fact.

## Correctness, configuration, and mechanism checks

The recovery canary creates six private jobs. It verifies running observations,
interruption of its own private ROG SSH master, death of its own controller,
same-key reuse, concurrent cancellation, durable terminal outputs and witnesses,
normal restart, and repeated cancellation after exit. It never signals a shared
master or another task and does not retry uncertain writes.

The worker configuration comparisons hold the binary and allocator constant and
use separate ABBA runs for workers2 versus workers1 and, if needed, workers4.
Every first and restarted controller must have an independently verified live
startup environment. These runs are configuration evidence, not source deltas.

C32 is a separate boundary diagnostic. Client requests in flight are not assumed
to equal simultaneously admitted pool identities. Successful replies, explicit
capacity refusals, and other errors are classified separately; refusals never
count as successful throughput. Post-burst readback and cleanup are required.

The two ignored pin microbenchmarks use preserved test-profile executables.
Their Cargo profile is retained and their results are described only as local
mechanism diagnostics. They cannot establish release runtime throughput or RSS
savings. In particular, less sequential buffer initialization is not equivalent
to removing that many bytes of simultaneously resident memory.

## Rejected and deferred directions

The 64/256 KiB buffer diagnostic retains all paired results and full-hash checks;
it does not establish a stable end-to-end advantage over 16 KiB. A proposed
single-open `openat2` substitute is rejected because a real execute-only parent
directory is accepted where the existing per-component read-open rejects it.

Broader worker counts do not change the pool's independent current-thread owner
or its fixed validation concurrency. Grouping durable audit writes, introducing
persistent remote helpers or native bounded-wait protocol operations, changing
security boundaries, or raising capacity are separate architectural proposals.
They are not inferred safe or beneficial from this experiment.

Adoption requires preserved behavior and measurable benefit for a clearly named
workload or a demonstrated elimination of unnecessary work without a new cost
that outweighs it. Tradeoffs remain explicit. No finite campaign is described as
proof that every possible workload or implementation has reached an optimum.

# Native process boundary and qualification

This integration shares the existing Hepta Runtime implementation between the
MCP executable and a trusted in-process Rust host. The facade uses the original
durable process owner, receipt store, SSH execution and recovery logic. It adds
no model provider, conversation store, FinalUse issuer or independent effect
owner. A successful shadow-intent digest remains non-authorizing.

## Exact source composition

| Input | Exact source | Role in this integration |
| --- | --- | --- |
| P0–P3 and CI base, runtime PR #68 | `ceae1b86f705e413a28948385bf57c684651c298` | Base checkout; strict path, receipt, audit and binding checks |
| Adopted A20 source | `7da3a7ebaded8214bc65e69046b74e6251e21767` | Merged recovery, publication witness, observation and scheduling implementation |
| Native library donor | `f4ff86681ead2c538b69ce9bdea86e79e3bb94a7` | Imported and adapted library/executable boundary; this is source provenance, not a claim of merge ancestry |
| Canonical shadow ABI, runtime PR #66 | `55ea025817a0d864024c42a9f155a1f3ae59af2c` | Imported non-executing wire contract and shared golden fixture |
| Corresponding execution-core decoder repair, private-ci PR #3666 | `77885b80b574d89f4dd7668d873348e0219cabb7` | Separately tested strict canonical decoder; not a runtime merge input or a runtime test result |

The shared canonical golden digest is
`9ef6afcc1658e9d022a321e0d2decaac71445433c96591a7c1c9afbc5b07f9a9`.
The private-ci counterpart repair passed its 19 scoped execution-core tests,
including that golden fixture. Those results do not establish that this combined
runtime binary passes its own tests. A23/A24 experimental schedulers are not
inputs to this composition.

The combined source retains both controller lock protocols, mandatory stable
idempotency keys, strict no-follow/owner/link-count checks, full request bindings,
A20 target supervision and terminal-publication witnesses. Native invocation
does not bypass those operations. Build and qualification reports must identify
the combined commit or uncommitted input manifest and the exact binary hash.

## Trusted native API

The public facade is `hepta_runtime::native`:

- `execute_or_observe(ProcessStartParams)` requires an explicit nonblank stable
  idempotency key and delegates to the existing durable `jobs::start_job`.
- `status(ProcessRefParams)` observes the original host/job identity.
- `read(ProcessReadParams)` preserves independent bounded stdout/stderr cursors.
- `cancel(ProcessCancelParams)` requests cancellation of the original stored job;
  the caller still observes its authoritative terminal status.

Responses are the original backend JSON strings. The facade does not reissue
receipts, allocate a second journal or turn an ambiguous result into a new job.
The embedding host must retain the run, turn, generation, operation key and
canonical payload binding that its existing owner admitted. It supplies
configured host, executable and working-directory choices after its existing
authorization checks. Model-provided tool JSON grants no authority to choose a
host, executable, principal or policy.

This trusted-host facade has not established production Hepta FinalUse admission
or equivalence to Codex's OS sandbox and approval policy. A general agent must
attach the existing authorized effect owner and its output/artifact resolver;
linking this crate alone is not that integration. The qualification workload
below is explicitly prebound to controlled temporary directories and an existing
localhost SSH authority.

Runtime configuration and several registries are process-global. One embedding
process owns one runtime configuration and state root. Multiple cells may share
that owner with explicit caller context; importing the crate does not establish
independent per-cell isolation.

## Recovery and unknown results

The core persists the original job binding before submission. After a controller
crash, a target-owned supervisor can continue while a successor reopens the same
private state and reconciles the same key/job. The successor must not allocate a
replacement key because an acknowledgement, output or terminal publication is
missing. This protocol does not by itself establish exactly-once arbitrary
business effects, recovery after a target reboot or production owner transfer.

The shadow endpoint remains `shadow_only` / `executable: false` with FinalUse
`not_granted`. Its digest supplies no native execution authority. Strict decoding
must reject unknown or duplicate fields, including fields added to the
`not_granted` envelope; a unit enum variant with `deny_unknown_fields` alone did
not provide that guarantee in the observed combined test run.

## Qualification history and resource envelope

The first combined gate completed formatting and all-target/all-feature Clippy,
then exceeded its 1,800-second process limit during the full Cargo test run after
a 13-minute build. A later warm shared-process run, using two test threads under
a two-CPU quota while other isolated Rust builds were active, exposed these
distinct failures:

- The shadow FinalUse unit-variant decoder accepted an extra field. The source
  repair uses a strict map-shaped private decoder while preserving public
  variants and canonical serialization. It also adds unknown-field and
  duplicate-field regressions.
- An inherited A20 publication test appended while an external hard link still
  existed. That conflicts with the adopted strict audit policy. The repaired
  same-inode relink fixture restores a single link before publication; a
  separate test requires rejection and invalidation of the cached publication
  proof while the hard link exists. The production hard-link prohibition stays
  intact.
- Archive metadata queries hit the existing three-second total deadline under
  the shared-process resource contention. The two initially failing archive
  retention tests passed in isolated runs without source or timeout changes.
  The warm run also captured the deadline failure inside an index fixture and
  an intentional-deadline assertion under the same contention.

The audit store lock, bounded index cache and background index workers are shared
across tests within one process, including tests using different temporary
roots. The query deadline covers lock admission and index readiness. A parallel
Cargo harness therefore combines unrelated tests' contention with the
concurrency each individual test intentionally creates. This diagnosis does not
establish a production throughput or tail-latency guarantee, and the failed
runs remain part of the qualification record.

The next correctness gate uses a fresh process per test, one test at a time and
zero retries, after other qualification builds have stopped. It retains each
test's internal concurrency and the bounded-deadline rejection tests. The
production three-second deadline is unchanged. Run it with the integration's
own target directory and an explicitly recorded CPU/memory ceiling; the
intended qualification envelope is two CPUs and 8 GiB, not a load test.

```sh
CARGO_BUILD_JOBS=2 cargo clippy --locked --all-targets --all-features -- -D warnings
cargo nextest run --locked --all-targets --all-features \
  --test-threads 1 --retries 0
```

At this documentation checkpoint, the repaired runtime gate and real native
canary are pending their recorded outcomes. A subsequent report must give its
actual exit status, test count, command, source identity and resource envelope.
The existing source workflows use `cargo test --locked --all-targets` with the
default shared-process parallel harness; they do not run this nextest envelope
or `--all-features`. Those workflow commands remain unchanged. A local nextest
pass must not be reported as an existing hosted CI pass or a concurrent-load
service guarantee.

## Real, isolated integration check

`examples/native_process_driver.rs` is a small caller of the library. It reads an
explicit trusted runtime configuration and one operation request. `start-hold`
prints and flushes the original receipt, then waits so the harness can kill that
exact owned controller without changing the target workload.

`tests/native_library_process_canary.py` uses existing authenticated localhost
SSH and a fresh private test tree. Its bounded real workload records each worker
entry before exclusively creating an execution marker. The harness then:

1. Receives the original job receipt and waits for the workload's marker.
2. Kills its own controller process and reopens the same runtime state.
3. Requires the original job to remain running, the same key to reuse the same
   job without a launch retry, and a changed payload to be refused.
4. Releases the original workload and verifies exact stdout/stderr, an unchanged
   marker, exactly one recorded worker entry and a terminal-publication witness.
5. Starts a separate owned job, cancels that exact stored identity and requires
   the authoritative cancelled state, its publication witness and one entry.

Recording an entry before marker creation detects a duplicate worker that fails
immediately at exclusive creation. The report contains the binary SHA256,
observed source HEAD/merge HEAD, source-input hashes, original identities and
operation responses. The source snapshot is an observation; the separate build
log must establish which source produced the binary.

```sh
cargo build --locked --example native_process_driver
python3 tests/native_library_process_canary.py \
  --driver target/debug/examples/native_process_driver \
  --source-root "$PWD" --ssh-target localhost
```

On failure, the harness preserves its report, requests and original identities
and attempts cleanup only through the original job cancel API. An ambiguous
submission is not retried with a fresh key. This is an opt-in test requiring
existing SSH authority and a Linux user systemd manager; it provisions no keys,
changes no daemon, and uses no production state.

The test covers a controller crash after an acknowledged receipt. It does not
qualify pre-acknowledgement power loss, target reboot, x230's present deployment,
arbitrary business exactly-once semantics, production FinalUse admission or OS
sandbox parity. A general model/effect loop needs its own composition test.

No performance advantage over Codex or MCP is claimed by this boundary. Such a
comparison needs the same model, tasks, context, tools, recovery behavior and
resource budget. Direct Rust calls remove an optional transport boundary while
retaining the original execution policy and persistence work.

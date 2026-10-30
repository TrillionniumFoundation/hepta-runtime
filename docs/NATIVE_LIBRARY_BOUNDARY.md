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
- `observe_request(ProcessStartParams)` resolves the original host/key and full
  request binding when the start acknowledgement and job ID were lost. It returns
  the original record and status without any launch, including pending jobctl
  records. `None` means no binding was found in the current local registry; it
  does not authorize replay or prove that no external effect occurred. Current
  allow_execute=false blocks new execution but does not block this original
  request observation; physical host/state-root and full payload binding remain
  mandatory.
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

The correctness gate runs each test in a fresh process, one test at a time and
with zero retries. It retains every test's internal concurrency and the
bounded-deadline rejection tests. The production three-second deadline is
unchanged. Use the integration's own target directory and record the actual
resource envelope; this is a correctness gate, not a load test.

```sh
CARGO_BUILD_JOBS=2 cargo clippy --locked --all-targets --all-features -- -D warnings
cargo nextest run --locked --all-targets --all-features \
  --test-threads 1 --retries 0 --no-fail-fast
```

The repaired source passed formatting, all-target/all-feature strict Clippy and
the native example build in job `1a16cc27e56-1b6abb-46bd`. The completed nextest
run then qualified source `dd7bf97f4cbe9b77d35c117ef1584e541129f041` with its
tracked checkout unchanged before and after the run:

| Recorded field | Actual value |
| --- | --- |
| Job | `1a16ce06214-1b6abb-4714` |
| Result | Exit 0; 1,177 tests run, 1,177 passed, 21 existing opt-in skips |
| Inventory | 1,198 tests across five binaries; no new test exclusion |
| Runner | Cargo-nextest 0.9.137, commit `75ddba7e911b44c5c0700dac0415d824403de9bd` |
| Start / end, UTC | `2026-10-24T07:46:48.065144Z` / `2026-10-24T08:16:40.149505Z` |
| Test summary / process wall time | 1,790.418 / 1,792.076 seconds |
| Resource envelope | Two-CPU quota, 8 GiB memory ceiling, nice 10; no other owned qualification build at start; host not exclusive |
| Complete 1,188-line log SHA256 | `086ba439c7079203527990811dd31076ebb64ec059561579e218a3fa6ac04c3c` |

The earlier warm shared-process run remains recorded as 1,142 passed, seven
failed and 21 ignored in 2,595.71 seconds. Its two semantic failures were repaired
in this composition; its five metadata-deadline failures motivated the explicit
process-isolation policy. An isolated pass does not erase those failures or
establish a production throughput or tail-latency guarantee.

Both existing source workflows now install the pinned nextest version and use
this process-isolated test command with zero retries. Their exact-HEAD and
prospective-merge identities and other gates are retained. The 90-minute job
budget accommodates the observed roughly 30-minute warm test run, the earlier
13-minute cold build, tool installation and the remaining gates. This budget is
not a measured hosted-run duration. The local result above is not a hosted CI
result; the changed workflows must report their own outcomes. See
[Runtime test strategy](RUNTIME_TEST_STRATEGY.md) for coverage and policy details.

The real native canary also passed against the same source. Its retained
80,592-byte report has SHA256
`4868644068756417162a40e4e3e316dbcecf3561ea4d93568c15bd2a75889d33`; the binary
SHA256 is
`c792efcaa3a712acbaeb61e20d99fdf408e5df5c7cad15374cd5a700fb40717a`, and the
355-file source-input manifest is
`f62d93ca41f509604e4f3ba1557bdd945dcf545fffdcb6843aacdbf7c76b9fbc`.

The report confirms controller exit -9, the original running job, same-key reuse
without launch retry, changed-payload refusal, exact output and a publication
witness, with one recorded worker entry. A separate owned job also recorded one
entry. Its cancellation request returned `stop_requested` with
`termination_confirmed: false`; the later authoritative status was `cancelled`,
exit -15, with a terminal-publication witness. Request acknowledgement and
terminal proof remain distinct. These are the bounded checks described below,
not a target-reboot or pre-acknowledgement power-loss experiment.

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

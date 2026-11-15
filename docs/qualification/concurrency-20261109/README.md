# Runtime concurrency audit — 2026-11-09

Implementation: [`826c462699a27ed6afa83298440acb732b726af5`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/826c462699a27ed6afa83298440acb732b726af5),
based on `4cd85c99c5f5a480832c48fbde8561bb365f67a9`.
The machine-readable [evidence record](evidence.json) contains the observed
commands, counts, source and artifact fingerprints, and explicit pending work.
It omits credentials, private profiles, private filesystem paths and raw large
logs. The original receipts and logs remain separate evidence.

**Status at this record:** the final ROG Rust gates, REA Python tests, patched
tunnel build, Mac Unix HTTP/doctor fixtures, Mac runtime R2 acceptance and
five-host systemd audit are complete. Deployment staging passed.
**The activation job was launched; its completion or rollback is unconfirmed.**
Hosted CI was last observed `in_progress`, with no passing result attested.
This is a scoped audit and verification record, not a declaration that every
deployment, hosted CI job or historical qualification has passed.

## Why the old limits survived

The direct SSH limits were introduced by
[`b20bcf02cfe72b3873c5c03180e4028ea673067f`](https://github.com/TrillionniumFoundation/hepta-runtime/commit/b20bcf02cfe72b3873c5c03180e4028ea673067f),
“perf(runtime): bound direct native SSH and retain original cleanup custody
(A53).” Its recorded scope was an exact X230-qualified 175-file source identity;
performance, full-six-host and CI qualification remained separate pending work.
This establishes the small-host qualification context. It does not establish an
unstated motive for choosing those limits or qualify this new implementation.

Those gates lived below MCP request dispatch. The baseline direct SSH actor had
2 connections per host, 8 global connections, 16 admitted requests and a bounded
queue. The observation actor separately had 8 masters, 8 sessions, 2 sessions
per host, 8 queue entries and 16 admitted requests. Its profile loader and
post-validation workers had additional limits. Raising or removing an outer
request limit did not change these independent transport gates. The baseline
direct admission path could therefore emit `direct SSH admitted capacity
exhausted` before submitting a child.

The old implementation also used permits to retain child and cleanup ownership.
The change removes count-based admission while retaining explicit activity and
original-child custody through cancellation, timeout, wait and reap. Same-key
idempotency, same-resource setup locks, generation checks and original-result
ownership remain correctness requirements.

There were two more independently deployed layers: Hepta's systemd job slice
could retain `TasksMax=128`, and an unconfigured stock tunnel client could retain
its default pool of 10. A native runtime policy report could not attest to either
layer. Both are recorded separately below.

## Scope of the implementation

The [concurrency policy](../../CONCURRENCY_POLICY.md) is the complete map of
removed application gates and retained correctness/data boundaries. It covers
SSH, process operations and exact-key locks, owner acquisition, inventories,
metadata/archive/audit work, retained-result reads, search, PTYs, document/REA
workers, evidence encoding, weight sessions, Python ingress, the job slice and
the packaged tunnel client. No arbitrary larger slot count substitutes for the
removed execution limits. Physical resources and external services still bound
actual throughput.

Unbounded Hepta tunnel profiles use HTTP. The seven-tool read-only template uses
the existing private Unix HTTP bridge, with its original allowlist and local
backend-token injection. The generic upstream stdio wrapper retains its
single-lifecycle response-identity lock and late-response tombstones; setting
the pool to zero does not make that compatibility wrapper concurrent.

The implementation also repairs idle re-initialize ordering in the Python
facade and makes the full tunnel CLI's `doctor` use the configured Unix socket.
The [deployment guide](../../../deploy/README.md) and
[read-only tunnel guide](../../CHATGPT_SECURE_TUNNEL.md) document those entry
points without expanding the read-only tool contract.

## Final ROG Rust and Python verification

The final source projection contains 427 files under `src`, with runner-recorded
SHA256 `bad34fdd5ff48e0169a38cb4a8c3cd04d7303467a573467e57b196c033618604`.
It was tested using Rust 1.96.0 and cargo-nextest 0.9.151 on Linux/x86_64,
two build jobs, disabled incremental/debug information and a short task-owned
temporary root. The runner version is the actual local verification version;
this record does not substitute for hosted CI.

| Final check | Result | Recorded time |
| --- | --- | --- |
| `cargo fmt --all --check` | Exit 0 | 1.929 s |
| `cargo check --locked --all-features --all-targets` | Exit 0 | 37.600 s |
| `cargo clippy --locked --all-features --all-targets -- -D warnings` | Exit 0 | 44.325 s |
| Full nextest, all features/all targets | 2,392 run, 2,392 passed, 0 failed, 40 skipped | 144.211 s tests; 558.495 s including build |
| `cargo check --locked --no-default-features --all-targets` | Exit 0, same final source | 36.602 s |
| `cargo clippy --locked --no-default-features --all-targets -- -D warnings` | Exit 0, same final source | 42.408 s |
| Python `rea_*tests.py` | 303 passed, no errors or skips | 7.169 s tests |
| Explicit same-live-owner descriptor/drain check | 1 passed; also included in the 303-test suite | 0.011 s tests |

The full Rust run used process isolation, `--test-threads 1 --retries 0
--no-fail-fast`; concurrency created within each test remained enabled. The
final nextest log SHA256 is
`c07c43a9b428feb965b78abc02dd147befb16fd9f34a82cc3b2507ddb0cfec73`.
The Python REA log SHA256 is
`73e61fb4953db07c6c319f1ed61dc551d13c5431dce59046960c7c9aa28c36da`.

The first full Rust run remains a failed run: 2,386 passed, 6 failed and 40
skipped. Four failures came from a qualification temporary path that exceeded
the existing OpenSSH socket publication bound. All four passed with a short
temporary root; production path validation was retained. One fixture still
waited for a removed shared-reader cap, and one expected obsolete concurrency
remediation text in an exact error projection. Those current assertions were
updated, then the full suite passed on the final source. The original failed
log, its source identity and the supplemental observations are retained in the
evidence record. Historical golden receipts were not rewritten as new passes.

## Patched tunnel and Mac fixtures

| Identity | Value |
| --- | --- |
| Upstream | tunnel-client v0.0.19, commit `01d67bb4da0d8359b808b4761f8db171ab682cd7` |
| Patch SHA256 | `d2a8e8ec047de59b3ac8c2619e6d62b3f0c8b6b62fe09daa89d2ff23378ac6c8` |
| Build | Go 1.27.3, full CLI, darwin/arm64 |
| Binary SHA256 | `754bfa627d6fb2f779daa42e91782af85ce1b01a3bfbae99065ac82326e3f7e1` |
| Binary bytes | 24,612,146 |

The [source manifest](../../../deploy/tunnel-client-source.json) and
[builder](../../../deploy/build_tunnel_client.py) bind source, patch and
toolchain. Explicit `mcp.max_concurrent_requests: 0` selects the ants unbounded
pool. Positive values preserve upstream behavior; negative values remain
invalid; the omitted-value default remains 10.

The final patch was checked against the tested source before running both
`pkg/runtimeconfig` and `pkg/dispatcher/internal` normally and under Go's race
detector; both package sets passed. The selected existing doctor tests passed.
The local sandbox denies Unix socket creation, so two Unix doctor tests are
explicitly excluded from that local selection. This is not a claim that the
entire `cmd/client` Go suite ran.

On Mac, the final binary and both packaged bridge copies were then checked
using isolated fixtures. All four Unix HTTP bridge tests passed in 2.227 s.
Each copy admitted 32 original reads before releasing the fixture barrier,
preserved response IDs/session/token handling, and rejected a mutating tool.
The final CLI's Unix doctor fixture returned `result: ok` with reachability,
metadata absence and the temporary health listener all passing. It used no real
account key and started no tunnel poller. The acceptance owner completed with
exit 0, durable/complete output and confirmed terminal publication.

These tunnel fixture results are separate from the native runtime R2 cohorts
below. Neither candidate test establishes that the running services have
switched binaries.

## Mac runtime R2 and native cohorts

The R2 native build exited 0 in 179.237 s using
`1.98.0-aarch64-apple-darwin`. Its source was the clean committed implementation
checkout, tree `fc34c18deeed0964c9bedb557a8385d72013273d`, and the build reported
`source_inputs_unchanged: true`. The resulting runtime is 16,837,440 bytes,
SHA256 `8969ebef564d162fdeb539be3b59fce9c511550f44eb4282655c3fc06d85f989`.

| Native cohort | Checks | Original requests | Peak outstanding RPCs | Observed simultaneous same-target SSH children | New-key retries |
| --- | --- | --- | --- | --- | --- |
| Mac | 75 passed, complete, no failures | 32 | 32 | 32 | 0 |
| ROG | 75 passed, complete, no failures | 32 | 32 | 32 | 0 |

Both cohorts were bound to that R2 runtime digest. Their original report
fingerprints are:

- Mac: `b10458dddcf86483d928e0cbe29484a0ebf3144354ff62526783cacd1c7550d6`.
- ROG: `f809ab5c7ef87a4f950e3e7f45288dd62ba1b66707f1342b70d008fbf7e7ba02`.

**Observation provenance:** the build and reports were observed through the
configured connector. The original build script computed these SHA256 values
from the completed Mac report files, and they were read from original build
job `1a1c0728c01-5e21-a65` stdout. The reports were independently reviewed before
the connection was lost; their raw files were not copied to this cloud checkout.
The derived observation journal is explicitly identified in `evidence.json`.
No unknown hash of `native-build-r2.json` is supplied, and this observation
journal is not presented as an original activation receipt.

## Five-host systemd audit

The audit read both system and user manager properties for
`hepta-runtime-jobs.slice` on five configured Linux hosts. All five user-manager
observations already reported `TasksMax=infinity`.

| Host | System slice before | System slice after | Action |
| --- | --- | --- | --- |
| rog | 128 | infinity | Persistent property change, verified |
| pocket4 | 128 | infinity | Persistent property change, verified |
| x230 | 128 | infinity | Persistent property change, verified |
| desktop | infinity | infinity | Read-only observation |
| ai395 | infinity | infinity | Read-only observation |

All three repair owners exited successfully with durable output and confirmed
terminal publication. Existing CPU/memory properties were preserved. The
active x230 cgroup also reported `pids.max=max`; the two other repaired slices
were inactive and had no active cgroup to inspect. These observations concern
the Hepta aggregate slice, not unlimited capacity of the whole operating system
or another administrator's service.

The retained private audit/repair record has SHA256
`e9d93f31750eed53e1c7e8d4226e31596d7b9062de7930c03b57c7fd0b744838`.
Only the necessary host aliases, values and outcome fields are projected here.

## Deployment staging, unconfirmed activation and claim boundaries

The stage job `1a1c07c1c58-5e21-a91` completed successfully with exit 0,
complete/durable output and confirmed terminal publication. The exact recovered
deployment-plan bytes have SHA256
`2f91972315995f8c66cd041c1875455825a5bd59eff9fac46fb191bfd14d7944`, matching
the original stage output. The plan binds implementation `826c462`, the R2
runtime digest above and tunnel digest `754bfa62…26e3f7e1`, for two HTTP tunnels.
Private profiles, credentials and their contents are omitted from this record.

The activation request created original job `1a1c07dac49-5e21-a9a` and returned
`launch_state: launched`. Its audit state is **`launched_unconfirmed`**.
Subsequent Hepta API reads returned `MCP Internal error`, including from a fresh
independent context; no alternative Mac channel established the result. The
operation has not been replayed. Neither completion nor rollback is asserted.

`remaining.live_activation` in [evidence.json](evidence.json) therefore has no
observed deployed runtime digest or verified tunnel-health results. Update it
only from the original activation outcome and actual readback, or from a
confirmed rollback. Build success, staging success and candidate tests cannot
stand in for that observation.

Hosted CI was last observed `in_progress`. No passing hosted-CI receipt is
attested by this record; the local gates above remain separate evidence.

For each activated tunnel, required future readback includes `live: true`,
`ready: true`, `runtime.lifecycle: running`, dispatcher `accepting: true` and
`pool_limit: 0`, plus successful control-plane polling. Queue buffer capacity
is separate from the active worker pool. The native runtime must report
`limits.concurrent_execution: unbounded_by_runtime`.

Earlier REA, Desktop Commander, provider and historical qualification records
retain their original scope and results. Removing concurrency gates does not
upgrade them to qualified, establish external-engine parity, assert infinite
physical resources, or certify an unobserved production deployment.

# Concurrent execution

Hepta Runtime admits independent work without a fixed execution-count ceiling.
The policy is reported by `effective_config` as
`limits.concurrent_execution: "unbounded_by_runtime"`. An arbitrary number is
not substituted for the old slot counts. Activity counters observe original
work for shutdown and cleanup; they do not grant or deny execution permits.

## Removed application gates

| Execution path | Former gate | Current behavior |
| --- | --- | --- |
| Direct SSH | 2 per host, 8 global connections, 16 admitted requests, bounded command queue | Each original command retains its child owner without a count-based admission gate. |
| SSH observation pool | 8 masters, 8 sessions, 2 per host, 8 queued, 16 admitted; 8 configured profiles | Profiles, master owners and requests have no fixed count ceiling. |
| SSH post-validation | 2 workers | Each original validation is tracked until it exits. |
| Durable process operations | Start I/O 4; outcome, cancellation and observations 8; registry 4 | Independent operations run without shared capacity permits. |
| Process idempotency | 64 hashed lock lanes | Only the exact host and operation key share an operation lock. |
| Effect-owner acquisition | 4 blocking acquisition workers | Independent acquisitions have no fixed worker gate; actual file ownership remains enforced. |
| Job inventory | 2 workers; 4 cached snapshots could refuse active work | Independent workers are admitted; the snapshot count is an idle-cache eviction target. |
| Metadata and archive queries | 8 workers, 8 collecting groups, 2 active indexes, 2 shared store readers | Independent queries and active indexes are admitted; batches remain finite streaming units. |
| Audit persistence | 128 queued submissions; 4 file-sync workers and a 32-slot queue | Submissions retain order; each original file sync is joined without a shared worker cap. |
| Configured-host read-only inventory | 2 host workers and 16 configured hosts | Every configured host starts its own original observation worker. All started owners are joined, including when another host or result write fails. |
| Retained-result reads | 4 workers and 256 hashed record locks | Independent reads run concurrently; mutations lock only the exact result identity. |
| Search | 8 active globally, 4 per owner and 1024 total retained receipts, including the target Python worker | Original searches retain their receipts without an active or retained-receipt count gate. |
| PTYs | 128 active sessions | Active sessions have no fixed count ceiling; only closed cache entries are pruned. |
| Document and REA workers | Fixed parser/import/view gates, typically 2; APK serialization and an 8-call queue | Independent workers execute without those admission gates. |
| Evidence encoding | One encoder at a time | Each original encoder retains ownership; encoded-byte accounting remains accurate across concurrent encoders. |
| Resident weight workers | Profile active-session count, default 1 and validation maximum 8; 1024 retained session intents | Independent sessions are admitted without an active or retained-intent count gate. Original intents remain retained; a legacy serialized field is used only for existing profile identity compatibility. |
| Python operator ingress | 16 active requests, 2 cancellation workers, bounded queues, serialized independent stdio calls and 4096 legacy pending/retired request IDs | Each original request and cancellation retains an independent worker. Legacy IDs and retired-request tombstones remain complete without a count gate; session transitions still preserve their required ordering. |
| Hepta systemd job slice | 128 aggregate processes/threads | The aggregate slice uses `TasksMax=infinity`. |
| Isolated systemd job | 64 processes/threads, including its supervisor | Each new job unit uses `TasksMax=infinity`; its configured CPU, memory and timeout properties remain enforced. |
| Isolated job registry | New jobs refused at 128 retained directories, including active jobs | Preparing a new job does not count or remove other jobs' records. Exact job IDs still bind the original request and receipts. |
| Packaged tunnel-client | Template count 4; stock omitted-config default 10 | The pinned v0.0.19 patch makes an explicit configured zero select the underlying pool's unbounded mode. |

The removed SSH defaults originated in small-host qualification work. They
were nested below request dispatch, so removing an outer request limit did not
remove the native SSH refusal. SSH output, child reaping and credentials retain
their original owners throughout cancellation and timeout.

## Correctness boundaries

Concurrent execution does not change these contracts:

- Repeating an idempotency key reconciles the original operation. A lost
  acknowledgement never creates an automatic retry or a second effect.
- The same session, result identity, file transaction or immutable publication
  still uses its required ownership lock. Unrelated operation keys do not
  share a hashed execution lane.
- Cancelled callers do not release children, file references, immutable
  encoders or store transactions before the original work reaches its cleanup
  boundary. Shutdown drains observed activity; it does not infer completion
  from permit availability.
- Payload, response, archive and timeout bounds remain separate contracts.
  Retained-history limits must not become admission gates by counting active
  jobs or ownership records. Retained model snapshots and durable no-replay
  keys are stored objects, not active execution slots. Existing receipts are
  not deleted to admit more work.
- Per-request streaming batches and internal sort/scan fan-out are algorithmic
  working sets. Their sizes do not limit how many independent requests execute.
- CPU, memory, file descriptors, executor threads, remote provider capacity and
  operating-system resource limits determine actual throughput. Resource
  exhaustion is reported as the original error, without replaying work.

## Entry points and transport

The Python operator facade must preserve individual request and cancellation
owners without a fixed global active-request or cancellation-worker count. Its
stdio transport dispatches independent requests concurrently and retains the
original request-to-response mapping during drain.

The packaged tunnel-client is pinned to the same v0.0.19 source revision as
the reviewed installed client. The [source manifest](../deploy/tunnel-client-source.json)
pins its commit, Go toolchain and patch digest. The
[build entry point](../deploy/build_tunnel_client.py) applies the patch to a
pristine checkout and writes a binary receipt. `mcp.max_concurrent_requests: 0`
selects the pool's existing unbounded mode. Positive counts retain upstream
compatibility and negative configuration values remain invalid. The Hepta
templates explicitly select zero; the upstream omitted-config default of ten
is not silently changed.

Unbounded Hepta tunnel profiles use HTTP. The system provisioning path retains
the native loopback HTTP endpoint and its `X-Hepta-Runtime-Token` headers for
both discovery and requests. The seven-tool read-only profile uses the existing
private Unix HTTP bridge, with an account-owned socket and local backend-token
injection. Its catalog and authority stay limited to the same seven tools.

The upstream generic stdio forwarding wrapper retains one active request
lifecycle per child so that late responses cannot be delivered to the wrong
request. Its lock and retired-request tombstones are correctness boundaries.
That compatibility transport remains finite even when the dispatcher setting
is zero, and must not be used for an unbounded Hepta profile. The Python facade's
own concurrent stdio implementation does not remove a wrapper imposed by an
external client. The patched full CLI also makes `doctor` honor the configured
Unix socket, matching the HTTP transport used by the daemon.

An external tunnel client's own MCP dispatcher is a distinct execution layer.
An existing installation needs both the patched binary and explicit zero in
its own HTTP configuration. The runtime's configuration report describes the native
runtime policy; it does not attest to an upstream proxy, SSH daemon or hosted
service. Authentication and transport cancellation remain unchanged.

## Verification

The [initial concurrency verification](qualification/concurrency-20261109/README.md)
binds implementation commit `826c462699a27ed6afa83298440acb732b726af5` and its
recorded binaries. A subsequent review found the isolated-job 64-task and
128-record gates, the search and weight 1024-record gates, and the Python
facade's 4096-ID gate still present in that source. Those omissions are removed
in the later changes described above. The earlier Rust suite and Mac/ROG
native probes do not verify these later changes. The
[r4 source checkpoint](qualification/rea-concurrency-source-projection-20261109-r4/README.md)
refreshes only the current REA source mapping; it does not attest to a new
runtime build, deployment, throughput result or external-tool qualification.

Regression tests cross the former limits with simultaneous original work,
including same-host SSH children, observation actor queues, exact-key job and
result locks, metadata reads, collecting groups, indexes, file syncs, active
searches, PTYs, weight sessions and evidence encoders. They also retain the
cancel, timeout, partial-spawn, panic, original-result and cleanup assertions.
The isolated-job registry fixture admits another job with 129 existing records
and verifies that the original record, spec and terminal-receipt bytes and
file identities remain unchanged. The systemd command fixture covers both
captured and PTY execution, network policies and configured resource values;
it verifies `TasksMax=infinity` alongside the unchanged isolation properties.

Run the Rust suite with the process-isolated commands in
[Runtime test strategy](RUNTIME_TEST_STRATEGY.md). Isolation prevents unrelated
tests from sharing process-global state; each concurrency regression still
starts its simultaneous work inside its own process. A source or mock test is
not a production throughput claim. Native deployment acceptance must use the
actual release binary and preserve the original request identities.

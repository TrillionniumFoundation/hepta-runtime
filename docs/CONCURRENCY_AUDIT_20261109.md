# Concurrent execution audit — 2026-11-09

## Scope and result

Reviewed native runtime revision `826c462699a27ed6afa83298440acb732b726af5`
and the pinned tunnel patch against the execution paths listed in
[Concurrent execution](CONCURRENCY_POLICY.md). Independent requests no longer
acquire fixed global/per-host execution-count permits. This is removal of
application admission ceilings, not a claim of infinite hardware throughput.

The review covered direct SSH and observation owners, queues and validation;
durable start/outcome/cancel/inventory I/O; exact-key idempotency and result
locks; audit persistence and archive queries; search and PTYs; document/REA
workers and evidence encoding; resident weight sessions; Python HTTP/stdio
ingress; and the packaged tunnel dispatcher's native unlimited mode.

Residual count-like constants were traced to retained immutable snapshots,
durable no-replay indexes, per-request streaming/sort working sets, bounded
diagnostic history or individual job resource contracts. Required identity and
publication locks remain. None of those was replaced with a large pretend
"unlimited" worker count. The generic upstream stdio wrapper is still a serial
compatibility transport: the active unbounded tunnel profiles use HTTP.

## Bound verification

- Every Rust source file plus `Cargo.toml` and `Cargo.lock` matched the existing
  final validation inputs byte-for-byte. Full-feature format, all-target check,
  Clippy with warnings denied and process-isolated nextest receipts passed:
  **2,392 tests passed, 40 existing opt-in tests skipped**. The recorded Linux
  validator used Rust 1.96.0 and nextest 0.9.151; this is not a claim to have
  rerun the CI-pinned toolchain. No-default-feature check and Clippy also passed.
- Native Apple Silicon release build used Rust 1.98.0. The actual runtime
  executable SHA-256 is
  `8969ebef564d162fdeb539be3b59fce9c511550f44eb4282655c3fc06d85f989`.
- That executable passed native qualification against both a local macOS
  target and a Linux SSH target: 32 simultaneous original payloads and matching
  observations, exact original owner/receipt identities, and identical-key
  reuse without a second physical launch. Both reports passed all 75 checks.
- Additional entrance/collector tests passed: tunnel packaging/configuration
  (7), read-only HTTP/stdio bridge (27), inventory (19), search (15 passed plus
  one existing platform skip), and operator/cancellation/custody regressions
  (206). Contract fixtures were made non-group-writable as their trust checks
  require; no contract content was changed.
- Five new HTTP probe regressions cover persistent SSE without EOF, empty
  events, multiline events, unrelated response IDs, JSON replies,
  notification acknowledgments and missing original results. The corrected
  probe also passed against an isolated native HTTP controller, which exited
  cleanly after its session was deleted.

## Mac activation

The controller was switched to the exact native release above. The runtime
reported `limits.concurrent_execution: "unbounded_by_runtime"`. Both active
HTTP tunnel profiles were switched to the pinned full-CLI build with explicit
`mcp.max_concurrent_requests: 0`; both reported a ready, accepting dispatcher,
`pool_limit: 0`, and healthy control-plane polling. The patched tunnel binary
SHA-256 is
`754bfa627d6fb2f779daa42e91782af85ce1b01a3bfbae99065ac82326e3f7e1`.
Mapped executable paths, not merely release symlinks, were checked.

The old controller was running without its HTTP listener and did not complete
its graceful stop. A scoped launchd controller replacement recovered it;
durable payloads/process groups were not signalled. An initial tunnel reload
hit launchd's asynchronous removal/registration race and triggered rollback.
The registration was reconciled, and the subsequent activation completed with
both tunnels verified. Preserve the individual attempt receipts: the failed
attempt is not rewritten as a success.

All **49,790** pre-switch controller job records and **10,028** worker request
records remained present with identical hashes afterward. Runtime policy
configuration and authentication material were unchanged. No original job was
resubmitted, removed or reconstructed for the release switch.

The deployment probe correction is included in this audit follow-up; the
native executable remains built from the explicitly named runtime revision.
No native source change or unverified binary substitution is hidden by the
follow-up commit. Raw deployment/configuration/task evidence remains private.

## Remaining boundaries

OS CPU, memory, process/thread and file-descriptor limits, SSH daemon limits,
and hosted-provider capacity still constrain actual throughput. Payload sizes,
deadlines, retained-history quotas, same-identity ownership and cancellation
cleanup are intentionally not removed. This audit does not certify unlimited
capacity in an external hosted service or an unrelated client installation.

# Operator V10 — Mac detached resource admission repair (2026-10-14)

The original installed V4 Mac task 1a13a804bcc-b2f-1650 has not been
relabeled or replayed. Read-only examination bound its original
launch_failed record to the target request.json and found no
launch.json, started.json, exit.json, stdout or stderr archives.
Its remote helper failed before starting a runner with the explicit cause:
detached backend cannot enforce requested CPU/memory limits.

Prior user-facing process_status summarized the same historical record
as lost, which is too vague to explain the prelaunch rejection. This
candidate does not rewrite that historical outcome, automatically
retry it, or interpret the missing exit record as a successful run.

## Exact correction

On a newly requested process, first perform existing argument and
idempotency-key reconciliation, then check the selected configured host
backend before computing a new job ID or persisting a launch intent.
For macOS, where this job implementation uses the detached backend,
reject any positive CPUQuota or MemoryMax request instead of sending it
to a helper that must fail after persisting a remote request.

Other host platforms, macOS tasks without these resource limits, nice,
timeout, idempotency-key reuse and existing old-job reads are unchanged.
No resource bound is silently discarded. No new MCP tool or catalog
definition is added.

## Acceptance

* A Rust unit case covers CPU-only, memory-only and combined resource
  limits on macOS, and verifies Linux remains unaffected.
* A separate native 66-tool HTTP controller with private state, a closed
  fake macOS host and a strictly rejecting SSH sentinel checks all three
  resource-request classes. It refuses the tool call without creating a
  durable controller job, remote directory or SSH invocation.
* Run cargo fmt, strict clippy, full Rust suite, private native test
  and exact-head hosted CI against the source commit.

This is a root-cause source repair and a no-side-effect negative
regression, not a production release, Mac live resource-limited execution
capability, account caller isolation, or Desktop Commander cutover.
Installed V4, DC, tunnel and independent 8791 candidate remain untouched.

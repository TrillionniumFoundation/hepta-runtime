# R22 capacity shadow: execution-safe slice (2026-10-16)

**Scope:** read-only planning; no process launch, controller/tunnel restart, registry mutation, credential access, automatic retry, or DC shutdown.

## Observed source and deployment boundaries

- R22 release: 49/49 manifest-file SHA256 checks passed. Native binary SHA256: `6d4d182b2fa50cc79f921f1a8fb3b7da0dc1456d8d5feddf14d031fb044a079f`.
- Manifest has no source commit. Complete file integrity is **not** reproducible source provenance.
- Six configured hosts passed real authenticated SSH health probes. This is reachability, not load balancing.
- Production Operator, V11 canary, successor canary, HTTP facade, tunnel and bridge observed active. No service altered.
- Retained job metadata exceeded 22,000 records. `process_list_page` works; legacy mixed `process_list` can refuse registry reconciliation.
- Development head `9a3b3c7e`: global `START_LOCK`; idempotency lookup fully scans and sorts all job JSON records. Current R22 executable needs exact source alignment before edits.
- HTTP facade has dynamically created workers, no fixed request cap; OS resource and scheduler budgets remain necessary.

## Prototype API and hard boundaries

`deploy/runtime_capacity.py::plan(hosts, tasks, now_ms, configured_hosts, inventory_complete)` returns a **deterministic shadow plan**, with SHA256 receipt, admitted IDs and defer reasons.

- Requires a complete authorized host alias list and explicit per-task host allowlist; no task is silently migrated.
- Requires fresh (<=30 s) trusted per-host free CPU millicores, available RAM MiB, slots and temperature; GPU workloads additionally need free GPU memory and GPU utilization.
- Rejects unknown fields, duplicated IDs, capacity overcommit, busy GPU (>=95%), hot host, stale telemetry, unconfigured hosts and incomplete inventories.
- Honors existing slot reservations, allowed/excluded hosts, data locality and bounded queue aging.
- GPU GTT/UMA totals are **not** equivalent to real allocatable GPU memory; missing metrics must remain unknown, not fabricated.
- `hardware_snapshot` on its own does not report all required scheduling inputs. Independent active-job reconciliation and host resource collectors remain needed.
- The planner cannot submit jobs, preempt workloads, reserve real resources, reconcile uncertain effects, or transfer V4/V11 execution ownership.

## Qualification and acceptance

`python3 -m unittest discover -s tests -p runtime_capacity_tests.py -v`: **29/29 PASS** (normal and Python -O) in a separate Git branch.

Tests include hot/busy/stale nodes, missing GPU telemetry, host pinning, duplicate keys, strict schemas, reservation exhaustion, priority aging and 2,048 synthetic tasks.

**Synthetic planning time is not Runtime QPS, launch TPS, p95 latency, H3 render throughput, or 500-way concurrency proof.**

Before effectful deployment: (1) publish R22 exact source/build commit; (2) measure live capacity and workload reservations; (3) preserve one authoritative effect owner and cross-registry idempotency; (4) execute isolated 1/4/8/16/32 request-level concurrency with p50/p95/p99, queue depth, latency and output-integrity evidence; (5) prove V4/V11 restart, rollback and fail-closed transfer.

Keep the existing production services and original Desktop Commander untouched until those actual gates are met.

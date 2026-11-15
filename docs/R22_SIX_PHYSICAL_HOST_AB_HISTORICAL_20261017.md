# Historical R22 six-physical-host A/B evidence (2026-10-16)

**Historical isolated result only — not current PR #15 HEAD or live production deployment.** Original result files remain private on the original operator host.

## Experiment contract

- Script now versioned at `tests/r22_isolated_real_six_host_ssh_benchmark.py`, with helper `tests/r22_isolated_six_alias_ssh_benchmark.py`.
- Six actual configured SSH hosts: main, pocket4, rog, mac, x230, ai395. `/usr/bin/true` only; six new durable identities, confirmed exit=0/output complete and original no-relaunch idempotent reuse.
- Both controllers used dedicated temporary loopback MCP servers, private test tokens and disposable controller/remote job-state roots. A fixed 3,000 synthetic records were added after original job completion; final record count was 3,006.
- All four physical-host receipts state `remote_cleanup_complete=true` and `production_routing_changed=false`; actual long-running production V4/V11 services and Desktop Commander were not switched.
- Binary hashes: baseline `7daff12a714f241c1a104f421e28246e89ea010642e5b06f8768f8676ef27d83`; previous perf candidate `993d3ba4fd7bfe38b3156ea40bf5c902b7494cdaa3f58d3bcb9d238fbf0b4602`.

| Original six-host scenario | Baseline batch ms | Candidate batch ms | Ratio baseline/candidate |
|---|---:|---:|---:|
| Forward new `process_start` | 2923.86 | 793.33 | 3.69x |
| Reverse-order new `process_start` | 2797.09 | 745.64 | 3.75x |
| Forward original-key cold reuse | 2903.59 | 678.54 | 4.28x |
| Reverse original-key cold reuse | 2911.76 | 729.17 | 3.99x |
| Forward original-key hot reuse | 2841.04 | 613.53 | 4.63x |
| Reverse original-key hot reuse | 2916.00 | 612.63 | 4.76x |

## Immutable retained private receipt hashes

- Forward baseline physical JSON SHA256 `0e6b4ea51735a541f1ca8164ba4f0a510bf24d20ec93c4383edd3e77d57c1341`.
- Forward candidate physical JSON SHA256 `e7f196405089840a4c40a32182dbbb79a1f73309dc146669d10502beec37acc1`.
- Reverse baseline physical JSON SHA256 `5981ac67a1d4837cbb489ea80cc9844f864641eb4e0367b5edbb6f8e90c96149`.
- Reverse candidate physical JSON SHA256 `d6b3f6cf91e27608ffb2f5d328cd07ee887f232287c6ca8259bbfaa4ec06b134`.

## Interpretation limits and next acceptance

- These are two historical forward/reverse runs with 3,000 synthetic history rows, not statistically powered p95/p99 experiments, saturated capacity/TPS or proof that 32-way/500-way runners scale.
- The old candidate binary SHA `993d...` is NOT the current Git integration PR #15 binary; it predates the stronger cached-inode verification, streamed exact-key search and two current-source HTTP registry fixes.
- The Git versioning of 42 installed control-plane source artifacts does NOT yet prove which Rust source commit produced the installed R22 executable.
- Reproduce **at new exact source SHA**, with measured 1/4/8/16/32-way throughput, correct host identity, exact original output, V4/V11 owner-fence and rollback before production promotion.

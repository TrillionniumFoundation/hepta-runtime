# R22 exact-Git-source candidate: four paired isolation A/B results

**Source commit built:** `72a455497564fc54e12cd27423b4f02ffbe5374e`.
**Candidate native binary SHA256:** `71b12fb298bcd97b336132f6dbe31d15c153b91b432923b1f1b8507f61a192e2`.
**Prior benchmark baseline binary SHA256:** `7daff12a714f241c1a104f421e28246e89ea010642e5b06f8768f8676ef27d83`.
**No production release/promotion:** Git source versioned; standalone binary built via `cargo build --offline --locked -j 2 --bin hepta-runtime` on Rust 1.95.0. The installed R22 binary is a *different* SHA.

## Paired benchmark on exact candidate binary

| Case | Baseline new ms | Candidate new ms | New speedup | Baseline hot ms | Candidate hot ms | Hot speedup |
|---|---:|---:|---:|---:|---:|---:|
| 6 aliases on one physical localhost, forward | 3445.49 | 866.77 | 3.98x | 3329.60 | 617.73 | 5.39x |
| 6 aliases on one physical localhost, reverse | 3446.42 | 913.59 | 3.77x | 3185.22 | 658.53 | 4.84x |
| 6 distinct physical SSH hosts, forward | 9355.71 | 3036.75 | 3.08x | 2869.40 | 589.92 | 4.86x |
| 6 distinct physical SSH hosts, reverse | 2961.47 | 733.43 | 4.04x | 2841.20 | 702.22 | 4.05x |

- Real physical hosts: main, pocket4, rog, mac, x230, ai395. Experiments only launched `/usr/bin/true` with unique test-only idempotency keys.
- Each paired run had six new durable job IDs, six successful original-state jobs, 3,000 seeded synthetic history records, final durable count exactly 3,006, six exact-key reuses with no additional launch.
- All reports record `isolated_state_retained=false`, `production_routing_changed=false`; physical runs additionally record six disposable remote roots and `remote_cleanup_complete=true`.
- Scripts are versioned as `tests/r22_isolated_six_alias_ssh_benchmark.py` and `tests/r22_isolated_real_six_host_ssh_benchmark.py`.
- See `docs/R22_EXACT_HEAD_AB_EVIDENCE_20261017.json` for all four pairs of exact native hashes, metrics and original private JSON receipt SHA256 values. Original raw receipt files stay on owner host.

## Source/quality gates and interpretation

- The integrated Rust source was verified against its isolated R22 baseline across 166 `.rs`/`.py` files: only jobs source/tests changed, effect-owner fence file hash unchanged. Complete jobs filter 38 pass, 1 manual benchmark ignored.
- The first full Rust suite had 736 pass, one under-contention FIFO `<2s` test failure, 14 ignored. Standalone FIFO test passed in 0.27 s. Lower-concurrency complete suite passed **737/737 Runtime, 14 ignored**, plus **8/8 Jobctl**; original failure remains preserved.
- The Git candidate control-plane LRU cursor and stateless HTTP read-only pager sharing fixes passed 171/171 Python tests after three initially observed failures were repaired.
- Initial six-physical forward new-job times had unusual long SSH startup in both arms (baseline 9.356s, candidate 3.037s); the reverse case was baseline 2.961s vs candidate 0.733s. Two small paired rounds are NOT sustained throughput, queue stress, p95/p99, full production owner handoff, or proof of 32/500-way capacity.
- This exact Git source is NOT proved bit-identical to the running R22 native SHA. Original production operator/tunnel/V11/Desktop Commander were never rerouted to the new candidate.
- **DRAFT / NO PRODUCTION PROMOTION.** Before switching V4/V11 effect authority, qualify source-origin caller identity, live registry/stream reconciliation, late failure recovery, sustained 1/4/8/16/32-way load, host reboot/restart and authoritative rollback.

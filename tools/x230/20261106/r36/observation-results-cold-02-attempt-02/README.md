# R36 scratch candidate: observation attempt 02

The candidate is not yet adopted. R24 remains the accepted baseline pending normal lifecycle ABBA.

## Actual run and retained failure

The held-agent job `1a1b225d6a1-fc05-7ca3` completed the six original workload/auditor stages. The native observation auditor verified 2,664 calls (2,304 measured, 288 warmup, 72 preflight/restart) with zero failures on ai395, mac, main, pocket4, rog and x230. Capacity testing returned 32 successes and 32 classified capacity refusals, with no other errors; drain and cancellation recovery passed.

The original seventh stage failed because the arithmetic summary retained an old topology SHA. The original parent and holder remain failed/exit 1. Their files are preserved verbatim. No workload or original auditor was replayed.

A separate pure calculation, job `1a1b2375107-fc05-7d00`, used the same six original report paths and both original binary hashes. The only source change replaces the stale topology identity with the topology frozen before measurement, `c131f12bd145d53bd2c26d0917411a41e6e85d19a6273fc19d0ef3744d23658e`. Original formulas, thresholds, policy SHA, host set and all other source bytes are unchanged. The inverse replacement reproduces the original summary Git blob `c5f269e19862be1ff212fdb727abbcb51c18727b` exactly.

The new output explicitly has evidence_verified, correctness_verified, performance_gates_passed and observation_gate_passed all true, with no rejection reasons. Its six evidence bindings and thresholds equal the original parent inputs. Exit 0 alone is not treated as a gate result.

## Finite campaign results

| Concurrency | R24 RPC/s | Candidate RPC/s | Change | CPU/call change | p95 change |
|---|---:|---:|---:|---:|---:|
| 1 | 7.575963 | 7.488912 | -1.1490% | -1.3289% | +1.6235% |
| 8 | 52.911690 | 54.007778 | +2.0715% | -0.4043% | -1.3769% |
| 16 | 54.583933 | 55.571572 | +1.8094% | -0.2604% | -4.8044% |

Sampled controller RSS peaks were 18,712 KiB for R24 and 18,900 KiB for the candidate (+188 KiB). Both the +512 KiB and 1.05x ceilings passed. Capacity refusals are not successful throughput.

This is one finite campaign, without a statistical confidence or pooled historical improvement claim. Normal lifecycle all_operations, launch and concurrent_cancel ABBA remains required before adoption. The reconciliation must bind the original failed parent and the separate successful pure calculation; no synthetic passed parent is created.

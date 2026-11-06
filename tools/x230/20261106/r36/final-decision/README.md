# Final decision: retain R24; do not adopt the validation-scratch candidate

The candidate's six-host observation nonregression gates passed, but the required normal lifecycle launch gates failed. R24 (`baab4def80be7af015b2e7a594cb302f66c4130e`, runtime SHA-256 `bc14cab1e632d6cd703f6a0f65d1a8e513b4471c09a403186d72e989e3f74c13`) remains the accepted baseline. This candidate is not promoted.

## Decisive original lifecycle result

The original held-agent job `1a1b246818d-fc05-7d49` completed with exit 1, complete durable stdout/stderr, no automatic retry, and its owned agent reaped. All 14 native harness tests passed (zero failure, error or skip). All four ABBA canaries and their four original auditors returned 0. The independent performance gate returned 1.

| Required lifecycle group | R24 RPC/s | Candidate RPC/s | Throughput change | p95 change | Result |
|---|---:|---:|---:|---:|---|
| all_operations | 6.586322 | 6.856514 | 4.1023% | 9.5110% | pass |
| concurrent_cancel | 4.780460 | 6.552104 | 37.0601% | -40.6024% | pass |
| launch | 5.281644 | 4.975503 | -5.7963% | 12.0109% | reject |

Launch throughput B/A was **0.9420368400540269**, below the frozen **0.95** floor. Launch p95 B/A was **1.1201092953806848**, above the frozen **1.10** ceiling. The other required groups do not override either launch rejection. CPU and RSS gates passed; lifecycle sampled controller RSS was 17,592 KiB for R24 and 17,824 KiB for B (+232 KiB, below the 18,104 KiB effective ceiling).

The finite C6 ABBA has 60 aggregate operation calls per arm, including 12 launch and 12 live-cancel calls per arm. Across four rounds there were 24 new starts, 48 same-key lookups and 48 cancellation calls. These are measured campaign results, not a statistical confidence or causal claim. Optional same-key groups are retained in gates.json and are not substituted for required groups. No measurement was rerun to obtain a passing result.

The original parent preserves `passed=false` and `adoption_passed=false`. Its source, baseline source and all bound inputs remained unchanged. The independent compiler monitor passed and measurement attribution remained valid.

## Candidate work and preceding checks

The candidate skips constructing an unused SHA Context in the reference-comparison branch and lazily reuses one private 16 KiB validation buffer within a synchronous sweep. Full reads, cancellation checks, ownership/identity verification, final fences and error ordering remain. Exact qualified source changes are confined to the profile implementation and two focused tests.

The eight-stage qualification and native six-stage CI both passed: 1,647 tests passed, zero failed, 34 ignored, 1,681 selected and no retry. The qualified runtime SHA-256 is `0d108670136e41599329fdeb675bf11e5dcc4a8366f0bfb79c9a22af2662e0f3`; the final lifecycle used this exact binary.

The full six-host OBS02 completed 2,664 calls with zero failures. C8 throughput was +2.0715%, C16 +1.8094%, C1 -1.1490%; all original observation CPU, p95, throughput and RSS gates passed. Two C32 bursts produced 32 successes, 32 classified capacity refusals and no other error, followed by successful drain/recovery. The first baseline preflight failure remains in its own archive. The original OBS02 parent also remains failed due solely to its stale topology constant; the one-line corrected pure summary and explicit reconciliation are retained separately. No workload or original auditor was replayed for that correction.

## Stopping boundary for this optimization round

The cost and remaining-headroom review is preserved at `../remaining-headroom-review-01/FINDINGS.md`. Previously attempted router, pidfd, path-allocation, lifetime and audit-cache variants are not reclassified or renamed as fresh successes. The D2 diagnostic attribution predates this scratch candidate and is not a current residual profile. It does not establish additional removable CPU while retaining complete reads and current identity/ownership/cancellation semantics.

There is no further untested low-risk patch supported by quantified evidence in this round. This is an evidence-based stopping point under the current contract, not proof of global optimality. The code, failed and passed originals, exact gate policies and full archives remain available for later work that changes the architecture or supplies new profiling evidence.

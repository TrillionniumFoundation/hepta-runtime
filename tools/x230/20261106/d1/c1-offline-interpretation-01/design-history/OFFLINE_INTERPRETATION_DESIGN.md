# D1 C1: source mismatch and a separate offline interpretation

## What is established, and what is pending

The original native workload report is 1,254,435 bytes, SHA256 `58303fa9ccc4f9dcb9c4ca4587761ecfdb2f7789fc68446512d163a264667da9`. Reading its original JSON shows the fixed four ABBA C1 rounds, each with six preflight calls, 24 warmups, 192 measured calls and 12 restart calls. The original adapter report is 14,034 bytes, SHA256 `0f2c2c504e2768b879ab3a2cfa56e21d3b1d28b6f5d7fce4d446e4d3f6abc8e2`; it preserves wrapper return code 0 and controller-close evidence, but `analysis_complete=false`, `traces=[]`, and the original identity-binding error. These report facts do not replace the not-yet-run independent raw native audit.

The actual adapter `run_c1_phase_cost.py` is 34,274 bytes, SHA256 `0902f5a9bf4c085172a61010deb54c74d7b89516fb9cfe1255722ad97b25dea9`. Its `select_trace` function (lines 359–458) requires a public `result._meta["io.hepta.runtime/request-v8"]` identity at lines 394–398.

That requirement conflicts with the frozen runtime's interface. `request_results::eligible` exposes retained identities for three tools, and `exposes_identity` adds four request-management tools; neither includes `process_status` or `process_read`. Formatted `server.rs` line 2509 still binds the actual audit ticket ID into the diagnostic trace. Lines 2550–2553 attach a public response identity only when `exposes_identity` permits it. The unchanged `request_results.rs` is 47,927 bytes, SHA256 `5090ea015457c77f7f37641e3dbdff3185eb9a24881974a60d5f396b8cdbf281`, Git `2b89dcef481fd204988cb10b362c3e28281dd253`, matching the actual D1 222-input map.

This establishes an incorrect static expectation. Confirmation of which subpredicate failed in the actual first frame still requires the original frame. The first expected frame is round-0-A/first, RPC 2, process_read for ai395, sequence 1, offset 641, length 608, SHA256 `5b4219ebcd437771501975ea7f9692e2391e6fd76a6dab1982fc4226bbbdcd4b`. It must be read and hashed without rewriting it. No trace interpretation or workload rerun has been performed for this design.

## First execute the original native auditor in a new namespace

After the complete failure archive is frozen and verified, the original, unchanged `analyze_native_observation.py` can run once against the original report/tree with a new output:

```text
/usr/bin/python3 -B ROOT/c1-tools-01/reference/analyze_native_observation.py
  --report ROOT/c1-observation-01/report.json
  --output ROOT/c1-offline-interpretation-01/native-independent-summary.json
```

This is the first execution of that auditor: the original parent never reached its native-audit stage. Its main function only reads the report and relative evidence, then uses `output.open("x")`; the inspected helpers do not create children or call hosts. Preserve the original four source files and their relative layout: the analyzer imports `audit_native_evidence.py` and `allocator_environment_audit.py`, and the latter hashes sibling `allocator_environment.py`. Record the actual new invocation, terminal result and complete output independently.

The original `c1-observation-01/independent-summary.json` must remain absent. The parent report, failed holder result and adapter error must remain byte-identical. A later independent success is not retroactive success of the original workflow.

The unchanged auditor verifies each canonical request, raw frame/index identity, response and DTO, immutable original job/output, controller generation and cleanup, allocator/topology evidence, raw timing and CPU counters, and resource trace. If it fails, retain that result and stop cost interpretation.

## A strict, different correspondence proof

A new offline interpretation must state that it binds the internal trace ticket identity to a verified RPC by unique scope and timing; it does not recover an identity that was never on the public wire.

1. Retain the actual fixed caller inputs, eight controller PID/start-ticks identities and modes, source/ELF pins, native original identities, full closure and held-agent/quiet/compiler evidence.
2. Parse each original trace with the unchanged raw parser. Require every existing row/slot/footer/clock/TID/nesting/completeness condition. Match the trace PID and birth ticks to the original controller startup, check the eight original boot IDs, and retain the original lifetime boundaries.
3. Establish a candidate association only when the controller, operation and host agree and the **entire trace request interval** lies inside the original RPC interval. The RPC interval must also lie inside its original call interval and its original measured or warmup interval where applicable.
4. Require a bijection in both directions. Every ON first controller must have all 222 original requests used exactly once; every ON restart must have all 12 used exactly once. Across the two ON rounds, this is 468 trace requests, of which 384 are measured. Require unique trace-native IDs and unique slots within their controller namespace. Reject missing, ambiguous, duplicated or excess requests. Do not use nearest-time, ordinal, response-content equality or job-ID-only matching.
5. Require all four OFF traces to contain no request or event rows. Keep their original 468 operation records and original counter-based measurements as native evidence; do not invent OFF phase CPU.
6. Save every match as an explicit derived record containing source file/frame hashes, controller identity, RPC ID and interval, trace slot/native ID and interval, host/operation and category. Set `native_id_publicly_observed=false`; preserve the original failed metadata assertion separately.

All four first-controller transport streams have the same declared raw SHA in the original report, while their indexes, controller identities and clocks differ. Content equality therefore cannot select a controller or a round. The full identity and timing proof is essential.

The adapter did execute its same-boot-before/after comparison before setting `trace_interpretation_started`, but it did not persist the `before_boot` value in its report. A new interpretation must not invent that field or use the current host boot as historical evidence. It can require all eight original trace-header boot IDs to agree, preserve the exact source-backed executed comparison, and cross-check any additional historical boot receipt that actually exists. The evidence basis must be stated.

## Interpretation limits

Only after the unchanged native audit and the new full correspondence proof succeed may a derived report summarize the measured ON requests. Keep preflight, warmup and restart costs separate; use exclusive synchronous thread CPU so audit write/sync are not double-counted; compare whole-controller CPU only over the matching original counter window. Keep the signed unmatched residual instead of assigning it to SSH, remote helper or network work.

This design changes no runtime behavior, workload, original record, acceptance threshold, repeat policy, original auditor or trace parser. It does not claim the failed campaign passed, does not create an optimized candidate, and does not establish a normal lifecycle cancellation benefit. No source implementation or analysis entry point has yet been created or executed here.

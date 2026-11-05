# R27: borrowed observation serialization experiment

**Status: experimental checkpoint; not yet measured, fully qualified, or adopted.**
The accepted optimization remains R24. This independent branch preserves the
next candidate and the frozen test protocol before its first measurement.

## Candidate

The production delta is limited to `src/mcp/runtime/ssh.rs` and a new sibling
`ssh_observation_serialization_tests.rs`. The source basis is accepted R24,
commit `baab4def80be7af015b2e7a594cb302f66c4130e`, carried unchanged through parent
`bfa0d6113d675bb9f597baa474f913c3a12df37a`.

`prepare_observation` previously constructed an owned `serde_json::Value` map
before serializing. A private borrowed `Serialize` enum now writes the same
four job observation payloads directly. Field declarations preserve the locked
JSON map's lexicographic output order. Original-size checks, command construction,
numeric domains, wait clipping, deadlines, system newline, and the final combined
64 KiB byte budget retain their original order and behavior. The direct transport,
cancellation lanes, pool capacities, and `jobs.rs` are unchanged.

Seven sibling tests retain the original function as an independent byte/error
oracle, including escaping, Unicode, maximum unsigned values, defaults, and exact
payload boundaries. The patch was independently reviewed and applied to isolated
R24 and R26 source copies. Those checks are not Rust compilation or qualification.
This branch uses the R24 application; it does not inherit the rejected R25 reserve.

## Fixed component experiment

The [component source](component/bench.rs) embeds the actual old and new function
bodies with source and fragment hashes. It uses identical small command stubs,
so it measures preparation mechanisms rather than full RPC transport. The
[generator](component/generate.py) and [runner](component/run_component.py)
preserve that scope. The [planned original native request](component/planned-native-request.json)
has not been dispatched at this checkpoint.

The ordinary allocator binary records two fixed ABBA rounds for six cases,
48 timing samples in total. A separate counting binary records allocations and
reallocations without making timing claims. Byte-equivalence checks cover every
case. No sample selection or automatic workload retry is permitted. Absolute
ordinary status/read CPU savings must be considered alongside the complete
controller cost; a component speedup cannot establish end-to-end adoption.

## Full qualification and acceptance

The [preregistered protocol](PREREGISTRATION.md) and its
[machine-readable counterpart](preregistration.json) freeze the original R24
criteria before R27 sampling. Full Rust qualification still has to run on X230:
format, format check, harness tests, Clippy, all-feature test build, isolated
tests, independent audit, and release build. Expected test inventory is 1,652
passes plus 34 ignored cases, with zero failures or retries; these are expected
counts, not results.

Full six-host acceptance retains C1/C8/C16 ABBA, the original C32 boundary test,
and the original six-host cancellation/crash/recovery canary. Every concurrency
requires throughput B/A >= 0.95 and p95 B/A <= 1.10. At C8, throughput must be
>= 1.03 and controller PID CPU/call <= 0.97. Sampled controller RSS must satisfy
both B <= A + 512 KiB and B <= A * 1.05. Child costs remain separately reported.
All source, binaries, original jobs, raw results, and terminal states must be
bound to their actual identities before any adoption claim.

This checkpoint contains no R27 performance result or passed CI claim. Actual
results and the decision will be committed after the coordinated experiment.

# D1: bounded phase-cost diagnostics from accepted R24

**Status: source prepared and independently reviewed; Rust qualification and measurements have not run. This is a diagnostic experiment, not an adopted optimization. Accepted R24 remains unchanged.**

The source baseline is accepted R24 commit `baab4def80be7af015b2e7a594cb302f66c4130e`. The Git parent `86155fbf3b89e5a77e2a4aadebd2128c663fe50b` retains that exact R24 compiler source while adding historical evidence. Its source subtree is `b71cac25e2c2138837f27f3c74f6a2dc5c56b565`. D1 includes none of rejected R35's deferred read JSON or command-ownership changes.

## Why this experiment is needed

The existing six-host observation evidence records controller-process CPU on the order of tens of milliseconds per call, while several reviewed allocation-only ideas are much smaller. D1 records named synchronous controller CPU spans and overlapping wall intervals so a subsequent optimization can target a measured absolute cost. It makes no throughput, memory, capacity, or performance-adoption claim.

The initial experiment is C1 with the original six hosts, balanced status/read workload, 192 measured calls and 24 warmup calls per cell, in a fixed **OFF / ON / ON / OFF** order. Every cell uses the **same exact diagnostic ELF**. Only recording mode and each fresh trace path differ. The original held-agent, quiet interval, native protocol, immutable fixtures, controller resource counters, cleanup and compiler-monitor controls remain required. No C8 extension is scheduled by this source publication.

## Source and scope

| Item | Frozen preparation |
|---|---|
| Original compiler inputs | 220 |
| Candidate compiler inputs | 222 |
| Existing inputs changed | 11 |
| New files | `phase_cost.rs`, `phase_cost_tests.rs` |
| Inputs unchanged from R24 | 209 |
| Pre-format candidate map SHA-256 | `42da71c2097c2c469346b9eed1cbc3a5be4773ee5d3b0a3df87aa72463350723` |
| Patch SHA-256 | `3940b39d5cdde7d4b76ba1e94f49ca461c6964b1edb2c2f44506fdf7c8a50523` |
| Prepared package | 39 files / 971,063 bytes |
| Rust tests added | Six contract tests, written but not yet run |

The only Cargo feature addition is the empty, nondefault `phase-cost-diagnostics` feature. Cargo.lock, dependencies, embedded Python, original remote protocols and all six release-profile settings remain unchanged. The normal feature-absent token paths were checked against R24, and the original module tail is byte-identical. This static check does not replace compilation, borrow checking, formatting or tests.

The Linux diagnostic module requires an explicit runtime mode and fresh private output. It uses bounded preallocated slots, does not perform event file writes on the request path, and flushes after the original transport owners join. Synchronous thread CPU spans contain no await; async intervals record wall time only. Original authority, freshness, admission, deadline, audit, cancel and cleanup decisions remain in place. The independent critical review and the final copyright/module-name addendum are included in the frozen package.

## Qualification and interpretation

The existing 19-file qualifier and eight stages remain unchanged. Its real Clippy, test-build and release commands use `--all-features`, so it will produce and test the diagnostic feature configuration with runtime mode unset. A separately retained ordinary-configuration build uses the original empty package-feature set; dependency defaults and locked versions remain enabled. Actual toolchain, selected tests, source after formatting, retained ELF bytes and native receipts must come from the real invocations, not this preparation.

The trace parser establishes raw structure and synchronous CPU nesting. Native success, process ownership, remote job state, binary identity and complete campaign closure require the independent original records. Wall intervals overlap and cannot be summed as separate costs. Local SSH child CPU, remote helper CPU and network-only latency remain outside the first diagnostic's attribution. OFF/ON will measure recording perturbation; it is not an A/B adoption test between production releases.

## Frozen artifacts

[Recovery-02 source package](source-preparation/recovery-02/) contains the full thirteen changed/added source files, complete maps, patch, tools, source provenance, static verification and independent reviews. [Root publication check](source-preparation/recovery-02/root-publication-static-check.json) independently rechecked all 39 payload hashes and Git blob identities and the 220-to-222 source boundary without running Rust or candidate tools.

The earlier preparation executor interruption is documented as recovery-02; no unacknowledged draft bytes are claimed as recovered. The future x230 root is `/home/qian/hepta-runtime-phase-cost-20261106-d1`. Qualification, ELF and campaign identities remain pending.

[R35's complete original lifecycle rejection](https://github.com/TrillionniumFoundation/hepta-runtime/pull/104) is preserved separately and will not be replaced by this diagnostic.

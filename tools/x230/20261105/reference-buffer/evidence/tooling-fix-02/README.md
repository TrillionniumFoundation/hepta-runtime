# Buffer screen: separate tooling correction attempt02

Attempt01 remains a failed compile with **zero samples**. Native job `1a1aa45954e-fc05-402f` terminated with exit 1; its original 428-byte stderr reports `no rules expected [` at the generated JSON metadata expression. Original source, frozen plan, build binding and all attempt01 records remain unchanged.

This directory prepares a separately labeled correction authorized after that concrete test-tool defect. The generated component and its generator each change only:

```rust
"buffer_bytes": [16384, 65536][index],
// corrected metadata expression
"buffer_bytes": ([16384, 65536][index]),
```

The parentheses are outside the measured operations. Both arm bodies are byte-identical to the originals. The original 16/64 KiB comparison, public SSH/false/shell inputs, 3 ABBA blocks, 256 iterations per cell, 48 timed cells, warmups, gates, qualified rlibs, compiler flags, environment and time limits are unchanged. Source-map and arm-diff bytes also match. The corrected build plan is derived directly from the actual attempt01 binding; the stage driver pins both that original binding and the original frozen plan, and rejects any difference beyond the corrected component identity and isolated paths.

## Installation and execution ownership

All remote paths below are under `/home/qian/hepta-runtime-optimization-20261105-r23/remaining-frontier`.

| Local item | Remote destination |
| --- | --- |
| Four Python helpers | `tooling-fix-02/` with the same filenames |
| `prepared/*` | `tooling-fix-02/prepared/` |
| `build-plan.json` | **`attempt-02/build-plan.json`** |
| New compiler, binary, run and receipt outputs | **`attempt-02/` only** |

Use the existing native process supervisor, with Python arguments `[-B, <remote>/tooling-fix-02/exec_screen_stage.py, compile]` for the single bounded compile. Only an actual successful compile receipt allows the single run after the fixed 30-second quiescence, using the same script with `run`. The corrected receipt writer and finalizer use these new paths. No Cargo invocation, dependency rebuild, workload retry or parameter sweep is added. Root schedules and verifies actual jobs; preparation here performs no remote compilation or measurement.

The driver embeds the actual pre-run machine snapshot in `attempt-02/run-driver.json`. If a separate `machine-before.json` is materialized to match the original record list, it must be derived from that actual recorded snapshot, with its origin stated; it must not be fabricated or sampled retroactively.

Accepted production R24 is commit `baab4def80be7af015b2e7a594cb302f66c4130e`; its verified publication receipt is recorded in the manifest. The component remains bound to qualified R23 profile/validation/guard source and rlibs, with the profile source byte-identical in accepted R24. It does not exercise R24 pool renewal.

## Review and interpretation

- [Exact correction](exact-correction.diff) covers every changed runtime artifact and binding field.
- [Manifest](manifest.json) gives exact sizes, hashes and installation mapping.
- [Static checks](static-checks.json) records one-line equality, preserved original inputs, AST parsing and unchanged measurement logic.
- [Original input identities](original-inputs.json) preserves the original failed attempt and frozen inputs.

This is a correction of our output-macro syntax before any performance sample, not a rerun after performance rejection and not a successful relabeling of attempt01. Actual native terminal status, receipts and raw samples will determine attempt02. Passing Python/static checks does not establish that Rust compiles. Any incomplete bind/compile/run or failing original screen gate ends this separately labeled correction without further parameter search.

Even a successful screen provides only component CPU evidence. It does not establish release RPC or cluster throughput, RSS savings, full-profile behavior, or permission to change the production buffer. The original cancellation/checkpoint, extra stack-buffer and private SHA-fallback limitations remain in the unchanged frozen plan.

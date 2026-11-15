# Weight-space programming: pinned reproduction evidence

This is an isolated research artifact, stacked on runtime PR #88 at
`1f2d3d782e8803e769989234e7902ca5c04eff97`. It does not change the Rust runtime,
registered HeptaTrader plans, model weights, accounting guards, or deployment.

## Executed results

| Scope | Result | Remaining boundary |
| --- | --- | --- |
| Kinetix car edit | PASS: all 14 tensors match; exact inverse patch | Kinetix episodes not rerun |
| Breakout construction | PASS: all 6 tensors match; 1,000 fresh-seed episodes per arm | No local PPO checkpoint comparison |
| Go, zero-forward-budget construction | PASS: all 14 generated NPY Git blob identities match | Go matches not rerun |
| Qwen3.5-0.8B edit | PASS: actual pinned BF16 source bytes, both edited hashes, exact rollback | Full-model forward and MATH-500 not rerun |
| HeptaTrader financial benefit | HOLD | Authoritative source replay incomplete; no weight benefit established |

Breakout means were 519.696 for the published construction, 0.564 for zero
weights, and 0.449 for a fixed norm/support-matched random-sign control. The
complete 3,000-episode record is retained. These are fixed-answer reconstruction
and validation results, not a new independent LLM discovery or an end-to-end
training-cost comparison.

Read [the full audit](MIT_REPRODUCTION_REPORT.md) for Experiments 3/4/6/7/8,
negative results, probe budgets, gradient distinctions, and Q1–Q3 limitations.
The accompanying [P0 diagnosis](../../../docs/weight-runtime/p0-replay-20261104/SOURCE_REPLAY_DIAGNOSIS.md)
preserves strict failure semantics. Its proposed diagnostic patch is unapplied.

## Reproduce in an isolated copy

Use Python 3 and NumPy (the recorded behavior run used NumPy 2.3.5). Run from
this directory. Scripts write regenerated outputs beneath `reproduced/`, so keep
the committed observations intact and execute from a disposable copy.

```bash
python replay_public.py
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 python run_breakout.py --episodes 1000 --workers 4
python replay_qwen_selected.py
```

The first two commands use the included source files. The Qwen command needs
network access to the pinned public Hugging Face revision and downloads only
the safetensors header and two tensors. Its generated two-tensor files are not
complete runnable models. Scripts verify source identities before reconstruction.

## Provenance and licenses

Upstream repository: [RikiyaT/lm_understand-logs](https://github.com/RikiyaT/lm_understand-logs),
commit `4d09ba6d6a7e891dd8063974dfe81b3d78e3494f`. Authors: Rikiya Takehi,
Jayden Teoh, Alex Zhang, and Omar Khattab. The [research blog](https://rikiyat.github.io/blog/weight-space-programming/)
was published on November 2, 2026. Bundled upstream files remain byte-identical
to their pinned source; local scripts and result files are separate.

The retained [upstream license](upstream/LICENSE) distinguishes CC BY 4.0
logs/data/networks, MIT-licensed author scripts, and the GPL-3.0 MinAtar source
embedded in its prompt. The full [MinAtar license](upstream/exp5_write_from_scratch/LICENSE-MinAtar)
is included. This directory is a separate research distribution; the copied
third-party materials are not relicensed as runtime implementation code.

`source_identity.json` records upstream Git blobs; `PACKAGE_MANIFEST.json`
records the SHA-256 of every packaged file except the manifest itself. Private
HeptaTrader command events and trading data are not included.

# Independent MIT weight-program replay and Qwen data audit

This bundle replays the three **published** MinAtar weight programs from
[Sparks of Weight-Space Programming](https://rikiyat.github.io/blog/weight-space-programming/)
(Rikiya Takehi, Jayden Teoh, Alex Zhang and Omar Khattab, MIT CSAIL, November 2,
2026). It also independently recomputes the portable arrays from HeptaRuntime's
existing Qwen mechanism replay and checks the original Qwen editor token usage.
The core replay script performs no new LLM search or Qwen inference. Separately
identified supplements below qualify Qwen exports and two short CPU forwards;
they generate no answers.

## Results actually obtained on November 4, 2026

The 20,486-parameter networks were constructed from the authors' numeric edit
statements. Every reconstructed F32 tensor was bitwise identical to the original
released checkpoint. Evaluation ran the original MinAtar 1.0.15 source embedded
in the pinned prompts, with a fresh explicit seed protocol.

| Game | Zero policy, mean ± SE | Replayed edit, mean ± SE | Authors' published edit, mean ± SE |
|---|---:|---:|---:|
| Breakout | 0.46094 ± 0.06265 | 528.20313 ± 20.14379 | 517.411 ± 7.41695 |
| Asterix | 0.52344 ± 0.08223 | 54.38281 ± 2.78402 | 53.178 ± 1.02331 |
| Seaquest | 0.07813 ± 0.03060 | 51.27344 ± 3.83635 | 53.110 ± 1.35738 |

There were 128 episodes per local variant/game (768 total); the authors used
1,000 episodes per edited policy. Both use categorical actions, sticky actions
0.1, and a 10,000-step cap. Local environment seed is 20261104 + episode index;
action seed is 20361104 + episode index. Edited Breakout reached the step cap in
48.44% of episodes. Original evaluation RNG seeds and trained PPO checkpoints
are unavailable, so this is statistical comparison under an explicit new
protocol, not reproduction of the exact authors' episode sequence or PPO result.

The local evaluations took 55.2061 seconds wall time and 55.1990 seconds CPU time,
with peak RSS 27,848 KiB. These costs exclude original LLM discovery, downloads,
and environment preparation. The zero policy uses an exact constant-logit fast
path; its latency is not an ordinary neural-forward baseline. The raw field
`forward_calls` counts policy action evaluations for that variant. These timings
do not establish superiority to gradient training.

The core script's Qwen portion is an independent arithmetic audit of **existing** arrays:
all 14 paired means, both NPZ hashes, and the four retained retry arrays match.
It adds no Qwen model inference. That earlier replay was a teacher-forced
mechanism test with zero generated tokens, not held-out generated accuracy.

The original Qwen p50c editor recorded 5,437,759 input tokens (5,180,032 cached),
149,017 output tokens, and 46,800 reasoning-output tokens as a breakout of those
outputs. Only the final cumulative usage in each of four conversations is added.
Target-model inference and evaluation are excluded. Its 50-forward budget counts
batched requests, not 50 individual neural-network examples.

## Reproduce independently

Python 3.12 and NumPy 2.3.5 were used. Linux, a Python virtual environment, and
approximately 1 MB of artifact storage are sufficient; no PyTorch or GPU is
required. The commands below download exact public inputs and then run the
published prescriptions, including their original version-pinned game code.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python acquire.py
.venv/bin/python verify.py
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 .venv/bin/python audit_and_replay.py --episodes 128 --output replay_local.json
```

`acquire.py` downloads 24 files, totaling 397,421 bytes. Each entry is pinned by
repository commit, byte length, SHA-256 and original Git blob SHA-1. Acquisition
does not execute downloaded content. Divergent existing cache files are refused,
not replaced. The source checkout locations are:

- MIT release: `RikiyaT/lm_understand-logs` at
  `4d09ba6d6a7e891dd8063974dfe81b3d78e3494f`.
- Existing HeptaRuntime replay: `TrillionniumFoundation/hepta-runtime` at
  `1f2d3d782e8803e769989234e7902ca5c04eff97`.

The replay refuses an existing output filename. To use a previously acquired
directory without networking:

```sh
.venv/bin/python acquire.py --from-cache /absolute/path/to/verified/replay-cache
.venv/bin/python acquire.py --verify-only
.venv/bin/python verify.py
```

`verify.py` checks every downloaded file, the retained original execution's
script/result/manifest identities, all 768 episode summary statistics, the
author-result values, and the editor-cost calculation. It performs no new
inference. NumPy/BLAS/platform differences may change fresh stochastic episode
trajectories; inspect fresh per-episode outcomes and report uncertainty rather
than requiring their scores to equal the retained run exactly.

## Evidence and scope

- `audit_and_replay.py` is byte-for-byte the script executed for the retained
  run: SHA-256
  `3e1641463d4cae2607084083ff672034046557bd7f4636a5f6a90d6d17ae40f0`.
- `results/new_replay.json` retains all episode scores/lengths and the complete
  portable-array audit: SHA-256
  `9d2fbf84d712e71821be0c5657fb1f47f5202c6cd9f744697f45a0d6a9450085`.
- `aggregate.json` retains compact results, runtime versions, costs and limits.
- `acquire_manifest.json` binds all upstream inputs, including the seven editor
  usage records used to check conversation boundaries.

No new Astra program discovery, unseen Qwen answer evaluation, compute-matched
training comparison, or HeptaTrader/NDU benefit is established by this bundle.
The fresh-seed protocol was explicit before execution but was not formally
preregistered. No live trading model was changed.

### Subsequent Qwen asset qualification

The [feasibility inventory](qwen_feasibility/README.md) pins the existing original
Qwen weights and edit, and identifies the missing evaluator modules, benchmark
inputs and generation runtime. The later [export qualification](qwen_feasibility/export_qualification/README.md)
actually built isolated base/p50c text exports using the unchanged author edit
script. It verified the two expected edited matrices, 130,188 changed BF16
values, and byte identity of the other 333 included language/MTP tensors.
The cached original file stayed unchanged. This closes the file-export identity
step of the earlier inventory, not model-loading compatibility, generated
accuracy, the original Astra discovery process or the full benchmark replay.
Only source commitments, a reproduction driver and aggregate receipts are
published; the generated weight files are not included.

The subsequent [strict CPU framework qualification](qwen_feasibility/framework_qualification/README.md)
maps all 320 main language tensors to the installed text class, supplies the
verified tied embedding alias, and loads all 321 target state keys with
`strict=True, assign=True`. The 15 MTP tensors are explicitly unconsumed by that
class. Each variant passes one finite seven-token forward, with all learned
weight hashes verified before and after. This is a documented compatibility
port using the existing CPU reference implementation, not a test of default
`from_pretrained`, vLLM, long context, KV-cache decoding or benchmark accuracy.
The two forwards generate zero tokens; their order-dependent timings are not
evidence of an editing speedup.

## Attribution and licenses

The original MIT repository licenses logs, data and networks under **CC BY 4.0**,
and its own scripts under MIT. The MinAtar environment source quoted inside its
prompts is **GPL-3.0** (Young and Tian's MinAtar); the full upstream license is
downloaded as `upstream/exp5_write_from_scratch/LICENSE-MinAtar`.
`upstream/LICENSE` records the MIT release's licensing distinctions. Original
benchmark quotations, where any occur, retain their respective licenses.

This bundle's new acquisition/verification code follows the HeptaRuntime
repository's Apache-2.0 license. That does not relicense downloaded weights,
prompts, game source or other upstream material. Downloaded directories and
extracted environments are intentionally ignored by Git; do not add them as
Apache-only repository source. If redistributing them, retain their original
attributions and applicable licenses. The retained local result is new evidence,
not a copy of the authors' evaluation log.

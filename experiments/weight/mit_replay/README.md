# MIT Qwen weight-edit reference replay

This directory provides a bounded, independently implemented replay of the public
`p50c` Qwen3.5-0.8B edit from **Sparks of Weight-Space Programming**. It acquires an
immutable base and patch, checks the actual BF16 bits, loads a private resident
model, and evaluates identical raw texts before and after the edit.

The completed replay and its portable evidence are documented in
[`RESULTS.md`](RESULTS.md). It passed the
predeclared public-context mechanism check in 28 actual CPU forwards.

It does not discover the edit, reproduce the unpublished MIT harness, train a
model, or establish benchmark improvement. The included diagnostic texts were
publicly used by the original experiment. Their replay is a mechanism and
integration check, not a blind evaluation.

## Pinned reference

| Item | Identity |
| --- | --- |
| Base | `Qwen/Qwen3.5-0.8B` |
| Base revision | `2fc06364715b967f1860aea9cf38778875588b17` |
| Source | `RikiyaT/lm_understand-logs` |
| Source commit | `4d09ba6d6a7e891dd8063974dfe81b3d78e3494f` |
| Published run | `exp8_math/runs/p50c` |
| Changed tensors | Layers 15 and 19 `mlp.down_proj.weight` |
| Tensor shape and dtype | Each `1024 × 3584`, BF16 |
| Selected columns | 64 per tensor |
| Actual changed BF16 elements | 65,260 + 64,928 = 130,188 |
| Selected elements including rounding no-ops | 131,072 |

The source sparse patch contains replacement BF16 bit patterns. We reconstruct
them exactly rather than recomputing an approximate floating-point projection.
All four before/after tensor hashes are pinned in `reference.py`. The source
checkpoint stays read-only; variant selection changes only the caller-owned
resident model.

## Components

| File | Responsibility |
| --- | --- |
| `reference.py` | Immutable source identity and expected tensor hashes |
| `acquire.py` | Public HTTPS downloads, size bounds, SHA-256 receipts and pinned revisions |
| `verify.py` | Safetensors header/offset checks, exact sparse reconstruction and actual-difference checks |
| `qwen_adapter.py` | Lazy local-only Transformers provider, bounded inputs and private resident variants |
| `run_reference.py` | Frozen replay plan, paired forwards, token scores, cost and failure reports |
| `test_verify.py` | Reconstruction and corruption rejection checks |

## Execution

Use an isolated Python environment with a working PyTorch installation,
Transformers supporting `Qwen3_5ForConditionalGeneration`, NumPy and Safetensors.
The initial ROG environment used Transformers 5.20.2 and Safetensors 0.8.0 with an
existing read-only PyTorch installation. The final run report records the actual
model and runtime versions. No import of this package downloads or loads a model.

Choose new task-owned directories. Do not point acquisition or output at an
existing serving checkpoint or experiment result directory.

```bash
python experiments/weight/mit_replay/acquire.py --root /absolute/reference
python experiments/weight/mit_replay/verify.py \
  --root /absolute/reference --output /absolute/verification.json
python experiments/weight/mit_replay/run_reference.py \
  --root /absolute/reference --output /absolute/replay_pair_1 \
  --pairs 1 --device cpu --threads 4 --max-seconds 300
```

The first replay uses one productive/repetitive pair, hence four forwards. After
checking observed resource use, all six source pairs and two premature-closure
controls can be replayed with `--pairs 6 --closure-controls`. This entails 28
forwards and no generated tokens. Use a separate output directory. A process
supervisor should impose a slightly larger hard wall limit and a memory/CPU
limit; the runner's wall check occurs between forwards.

The diagnostic gate is frozen in `plan.json` before model loading: mean change in
repetitive-branch log probability must be below −0.02 nats/token, and the absolute
mean productive-branch change must be smaller. This is a predeclared smoke gate
for the published mechanism, not a calibrated capability acceptance threshold.
Every individual pair and closure control remains in `report.json`, so a mean
cannot hide opposing cases. The raw token log probabilities are also retained.

### Alignment and comparability

The runner uses the exact public raw texts from `requests/fwd_24.json.claimed`
and their published `transfer_probe_bounds.json`, with no chat-template
re-rendering or prompt rewriting. It requires exact token lengths, aligns the
causal next-token scores to the published branches, and verifies matching token
IDs across the base and edited forwards. Mismatch fails the run. There is no
sampling seed to match because these are teacher-forced forwards, with the model
in evaluation mode and gradients disabled.

CPU eager BF16 arithmetic can differ from the original inference backend. The
goal is actual hash-exact weight reconstruction and an observed behavioral
mechanism under a recorded alternative backend. Do not report its values as
bit-identical original-harness output, MATH-500 accuracy, or a new held-out gain.

## Worker adapter contract

The lazy factory is
`experiments.weight.mit_replay.qwen_adapter:load` and accepts:

```json
{
  "reference_root": "/absolute/reference",
  "device": "cpu",
  "threads": 4,
  "max_batch": 1,
  "max_sequence": 256,
  "variant": "base"
}
```

The returned object exposes `module`, `normalize_inputs`, `forward`, `describe`
and `close`. Inputs are raw `texts` or explicit `input_ids` and an optional
`attention_mask`; outputs are tensors `logits`, `input_ids`, `attention_mask`.
Outcome fields are rejected. Core worker code owns hooks, typed patch
operations, session isolation, authorization, and artifact registration.

`set_reference_variant("base" | "edited")` is only the immutable public-reference
replay primitive. It is not an arbitrary patch authoring API. Existing generic
writer-projection patches should use the core typed operation and their own
expected source hash; their independently rounded output must not be represented
as the exact published sparse patch unless hashes match.

Useful hook modules are listed by `describe()`, including the two down
projections. A diagnostic attachment can capture their incoming activations or
outgoing writes through the core hook system without adding outcome metadata to
the model provider.

## Evidence and failure behavior

`acquisition.json` records immutable URLs, byte lengths, full-file SHA-256, and
upstream LFS checksums where available. Verification rehashes those files before
loading and rejects malformed, duplicate, out-of-bounds, unchanged, or
non-finite sparse replacements. It checks actual changed counts, touched columns,
and both final tensor hashes. The adapter checks the loaded resident BF16 values
again and rejects missing, unexpected or mismatched checkpoint keys.

Each run creates `plan.json` exclusively, then append-only `events.jsonl`, a final
`report.json` and `token_logprobs.npz`. Failure reports include the exception and
completed forward costs. Output directories are not reusable for another run.
Partial downloads are not silently treated as complete. A full supervised job
termination can prevent final report creation; preserve the plan, event log and
supervisor status as failure evidence in that case.

`cost` counts the completed forward calls and token evaluations, elapsed time,
peak process RSS and generated tokens (zero here). Download and environment
preparation are separate supervised jobs and must be included separately when
reporting total project cost.

## Local checks

```bash
python -m unittest discover -s experiments/weight/mit_replay -p 'test_*.py' -v
```

These small tests validate corruption rejection and exact reconstruction. They
do not substitute for the real model replay.

## Upstream sources and attribution

See `ATTRIBUTION.md`. The original experiment's complete persistent kernel and
forward service are not published in the source repository; this directory is a
new adapter, verifier and bounded runner around the public reference artifacts.

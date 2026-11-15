# Resident weight worker

This worker performs bounded CPU experiments. It never trains, modifies a source
checkpoint, activates a production model, or sends an order. Independent holdout
assessment and production decisions remain with the evaluator and existing owner.

## Launch and transport

Use an existing compatible Python environment or an isolated environment with
`requirements.txt`. Startup never installs dependencies. Qwen additionally requires
the separately pinned MIT replay dependencies and acquired reference files.

```text
python worker.py --print-identity
python worker.py --serve --socket /run/session/worker.sock --session-id SESSION
python worker.py --client --socket /run/session/worker.sock --timeout-ms 120000 --connect-timeout-ms 30000
python worker.py --stdio --session-id SESSION
```

The server reads one startup `open` request and survives stdin EOF. Later requests
use the UID-restricted mode-0600 Unix socket. The client uses only the standard
library. Each stdout line is one response; model logs go to stderr. `--stdio` is a
debug transport. The owner-managed daemon enforces idle, lifetime, resident-memory
and request limits. A hard timeout terminates the worker and retains unresolved
operations; it cannot be interpreted as successful completion.

Optional `--expected-worker-sha256` checks the entry file. Optional
`--expected-package-sha256` checks SHA256 of compact, sorted-key canonical JSON
mapping relative paths to SHA256, including `worker.py` and `weight_runtime/*.py`.
Tests/docs are excluded. This is drift detection, not code signing: code admission
must happen in the existing owner before execution.

Requests use `{id,op,session_id?,params}`. Responses use `{id,ok:true,result}` or
`{id,ok:false,error:{code,message,details}}`. IDs are strings, maximum 128 characters;
frames are limited to 1 MiB. Large tensors are retained safetensors artifacts.
`query` provides at most 1024 scalar values per tensor page.

The owner injects `input_roots` and `output_root` into open. The latter is the
artifact directory; the socket is its sibling. `artifact_root`/`run_dir` overrides
are refused. Files resolve within declared input roots or the session output root.
Artifact references contain `artifact_id`, content `sha256`, `kind`, absolute `path`,
`byte_length` and metadata. Artifact IDs bind metadata as well as content, so they
are not necessarily equal to content hashes.

Open accepts `cpu_threads` (1–8, default 2), `idle_timeout_s` (1–3600, default 900),
`max_memory_bytes`, and lower values for the named limits in `session.py`. Requests
accept `timeout_ms`, capped by `--max-request-ms` (at most 600000). The daemon's
`--lifetime-s` is at most 7200. Persistent model/cache memory counts while idle.

Completed operation IDs replay their exact durable response; changed payloads
conflict. Pending operations are never automatically rerun. Recovery reloads and
verifies the same base and restores recorded budgets. Unresolved operations block
new computation; evidence inspection and closing remain possible.

## Model providers

`torch_sequential` (alias `torch_fixture`) accepts a declarative architecture and
an exact safetensors state dict, with standard names such as `0.weight`:

```json
{
  "provider":"torch_sequential",
  "input_roots":["/models"],
  "output_root":"/run/session/artifacts",
  "model":{
    "architecture":{"layers":[{"type":"Linear","in_features":2,"out_features":2,"bias":false}]},
    "weights_path":"/models/identity.safetensors",
    "weights_sha256":"FULL_FILE_SHA256"
  }
}
```

Supported layers are Linear, ReLU, Tanh, GELU, Sigmoid, LayerNorm, Flatten, Identity
and Softmax. Input is `{"x":[[1,2]]}` or an artifact/tensor reference under `x`.
Arbitrary pickle/module deserialization is unsupported. The Python provider class
also accepts an already-owned `torch.nn.Module` in trusted integrations.

`laya` requires these model fields: `source_dir` (pinned release `learn` directory),
`source_tree_sha256`, `base_dir`, `base_manifest_sha256`, `parent_adapter_path`,
`parent_adapter_sha256`. `providers.source_tree_identity(source_dir)` hashes the
canonical map of relative `.py` paths to SHA256. The installed `laya.common` code
hash is also bound. Loading uses `enforce_gpu=False` and the frozen parent.

Laya inputs are `{state,order:[0,1,2,3,4,5,6],parallel_layout:false}`. Outputs include
semantic-order price logits/probabilities and ACT/ESCALATE logits/probabilities.
The action outputs matter because the price distribution supplies confidence
features to the action head. Parallel layout is an explicit input control.

The default Laya patch target is `effective.scorer.3.weight`. An explicit research
allowlist can additionally admit `model.encoder.layers.N.mlp.Wo.weight` and
`model.head.layers.N.linear2.weight`. RowLoRA final weights compile to A/B using
`row_index` and run through the original nested-linear execution. An exactly
unchanged effective target preserves the original A/B bytes: a merged matrix can
round away contributions that the nested forward still computes. Changes apply
only to the research instance and are restored after every probe.

Laya state fields are rebuilt in the pinned dataset's `CAUSAL_STATE_FIELDS` order
before tokenization, matching `dataset.encode_rows` without mutating the frozen
input. Canonical JSON key sorting is a storage format, not the model's text order.
The same tokenizer path is exposed as `make_laya_encoder` so production encoding
parity can be checked without loading model weights. Input receipts retain the
field order and the actual encoded tensor identity.

`mit_qwen_reference` is an optional CPU bridge to the independently verified replay
adapter. It requires `reference_root` and `adapter_source_sha256` (the replay
directory's `.py` source-tree digest). Targets are restricted to the verified
reference matrices. Worker output is last-nonpadding-token logits, not a generated
answer or benchmark score. The independent reference runner performs teacher-forced
mechanism diagnostics on public texts. Neither path implements text generation or
a full benchmark evaluation.
A recalculated writer projection is not claimed bit-identical to MIT's sparse
BF16 replacement.

## Core operations

- `inspect`: parameters or `collection:"modules"` for actual hook names/types;
  selected names, paging, optional hashes/statistics. `export_tensor:true` plus
  `tensor` retains a bounded parameter or optional `rows`/`columns` matrix block.
- `probe`: `inputs`, optional `patch_id`, `captures`, and `softmax_output`.
- `intervene`: probe plus `interventions`. Hooks select `module`,
  `where:"input"|"output"` and optional tuple `tensor_index`. `select:"markers"`
  captures Laya markers in semantic order; `select:"tokens"` uses explicit
  `token_indices`. Interventions support scale, replace and subtract_direction.
  Captures at the same hook observe the value before intervention. Hooks and
  temporary weights are restored on both success and failure.
- `analyze`: registered numerical operations; unknown operations are rejected.
  This is not arbitrary code execution. Tensor results are retained artifacts.
  Includes statistics, difference, SVD, permutation metrics, concatenate, reshape,
  pair_differences and writer_ranking. See `docs/weight-runtime/ANALYSIS.md` for the
  complete artifact-reference workflow and ranking formula.
- `patch`: `expected_model_id` and 1–16 operations, each bound to
  `expected_tensor_sha256`. Operators: scale, zero, add, low_rank,
  input_projection, writer_projection, replace_sparse. Shape/dtype mismatch,
  unknown operations, nonfinite values and post-cast overflow are errors.
- `seal`: `patch_id`, `information_cutoff_ms`, `evaluation_protocol_sha256`, and
  optional `calibration_artifact_id`. Output is `DirectWeightEdit` with
  `SEALED_RESEARCH_CANDIDATE`, zero backward/optimizer counters, no fabricated
  training receipt and no production approval. Independent evaluation verifies
  the declared information cutoff against actual input lineage.
- `query`: retained metadata, selected JSON fields or bounded tensor pages.
  Retained historical facts do not assert freshness of source files.
- `close`: release model references while preserving artifacts.

Writer projection computes `W[:,J] -= alpha * u @ (u.T @ W[:,J])` with a unit
direction. Alpha 6 is a research operation: the selected component becomes negative
five times its original value. Computation dtype is explicit float32/float64;
results are cast to the real target dtype, saved, reloaded and hash checked. Metrics
count realized effective coordinates separately from stored parameter elements.
`storage_changed_coordinates` measures numeric changes in the serialized physical
parameters; `storage_changed_parameters` counts changed parameter hashes, and
`storage_bytes_unchanged` requires exact parameter byte equality. Per-parameter
`storage_measurements` retain hashes and delta norms. Zero effective-coordinate
changes alone do not establish an execution no-op, and signed-zero bit changes
can change hashes without increasing a numeric coordinate count.

The reference numeric screen uses unique effective weights across the whole loaded
model and individual target tensor norms. It is explicitly research-only and **not**
the old adapter-only production plasticity rule. `production_eligible` stays false.

## Tests

```text
python -m unittest discover -s workers/weight/tests -v
```

For an owned Laya install, `tests/check_laya_encoding.py` performs tokenizer-only
parity checks with required dataset/common/input SHA256 pins. It checks four state
key orders, three option orders and both sequential and parallel layouts. Default
order tensors must also equal the pinned production `dataset.encode_rows` output.
This check reads one frozen input and the local tokenizer; it does not load model
weights, perform forwards or read outcome files.

Tests use real CPU modules and tensor operations. Missing dependencies fail imports;
they are not mocked successes. AF_UNIX testing skips explicitly only when the
execution environment forbids Unix sockets. That skip must be reported, and the
real owned-host MCP/daemon/client path must still be exercised on a permitted host.

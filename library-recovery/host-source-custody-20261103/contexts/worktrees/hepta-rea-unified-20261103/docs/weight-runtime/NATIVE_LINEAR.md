# Scoped native F32 Linear forward

`weight_linear_forward` computes `output = input × weightᵀ + bias` in Rust for
one explicitly selected safetensors F32 tensor with shape
`[out_features, in_features]`. Bias is an optional explicit vector supplied in
the request; omission means no bias. The implementation reads and validates
the actual weight bytes and performs the arithmetic itself. It does not call
Python, PyTorch or a placeholder provider.

This is a fixed operator pilot. It does not import a model graph, run arbitrary
layers or Transformers, train weights, convert quantized tensors, supply
tokenization, or implement a general replacement for the resident PyTorch
worker. F16 and BF16 remain supported for exact artifact edits but are refused
by this forward operator.

## Source and input contract

An admitted workspace source requires its complete SHA-256:

```json
{
  "source": {
    "kind": "path",
    "path": "/approved/models/linear.safetensors",
    "expected_sha256": "<full-file-lowercase-sha256>",
    "tensor_name": "weight"
  },
  "inputs": [[-2.0, 1.0], [0.5, 2.0], [3.0, -1.0]],
  "bias": [0.25, -0.5]
}
```

An existing native artifact is selected by its verified internal ID:

```json
{
  "source": {
    "kind": "artifact",
    "artifact_id": "wa1_<manifest-identity>",
    "tensor_name": "weight"
  },
  "inputs": [[-2.0, 1.0], [0.5, 2.0], [3.0, -1.0]]
}
```

Workspace paths use the existing descriptor-relative, no-symlink root admission.
A path underneath `state_dir` is refused even if a controller workspace root
also covers that directory; retained artifacts must use the artifact-ID form.
The latter verifies the internal manifest, fixed model location, ownership,
single-link private inode and file size before use. Neither form accepts a
caller-selected arbitrary state path. Unknown source fields are rejected.

The existing isolated Rust REA parser provides the tensor descriptor. The
controller independently checks its header identity, shape, dtype, storage
extent, source version and probe against the same opened descriptor. It then
hashes the **complete** file and captures the chosen tensor bytes in that same
streaming pass, verifies the expected complete SHA-256, and checks the file
descriptor's metadata again. Arithmetic uses those captured bytes, without a
later independent file read.

All input, bias and weight values must be finite F32. JSON numeric inputs are
deserialized as F32. Every row must match `in_features`; an explicit bias must
contain exactly `out_features` values. The implementation accumulates products
in F32 in input-column order and adds the bias afterward. It rejects non-finite
outputs. Different BLAS/GPU accumulation orders can produce different rounding
on general matrices; equality of the small exact fixture does not establish
bitwise equivalence for all inputs.

## Budgets and results

| Resource | Limit |
| --- | --- |
| Complete safetensors source | 2 GiB |
| Input rows | 1–64 |
| Each matrix dimension | 1–4,096 |
| Weight tensor | 1,048,576 elements / 4 MiB |
| Multiply-adds | 16,777,216 |
| Output values | 16,384 |
| Response | 1 MiB |
| Whole forward operation | 60 seconds |

The operation checks both asynchronous I/O timeout and the deadline during
bounded Rust computation. Invalid shapes, incompatible dtype, non-finite values,
incorrect source identity and exceeded budgets fail instead of producing a
partial result. No files or model state are modified.

The `hepta.weight.linear-forward.v1` result includes outputs, weight shape,
multiply-add count, source/header/tensor/input hashes, observed source version
and compute duration. `implementation` is `rust_sequential_f32_linear`;
`training` and `production_eligible` are false. Compute duration describes only
the local calculation, excluding source admission, parsing, full-file hashing
and transport. It is not a whole-request latency or benchmark comparison.

## Independent CPU comparison

Ordinary tests cover exact file-backed outputs, explicit bias, full-file hash
changes, source confinement, symlinks, direct state-path refusal, oversized
files, dtype/rank restrictions, non-finite arithmetic and computational budgets.
Run on the configured development host:

```sh
cargo test --all-features --lib weight_forward
```

The opt-in external qualification starts the shipped stdio MCP binary with an
isolated temporary state directory and no configured Python worker profiles.
It uses an explicitly supplied existing Python environment only as the
independent test oracle. The reference loads the same safetensors file through
`safetensors.torch.load_file` and computes real `torch.nn.functional.linear`
outputs on CPU:

```sh
HEPTA_WEIGHT_TEST_PYTHON=/absolute/cpu-venv/bin/python \
  cargo test --all-features --test weight_forward_external -- --ignored --nocapture
```

The fixed initial matrix is `[[1, -3], [0, 4]]`. The deliberate first-coefficient
change, 1 to 2, is evaluated on separate inputs `[-2, 1]`, `[0.5, 2]` and
`[3, -1]`, whose first-channel targets are `-7`, `-5` and `9`. The second output
channel is protected. The test checks:

- Rust and real PyTorch outputs and source hashes agree for the original,
  patched and restored matrices; explicit bias is also compared.
- An exact no-op preserves the complete hash and every output.
- Repeating the identical patch yields the same verified artifact ID.
- The specified first-channel held-out error decreases to zero for this
  constructed task, while the second channel is unchanged.
- Restore reproduces every original file byte and the original outputs; the
  source file remains immutable throughout.
- Native tools are available without Python worker profiles, and using a
  retained artifact's state path instead of its ID is refused.

A successful run prints `WEIGHT_NATIVE_PYTORCH_LINEAR_QUALIFICATION` with the
observed PyTorch version, hashes and metrics. Record the actual run output as
evidence; source code and test definitions alone do not constitute a successful
qualification. This fixture supports only the documented linear operator and
exact transformation behavior. It does not support a performance multiplier,
automatic repair claim or arbitrary-model migration claim.

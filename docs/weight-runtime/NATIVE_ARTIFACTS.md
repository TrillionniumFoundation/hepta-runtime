# Native immutable tensor artifacts

`weight_artifact_patch` and `weight_artifact_restore` operate on safetensors bytes
inside the Rust runtime. They do not launch a Python client, load a model into
PyTorch, or change a resident worker. They are available through runtime mode
with controller workspace permission, independently of configured Python worker
profiles. The existing worker tools retain their own provider and job semantics.

## Exact bounded edits

`weight_artifact_patch` accepts one absolute source path admitted beneath the
configured `controller_workspace_roots`, the **full-file** lowercase SHA-256,
one tensor name, and 1–1,024 distinct flattened element edits. A descriptor is
obtained through the existing isolated REA model parser; the controller checks
its source metadata, header digest, tensor extent and probe against the same
open file descriptor. Only nonempty, verified F32, F16 and BF16 safetensors
tensors are accepted.

Example arguments, with the source identity supplied by the caller:

```json
{
  "path": "/approved/models/linear.safetensors",
  "expected_sha256": "<full-file-lowercase-sha256>",
  "tensor_name": "weight",
  "edits": [
    {
      "index": 0,
      "expected_hex": "0000803f",
      "replacement_hex": "00000040"
    }
  ]
}
```

This example changes an F32 element from 1 to 2. Hex strings describe the exact
little-endian storage bytes: eight hexadecimal characters for F32 and four for
F16/BF16. Both expected and replacement elements must be finite. No floating
point arithmetic, implicit conversion, quantization, shape change or automatic
choice of edit occurs. Duplicate indices, incorrect element widths and out of
range offsets fail. To request an exact no-op, supply the same expected and
replacement bytes for an existing element. The empty edit list is rejected.

The runtime opens the source read-only and streams a new file, substituting only
the selected bytes. It checks every expected element, hashes the complete input
and output during that pass, and verifies source descriptor metadata afterward.
Source mismatch never produces a successful receipt. The original file remains
unchanged, including for no-op and restore operations.

## Publication, identity and restore

The caller does not choose an output path. Results live under
`<state_dir>/weight-artifacts-v1/<artifact_id>/`, containing `model.safetensors`
and `manifest.json`. Generated directories are private; generated files are
owned, single-linked and mode 0600. A complete model and manifest are flushed
inside one staging directory and published with Linux `renameat2` using
`RENAME_NOREPLACE`. The store directory is flushed and the retained model is
hashed again before success is reported. This publication implementation is
currently Linux only.

An ID has the form `wa1_<sha256>`. Its digest binds the canonical manifest:
source path, complete source and target hashes, tensor descriptor, exact edit
bytes, operation kind and optional parent artifact. It is an operation identity,
so the same source bytes under a different path need not receive the same ID.
An identical repeated call revalidates the source, plan and retained artifact
before returning the same ID with `reused: true`. It does not trust a receipt or
the presence of a directory as proof of completion.

`weight_artifact_restore` accepts only:

```json
{"artifact_id": "wa1_<manifest-identity>"}
```

Restore opens the verified internal artifact; it never accepts an arbitrary
caller-supplied path. It verifies the stored manifest and target, applies the
inverse exact byte edits into a **new** artifact, and requires the resulting
complete hash to equal the original source hash. The patched artifact remains
available. A restore receipt cannot be restored again; use the original patch
ID to repeat or reconcile restoration.

Receipts include `artifact_id`, `kind`, `artifact_path`, `manifest_path`,
`source_sha256`, `sha256`, `byte_length`, `changed_bytes`, `exact_no_op` and
`reused`. They explicitly report `source_modified: false`,
`production_eligible: false` and `behavior_evaluated: false`. Artifact creation
verifies the file transformation; it does not establish model quality.

## Resource and failure boundaries

| Resource | Limit |
| --- | --- |
| Complete source file | 2 GiB |
| Edits per call | 1–1,024 |
| Tensor name | 4,096 UTF-8 bytes |
| Streaming buffer | At most 1 MiB |
| Manifest | 512 KiB |
| Store, including staging directories | 8 GiB and 128 entries |
| Store lock wait | 10 seconds |
| Complete patch or restore call | 300 seconds |

A regular validation failure removes its own staging directory. Cancellation or
a process crash can leave a private staging directory that still counts toward
the quota. Staging directories are never successful artifacts. A timeout may
occur after publication; repeat the identical request to reconcile the stable
identity. No automatic cleanup deletes unrelated or already published entries.

Hashes bind observed bytes and manifests; they are not signatures establishing
an external author's identity. The runtime state directory remains an
administrator-owned trust boundary. Concurrent file changes detectable through
the opened descriptor fail validation; a privileged process with arbitrary
control of runtime memory, files or metadata is outside this guarantee.

## Verification

Run the repository checks on the configured development host, as required by
`AGENTS.md`:

```sh
cargo test --all-features --lib weight_tensor
cargo test --all-features --lib weight_artifact
```

The ordinary tests cover exact no-op, finite F32/F16/BF16 round trips, immutable
parents, stable repeated identities, restoration of every original byte,
incorrect hashes and expected elements, source confinement, symlinks, oversized
files and corrupted retained artifacts. A separately specified tiny linear task
checks that the chosen coefficient patch improves held-out outputs while an
untouched coefficient retains its behavior. That fixture is a narrow behavioral
check, not evidence of general model repair.

The separate [native linear qualification](NATIVE_LINEAR.md) runs actual shipped
MCP calls and compares their Rust outputs with real CPU PyTorch before and after
no-op, patch and restore. Test execution results must be recorded from the
development host; adding these tests alone is not a passing qualification.

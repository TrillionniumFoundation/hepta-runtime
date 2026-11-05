# GGUF storage layout validation

## Scope of this change

The native descriptor parser previously derived storage lengths only for F32 and F16.
This change adds the 16 additional invariant scalar/block layouts recognized by the
pinned REA 6.8.0 implementation and applies row constraints before deriving lengths.
The existing bounded reads, overlap checks, worker limits and snapshot index are reused.

This is a bounded model-parser improvement, not qualification of the whole REA model
provider or its Evidence contract. No model is executed, dequantized, trained or modified.

| Classification | Type IDs | Storage handling |
| --- | --- | --- |
| Invariant layouts | 0, 1, 2, 3, 6, 7, 8, 26, 27, 28, 29, 30, 34, 35, 39, 40, 41, 42 | Validate the fastest dimension against the storage block size, then derive a checked byte extent. |
| Historical Q8_1 storage ambiguity | 9 | Enforce the common 32-element row constraint. Nonempty byte length stays unknown. |
| Historical K-block ambiguity | 10–15 | Enforce the common 64-element row constraint. It does not establish a 64-element storage block. Nonempty byte length stays unknown. |
| Historical type-identity collisions | 16–25 | Report AMBIGUOUS_ID, keep nonempty length unknown, and retain an identity limitation even for empty tensors. |
| Unrecognized or removed IDs | All remaining IDs | Keep length and row layout unknown, including zero-element tensors. No tensor-scoped reads. |

For every known row constraint, the first dimension must satisfy it even if later
dimensions make the total divisible or zero. For invariant layouts, storage bytes are
computed as (total_elements / block_elements) * block_bytes with checked multiplication.
File offsets still require declared alignment, checked addition to the data-section base,
file containment, and no overlap with another verified extent. Padding is allowed and
does not determine an unknown tensor's length.

Known historical layouts with zero elements have a provably empty extent after their
row constraint passes. This does not resolve an ambiguous type identity. Completely
unknown IDs no longer receive a verified length merely because their shape includes zero.

## Primary sources and version pins

The migration reference is the actual installed **rea-agents@6.8.0**, not a reconstruction
of its parser. Its MIT attribution remains in LICENSES/REA-MIT.txt.

| Reference module | SHA-256 |
| --- | --- |
| dist/model/GgufHeader.js | 6e8f33cdb4e58e4a196e505c7496f160764260e406a7ea8d89bcbb13e1105a42 |
| dist/model/ModelTensorTypes.js | ebb648607ca406e09722d6be1e70882d276170080b9ca6dadbd103360c68854d |

The differential runner rejects another package version or either changed module.
The recovered npm tarball identity used by the wider migration is
8d542ec76a9cb350584b60a6c9c088706ff812d5bb5b094c20c95b6dc25698bb.

The modern invariant block sizes were independently checked against the same GGML
revision cited by the original implementation:

- [GGML enum and scalar types, da8e2a54b919557b816b1c2beb432ccb766f7ce0](https://github.com/ggml-org/ggml/blob/da8e2a54b919557b816b1c2beb432ccb766f7ce0/include/ggml.h).
- [GGML block declarations and sizeof assertions at that revision](https://github.com/ggml-org/ggml/blob/da8e2a54b919557b816b1c2beb432ccb766f7ce0/src/ggml-common.h).
- [GGML row-size and type-trait functions at that revision](https://github.com/ggml-org/ggml/blob/da8e2a54b919557b816b1c2beb432ccb766f7ce0/src/ggml.c).

Downloaded source SHA-256 values:

| Source file | SHA-256 |
| --- | --- |
| include/ggml.h | 475beaa7e959be8c383279d9ce9d5191f37426e6b338270cfb12b26a798129d3 |
| src/ggml-common.h | 0061131b615c5721fc88a78feeb22c1f8c450f1c2646a317d80796a653bf595c |

Historical ambiguity has primary-source support:

- [llama.cpp b1500, 57ad015dc3011b046ed5a23186c86ea55f987c54, ggml-quants.h](https://github.com/ggml-org/llama.cpp/blob/57ad015dc3011b046ed5a23186c86ea55f987c54/ggml-quants.h) declares Q8_1 with two float scales, hence 40 bytes per 32 values. It also selects QK_K as 64 or 256 with GGML_QKK_64.
- [The same revision's ggml.h](https://github.com/ggml-org/llama.cpp/blob/57ad015dc3011b046ed5a23186c86ea55f987c54/ggml.h) assigns IDs 16, 17 and 18 to I8, I16 and I32 after the K types.
- [llama.cpp b2300, 6ea0f010ff6967034528d9e0b8330b9b0f0b7c13, ggml.h](https://github.com/ggml-org/llama.cpp/blob/6ea0f010ff6967034528d9e0b8330b9b0f0b7c13/ggml.h) places IQ types at 16–23 and the scalar types at 24–26. The complete 16–25 collision policy is retained from the pinned REA module, whose comments enumerate the intervening release references.

A current GGML enum alone cannot prove the layout of an older GGUF file.
general.quantization_version, general.file_type, nearby offsets and available
padding do not disambiguate these released layouts.

## Reproducible checks

### Independent C++ layout probe

scripts/rea-model-gguf-layout-probe.cpp includes the unmodified upstream headers.
It obtains enum IDs, block counts and actual C++ sizeof values rather than duplicating
a table of expected sizes.

~~~sh
c++ -std=c++17 \
  -I /path/to/pinned-ggml/include \
  -I /path/to/pinned-ggml/src \
  scripts/rea-model-gguf-layout-probe.cpp \
  -o /path/to/fresh-evidence/ggml-layout-probe
/path/to/fresh-evidence/ggml-layout-probe
~~~

On 2026-11-05 the probe compiled and ran on the desktop Linux host against the
SHA-bound headers above. All 18 invariant rows matched the REA mapping. The additional
quantized sizes observed were Q4_0=18, Q4_1=20, Q5_0=22, Q5_1=24, Q8_0=34,
IQ1_M=56, TQ1_0=54, TQ2_0=66, MXFP4=17, NVFP4=36, Q1_0=18 and Q2_0=18 bytes
per their declared blocks.

### Actual original/native differential

Use a new fixture directory and output file on each run; the runner uses create-only
writes. It checks successful semantic projections (types, dimensions, counts, offsets,
lengths and validation state), and expected success/refusal for malformed cases.

~~~sh
node scripts/rea-model-gguf-layout-diff.mjs \
  --rea /path/to/rea-agents-6.8.0 \
  --work /path/to/fresh-evidence/fixtures \
  --native /path/to/compiled/hepta-runtime \
  --out /path/to/fresh-evidence/differential.json
~~~

Omitting --native only verifies the fixtures against the actual original module;
the resulting report explicitly says native_executed=false and mismatches=null.

Initial source-only validation on 2026-11-05 executed **160 original-parser cases**:
111 accepted, 49 refused, and zero fixture-expectation failures. This initial run did
not execute a new native binary. The integration owner runs the same comparison
after compiling the combined source and retains the native binary hash in the report.

There is one declared intentional behavior difference: the native parser's preexisting
guard rejects overlapping verified tensor extents, whereas the original header parser
accepts them. The runner reports this separately and does not call it output equivalence.

### Rust regressions

Six parser regressions cover both header byte orders, all 18 invariant layouts,
multidimensional row constraints, incomplete payloads, exact tensor read boundaries,
historical ambiguity, unknown empty IDs, padding, overlap, alignment and arithmetic
overflow. A retained-session regression removes the original source and confirms that
Q4_0 ranges restore from the snapshot while Q8_1 tensor-scoped reads remain refused.

~~~sh
cargo test --all-features gguf_
~~~

The changed Rust files passed rustfmt, the JavaScript runner passed node --check,
and the patch passed git diff --check before integration. Rust compilation and the
combined full test matrix are owned by the integration worktree; this branch creates
no independent Cargo target.

## Remaining boundaries

The result remains a directory and raw-storage proof. It does not validate quantized
payload numerics or decode tensor values. The original/native Evidence envelopes and
whole-provider operation set are not qualified by these fixtures. Other preexisting
differences, including header budgets, zero-rank acceptance, name constraints and
large-integer capacity policy, remain outside this change. The mapping is pinned:
newer type IDs are left unknown until independently reviewed.

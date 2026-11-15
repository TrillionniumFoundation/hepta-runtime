# Strict Qwen CPU text loading and finite-forward qualification

Date: 2026-11-04. Result: **passed_strict_cpu_load_and_finite_forward**.

The previously qualified base/p50c text-weight exports both load into the existing Transformers 5.20.2 text class under the explicit in-memory mapping below. All learned main-language parameters are bound to the exported bytes; no missing parameter is initialized as a fallback. Each variant completes one short CPU forward with finite last-token logits.

This closes the **audited text-class loading and short-forward compatibility step**. It is not an unchanged execution of the original vLLM evaluation harness, a generation test, a benchmark score, or an independent Astra editing experiment.

## Inspected framework contract

Before running either forward, the installed Qwen3_5ForCausalLM, Qwen3_5TextModel, weight-tying, initialization and RoPE source were inspected. Five installed source file hashes are preserved in receipt.json and required by the driver.

The actual text-class state contract differs from the export's names:

| Source or state | Explicit treatment |
|---|---|
| 320 source keys model.language_model.<suffix> | In memory only, map to model.<suffix> |
| lm_head.weight | Alias the same source embedding tensor as model.embed_tokens.weight, as required by the class's tied-weight declaration |
| 15 mtp.* source tensors | Explicitly excluded from this ordinary text-class forward; the inspected class declares the ^mtp.* unexpected-key exclusion |
| Visual tensors | Already absent from the prior text export |
| RoPE inverse-frequency buffers | Deterministically constructed on CPU by the inspected class; not populated from uninitialized meta storage |

A meta-only model first establishes that the mapped learned state plus the declared embedding alias exactly covers **321 target state entries**, with no key or shape gap. The mapping is injective for all 320 source tensors. The meta instance is discarded.

For each actual CPU model, the inspected initialization.no_init_weights() context suppresses learned-weight initialization. All learned state is then supplied using:

```python
model.load_state_dict(loaded, strict=True, assign=True)
```

The two missing/unexpected-key lists are empty **after the declared architecture filtering and key mapping**. No strict=False path is used. The embedding/output-head identity is verified as the same parameter object.

Every loaded main-language tensor is hashed as raw bytes and compared with the earlier qualified export manifest. Shape and dtype are recorded per tensor. All 640 entries across the two variants have also been independently matched to the prior manifest's shape, BF16/F32 dtype and expected source hash after evidence transfer. The two source-edited matrices retain their published BF16 hashes. Hashes are checked again after forward to detect learned-parameter mutation.

This is an explicit compatibility port for loading. The behavior of the default from_pretrained checkpoint-conversion machinery was not tested; no claim of unmodified out-of-the-box loading is made. MTP speculative decoding was not tested.

## Exact bounded forward

Both variants use the same fixed, nonbenchmark text:

> A quiet morning brings clear light.

It tokenizes to seven input IDs: 32, 11012, 6353, 12077, 2708, 3000, 13. No chat template is applied. Each model uses evaluation mode, inference_mode, CPU only, eager attention, four CPU threads, use_cache=False and logits_to_keep=1.

| Check | Base | p50c |
|---|---|---|
| Main source tensors verified | 320 | 320 |
| Missing target keys | 0 | 0 |
| Unexpected mapped keys | 0 | 0 |
| Random/missing learned weights used | No | No |
| Output shape | 1 x 1 x 248320 | 1 x 1 x 248320 |
| Output dtype | BF16 | BF16 |
| All logits finite | Yes | Yes |
| Learned parameters unchanged by forward | Yes | Yes |

The maximum absolute logit difference is **0.328125**; RMS difference is **0.09628460897030124**. These are numerical differences on one fixed short input. A nonzero difference was not an acceptance condition, and these values do not measure accuracy, reasoning, loop repair, instruction following or task utility.

Output-array SHA256 values are recorded after lossless BF16-to-F32 conversion. No response is sampled or decoded, and no raw logits or model weights are included in this publication package.

## Runtime, warnings and cost

The existing environment was Python 3.14.4, Transformers 5.20.2, Torch 2.13.0+rocm10.0.0, Safetensors 0.8.0 and NumPy 2.5.2. The ROCm build was used on CPU; accelerator visibility was disabled, every parameter and buffer was required to be on CPU, and Torch's accelerator-initialization flag remained false.

The process emitted two preserved warnings: causal_conv1d and flash-linear-attention are not installed, so Transformers uses reference PyTorch implementations. No package was installed. Finite output does not establish equality to the optimized kernels or original vLLM backend.

| Cost | Measured value |
|---|---:|
| Entire qualification wall time | 9.427264991 seconds |
| Entire qualification CPU time | 9.507730247 seconds |
| Peak RSS | 2,660,096 KiB, approximately 2.54 GiB |
| Base strict load plus weight verification | .866415 wall seconds |
| p50c strict load plus weight verification | .864313 wall seconds |
| Base single forward | .427626 wall seconds |
| p50c single forward | .081361 wall seconds |

The job had a 300-second wall limit, a 285-second driver alarm, and a 12-GiB virtual-address-space limit with the same RSS limit setting. It completed without timeout or cancellation.

The forward times are **not a performance comparison**: exactly one base forward precedes exactly one p50c forward, with no warmup, randomized order or repeated latency design. First-use and library/cache effects are confounded with variant order. Do not report the ratio as editing speedup. The complete timing also includes imports, meta planning, input hashing and provenance checks on already cached files.

All 18 export files, including the old export receipt, per-tensor manifest, models, tokenizer assets and configurations, retain their original full SHA256 and file-identity fingerprints. The five inspected framework files retain their hashes. Existing exports and their receipts were not rewritten.

## Evidence and reproduction

Publish these five files:

- qualify_framework.py: the exact executed driver;
- receipt.json: the original remote result, copied byte for byte;
- mapping_manifest.json: all 640 per-variant source-to-target tensor mappings, shapes, dtypes and raw hashes;
- qualification.json: durable process result, exact stderr warnings and version-bound transfer hashes;
- this README.

The executed driver SHA256 is:

```text
d4ff765d249b6fee60e619ea90af3f2b00e54468c9601006ed962dc1e7c994f0
```

The receipt SHA256 is:

```text
8cd96da30ae00a4fe8c327db646ece3f7a6e65fe8ba17da502b2fdb27a73d5e1
```

The mapping manifest SHA256 is:

```text
df892a3746e7c1f96a896b27f3f858967d35fba7687560de412e6d032d9047e2
```

Use the exact prior export snapshot and an environment matching the recorded versions and five inspected source hashes. The driver fails before model execution if these inputs differ:

```bash
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
PYTHONDONTWRITEBYTECODE=1 TOKENIZERS_PARALLELISM=false \
HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
CUDA_VISIBLE_DEVICES= HIP_VISIBLE_DEVICES= ROCR_VISIBLE_DEVICES= \
python -B qualify_framework.py \
  --exports-root /absolute/path/to/qualified-export-snapshot \
  --output-root /absolute/path/to/a-new-private-qualification
```

The prior export receipt is itself a frozen input: its SHA256 includes the original build's timing, so a fresh export build's new receipt will differ even when all tensor bytes match. Preserve a fresh build's receipt. To replay this historical qualification independently, prepare a separate input snapshot using the reproducibly rebuilt model files, published frozen export reference receipt and deterministic tensor manifest; the archived receipt remains a reference artifact and must not be represented as the new build's cost receipt. No overwrite of the original or fresh build's provenance record is required.

This driver deliberately validates the exact recorded input snapshot, not arbitrary future models or framework versions. Runtime timing and logits may differ on another hardware/runtime build; strict weight provenance and finite-output conditions must still hold.

## Remaining boundary

Still unverified are long-context loading/decoding behavior, KV-cache operation, author chat-template/thinking/EOS semantics during generation, vLLM execution, MTP generation, complete benchmark preparation, absent original grading dependencies, and MATH-500/GSM8K/IFEval outcome replication. This qualification creates no new evidence of improved capability, end-to-end Hepta value or superiority to training.

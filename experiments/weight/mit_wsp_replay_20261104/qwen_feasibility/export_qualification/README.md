# Qwen base/p50c text-weight export qualification

Date: 2026-11-04. Result: **passed_file_identity_only**.

This closes the isolated weight-export step identified in the earlier feasibility inventory. It does not close generated-answer evaluation or establish framework loading compatibility. The earlier inventory is a record of the state before these exports; its missing standalone export item has now been addressed under the explicit contract below.

## Actual operation

Using the already cached and rehashed Qwen/Qwen3.5-0.8B revision `2fc06364715b967f1860aea9cf38778875588b17`, a new private directory received two exports. The fixed original `apply_edit.py` and `st_numpy.py` came from RikiyaT/lm_understand-logs commit `4d09ba6d6a7e891dd8063974dfe81b3d78e3494f`. The author script was executed unchanged.

The source checkpoint contains 320 tensors under `model.language_model.*`, 15 tensors under `mtp.*`, and 153 visual tensors. This export **removes only `model.visual.*`**, preserving all 335 remaining tensors and their original names. Keeping MTP is an explicit conservative choice: the published text configuration still declares `mtp_num_hidden_layers=1`. The author's original full text-export tensor list and complete file hash are not published, so exact identity to that unpublished export is not claimed.

No separate lm_head tensor exists in the source. The published `tie_word_embeddings=true` setting is retained. The author's config, generation config, tokenizer config and chat template are copied byte for byte; tokenizer.json, vocab.json and merges.txt come from the pinned base acquisition. All shared fields of the base text_config and published text config match. Published extra/default fields are recorded in receipt.json.

The exported base is processed by the original author's p50c edit script. No model class is instantiated. There is no Torch import, GPU initialization, generated answer, optimizer step, package installation or live checkpoint change.

## Verified result

| Artifact | Bytes | Whole-file SHA256 |
|---|---:|---|
| Base text-weight export | 1,545,740,112 | `e9f6dd9e3636887f8bb04a467241c894af8828fd548c3d8f627a386ccf2a4765` |
| p50c text-weight export | 1,545,740,112 | `6a211ed8a9b0b977c13889c3fd4f14dabeaee779ea001dd01f17c899877a0374` |

All 335 base tensors match the source checkpoint in dtype, shape and raw-byte SHA256. The edited export changes exactly the two expected BF16 matrices:

| Layer | Shape | Changed BF16 entries | Edited tensor SHA256 |
|---|---|---:|---|
| 15 mlp.down_proj.weight | 1024 x 3584 | 65,260 | `82e2d733ea64feaeb4af93a1e065641d3df98b494a8b7576ef2f52e90fe2ee53` |
| 19 mlp.down_proj.weight | 1024 x 3584 | 64,928 | `8ef3c61bc36af113ad58e89dbb0a4a14dcba5a45cb750c15ab515c82ddd12eb2` |

The total is 130,188 changed values. Both edited hashes match the author's manifest. All 333 other exported tensors are unchanged: 318 other main language tensors and all 15 MTP tensors. tensor_manifest.json records every retained tensor, not only the changed ones.

All seven input asset files were rehashed before and after execution, and their device/inode/size/mtime/ctime fingerprints stayed unchanged. The two author scripts and four published configuration/template files were also rehashed. The remote process exited 0, produced no stderr, and has a complete durable terminal result. Local receipt and tensor-manifest copies were checked against the remote full-file hashes; the three tensor-manifest chunks were version-bound.

## Measured cost and limits

- Driver wall time: **7.113290498 seconds**.
- Driver self CPU: **6.070490411 seconds**.
- Child author-script CPU: **1.054033 seconds**.
- Total recorded CPU: **7.124525695 seconds**; the few-microsecond difference from separately displayed components is due to sequential CPU-clock reads.
- Peak parent RSS: **3,057,252 KiB**. Peak child RSS: **3,061,436 KiB**. These are separate peaks, not summed concurrent memory.
- Whole private run directory after completion: **3,137,516,675 bytes**, below the 5,000,000,000-byte budget.
- Execution wall cap: 900 seconds; process address-space cap: 12 GiB.
- Private directory modes: 0700; weight file modes: 0600.

The environment was Python 3.14.4 and NumPy 2.5.2 on Linux. Original author-edit execution itself took about 1.055 wall seconds. Per-phase timings, including repeated source and output hashing, are in receipt.json.

This is file transformation and integrity verification on already downloaded, recently read assets. The filesystem cache was not flushed. It excludes the original model download, environment construction, Agent work, framework initialization and any generation or scoring. These timings cannot be used as inference throughput, training speedup, or a complete WSP cost comparison.

## Reproduction

The reusable implementation is export_qualify.py. It enforces fixed SHA256 values for every required source asset and all six author source/config files, a new output directory, the 900-second deadline, predicted and actual output-byte bounds, exact tensor preservation and before/after source identity.

Provide a reference root with this layout, as produced by the existing pinned MIT Qwen replay acquisition:

```text
reference/
  base/
    model.safetensors-00001-of-00001.safetensors
    config.json
    tokenizer.json
    vocab.json
    merges.txt
  source/
    edit.npz
    manifest.json
```

The base files come from [the fixed Hugging Face revision](https://huggingface.co/Qwen/Qwen3.5-0.8B/tree/2fc06364715b967f1860aea9cf38778875588b17); the edit comes from [the fixed author's p50c edit directory](https://github.com/RikiyaT/lm_understand-logs/tree/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp8_math/runs/p50c/edit). Every required hash is in the driver and receipt.

Acquire the six small files identified in author_source_manifest.json into a local author_source directory, preserving the listed paths. Each entry gives a fixed raw URL, byte length, Git blob SHA1 and SHA256. The driver verifies the SHA256 values again before executing any original code. Do not run against a moving branch or overwrite an existing export directory.

With the original NumPy environment available:

```bash
OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
PYTHONDONTWRITEBYTECODE=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
CUDA_VISIBLE_DEVICES= HIP_VISIBLE_DEVICES= ROCR_VISIBLE_DEVICES= \
python -B export_qualify.py \
  --reference-root /absolute/path/to/reference \
  --author-source-dir /absolute/path/to/author_source \
  --output-root /absolute/path/to/a-new-private-export
```

The output contains base/, p50c/, receipt.json and tensor_manifest.json. An enclosing operator must also enforce the declared job timeout and address-space limit, as done in this execution. Source hashes and the exact executed driver hash bind the run. Timing and resource fields naturally differ on another host; tensor hashes must match.

## Publication and remaining blockers

Publish only this README, export_qualify.py, author_source_manifest.json, receipt.json, tensor_manifest.json and qualification.json. No model weights are included in this local package. The remote raw weights remain private. The local author_source cache and source_bundle.json are transport/cache files and need not be vendored.

Original experiment code is MIT-licensed; experiment logs/edits use the release's CC-BY-4.0 terms. The Qwen model card identifies Apache-2.0. Preserve upstream notices if redistributing their files; this package publishes hashes and download identities instead of the original weights or source bundle.

Still open: vLLM/runtime readiness; missing original mcqa and IFEval grader dependencies; complete pinned benchmark inputs; grading compatibility; actual model loading and 34,816-context support; measured generation throughput and allocation; the full 11,440-answer base/p50c comparison; and original Astra rediscovery. None of those are implied by this successful file-level qualification.

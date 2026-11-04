# Qwen generated-answer replay: read-only feasibility audit

Date: 2026-11-04. Status: **blocked before generation**.

The exact public Qwen base weights and p50c edit remain available on the host that ran the earlier Hepta teacher-forced audit. Both full file SHA256 values were recomputed during this inventory. A new download of the 1.75 GB checkpoint is unnecessary. The existing runtime and public evaluation release do not currently form an executable, version-pinned MATH-500/GSM8K/IFEval replay. No new model was loaded, no generated answer was produced, and no existing environment or model was changed.

This is an inventory and reproducibility audit. It is not a new Qwen benchmark measurement or a new Astra discovery run.

## What was positively verified

The existing acquisition receipt binds Qwen/Qwen3.5-0.8B revision `2fc06364715b967f1860aea9cf38778875588b17` and RikiyaT/lm_understand-logs commit `4d09ba6d6a7e891dd8063974dfe81b3d78e3494f`.

| Artifact | Bytes | Recomputed SHA256 |
|---|---:|---|
| Complete source checkpoint | 1,746,942,600 | `04b1c301231dd422b8860db31311ab2721511346a32cb1e079c4c4e5f1fe4696` |
| Released p50c edit.npz | 387,619 | `e92a92aafd1f1068b4fd94aa0fbe081ba3ddea2047ee7bcac7161d861be299e7` |
| Existing acquisition receipt | 6,831 | `da715cf857d6bf31c612c1389c91690f6ee3ae79f3df9fac8f1ba4f0cb18e8d7` |
| Earlier raw teacher-forced report | 8,938 | `88bdfa3226d624e195474bba786034e4c498ce061453b44745a58c5b3f2cc521` |

All seven Python source files associated with the earlier replay match their identities in that report. The report used 28 teacher-forced forwards on 14 diagnostic contexts and generated zero tokens. The successful mechanism-level result therefore does not close the requested generated-answer benchmark result.

There is no standalone edited full checkpoint in the inventoried replay directory. The base and small published edit are sufficient to reconstruct its edited tensor bytes. The prior replay validated the two affected BF16 tensors against the author manifest; this inventory rechecked the full base and edit file hashes without loading a neural network.

The independently downloaded evaluation source audit covers 12 public files, 62,188 bytes. Their byte lengths and Git blob SHA1 values match the complete pinned repository tree; source_manifest.json additionally records SHA256. These include the original evaluation implementation, math grader, checkpoint builder, edit rebuilder, model configuration, and author aggregate/shard results.

## Exact blockers

### 1. The available model runtime is not the original generation environment

The original replay environment currently exposes:

- Python 3.14.4, Torch 2.13.0+rocm10.0.0, Transformers 5.20.2, NumPy 2.5.2, Safetensors 0.8.0, Tokenizers 0.23.3, Hugging Face Hub 2.4.0.
- No installed or importable vLLM, datasets, math_verify, or weightenv.
- No installed PyArrow, NLTK, langdetect, absl-py, or immutabledict.

This was checked with standard-library package metadata and top-level module specification lookup, including inherited system packages. Torch was not imported and no accelerator context was created. The environment uses system site packages, so checking only its own package directory would have incorrectly reported Torch and NumPy missing.

The other known weight-workbench environment on desktop has Torch 2.6.0+cpu, NumPy 2.2.6 and Safetensors 0.5.3. It has no Transformers, vLLM, datasets, math_verify, or weightenv.

The existing Qwen adapter is a teacher-forced provider with bounded batches/sequences and use_cache=False; it does not implement the author's generated-answer evaluation. A new Transformers generation runner would be a separately validated port, with sampling/kernel/version differences, rather than an unchanged execution of the released vLLM evaluator.

### 2. The public evaluation code exists but its dependency closure is incomplete

The released [evaluate.py](https://github.com/RikiyaT/lm_understand-logs/blob/4d09ba6d6a7e891dd8063974dfe81b3d78e3494f/exp8_math/code/evaluate.py) imports `weightenv.lmo.tasks.mathqa`. The released mathqa.py in turn imports `mcqa.loop_signals` through either a package-qualified or local fallback path. The import occurs at module initialization.

The complete pinned upstream tree has 9,813 entries and is not truncated. It contains no weightenv directory, mcqa.py, or instructions_registry.py. IFEval grading in evaluate.py imports `weightenv.lmo.tasks.ifevalg.instructions_registry`, which is also absent. No exp8_math requirements or dependency lockfile is published.

This distinguishes a published reference implementation from a self-contained evaluation package. Obtaining the missing original modules or writing an explicitly documented compatibility port is necessary even before invoking the released evaluator's prepare command.

The original Astra agent's weightenv forward/discovery service is also absent from the public release. That prevents an unchanged editor-discovery replay. It is a separate issue from reproducing already published edits and should not be used to imply that outcome replay is inherently impossible.

### 3. Complete benchmark inputs and exact dataset pins are missing locally

The known replay directory has 62 files after excluding installed package trees. It contains the short teacher-forced diagnostic request, manifests, source code, tokenizer assets, and model weights; it contains no benchmark directory, MATH-500 test file, GSM8K test file, or IFEval input file. No standard Hugging Face model/dataset cache was found in the inspected host locations.

The complete public exp8_math tree has no bench directory. The published prepare() function obtains MATH-500 and GSM8K from Hugging Face without revision pins. It does not prepare IFEval. Released practice/train data and archived first-sample model answers are not substitutes for these benchmark inputs.

A future replay can acquire the full public inputs, pin the obtained revisions, and check row IDs/order against author per-problem logs. Exact original input-file identity cannot currently be claimed because their hashes/revisions were not supplied in this release.

These are bounded negative findings for the named replay roots and cache locations, not an exhaustive assertion that no copy exists anywhere on any disk.

### 4. The original text export and generation configuration need reconstruction

The cached Hugging Face model uses Qwen3_5ForConditionalGeneration, with the visual component present. The author's published text export configuration uses Qwen3_5ForCausalLM and model_type qwen3_5_text. Its model/generation configuration records Transformers 5.17.0.

The released apply_edit.py explicitly supports reading the full base file and validates the exact edited language tensor hashes. An isolated text-only base and p50c export can therefore be constructed from the cached source, but must preserve the published tensor naming, tokenizer, chat template, EOS behavior, and generation configuration. No such export was created in this read-only inventory. The configuration version is evidence about its serialization provenance, not a complete declaration of the author's evaluator environment.

### 5. A full comparison has a material, currently unallocated generation budget

The observed author shard files confirm protocol think35: BF16, thinking enabled, seed 0, temperature 0.6, top_p 0.95, top_k 20, presence_penalty 1.5, and at most 32,768 new tokens. The code sets max_model_len to 34,816.

| Dataset | Problems | Samples/problem | Answers per variant |
|---|---:|---:|---:|
| MATH-500 | 500 | 4 | 2,000 |
| GSM8K | 1,319 | 2 | 2,638 |
| IFEval | 541 | 2 | 1,082 |
| Total | 2,360 | — | 5,720 |

Base plus p50c requires **11,440 answers**, with a combined ceiling of **374,865,920 generated tokens**. Multiplying the author's published mean token lengths by these sample counts gives approximately **246,672,017 actual author-run tokens** across the three datasets. This is arithmetic on published results, not a throughput or cost measurement on a local host.

The original replay host was observed with 32 CPUs, roughly 110 GiB available system memory, and a Radeon 8060S at 0% GPU utilization. Its driver reported 4 GiB dedicated VRAM; system/shared memory availability does not establish support for the required vLLM kernels or 34,816-token context. Desktop showed an RTX 4060 with about 8 GiB VRAM, 20% GPU utilization and CPU load around 22 while other qualification work was active.

A bounded inventory of six configured host aliases identified no better ready-made Qwen replay environment. The live training host was excluded. These point-in-time observations are not a compute reservation or evidence of sustained idle capacity.

## License and publication scope

The pinned [Qwen model card](https://huggingface.co/Qwen/Qwen3.5-0.8B/blob/2fc06364715b967f1860aea9cf38778875588b17/README.md) identifies Apache-2.0. The MIT experiment release distinguishes MIT-licensed code from CC-BY-4.0 experiment logs/data. The official [GSM8K dataset card](https://huggingface.co/datasets/openai/gsm8k) identifies MIT, and the official [IFEval dataset card](https://huggingface.co/datasets/google/IFEval) identifies Apache-2.0.

No license statement was found on the inspected [MATH-500 dataset card](https://huggingface.co/datasets/HuggingFaceH4/MATH-500). That is an unresolved provenance check for future redistribution, not a claim that ordinary evaluation is prohibited. No benchmark data or model weights are redistributed by this audit.

Only README.md, inventory.json, source_manifest.json and closure_protocol.md are intended as possible public evidence. private_evidence.json contains operational paths and host inventory and must not be committed. The upstream source copies are an audit cache and need not be vendored; source_manifest.json supplies exact acquisition identities.

## Acceptance boundary

What is closed: existing Qwen asset location and identity, previous source/report identity, known runtime dependency inventory, public evaluator dependency audit, benchmark/protocol accounting, and an explicit closure protocol.

What remains open: fresh full MATH-500/GSM8K/IFEval generated-answer results, a compatible isolated generation runtime, missing grader/data preparation components, exact original dependency/data provenance, safe measured compute allocation, and independent rediscovery of the edit.

No score improvement, end-to-end Hepta value gain, or advantage over gradient training is inferred from this inventory.

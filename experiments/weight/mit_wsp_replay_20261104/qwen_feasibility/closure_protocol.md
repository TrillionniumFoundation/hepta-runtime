# Conditional closure protocol for the Qwen outcome replay

This file is a proposed protocol, not authorization to launch a job. The prerequisite audit is currently failing. No generation run was started.

## 1. Complete and freeze evaluator inputs

Use source_manifest.json and the pinned public experiment commit. Reuse the locally verified full base checkpoint and edit.npz. Keep the source files read-only and place any reconstructed exports in a new isolated directory.

Obtain the absent mcqa.loop_signals and IFEval checker modules from the original authors, or implement a separately named compatibility port. If porting, preserve the released math answer extraction, math-verify behavior, IFEval strict prompt-level checks, removal of the thinking prefix, and treatment of missing </think>. Document every change from the pinned evaluate.py. Do not describe a compatibility port as the untouched original harness.

Record exact Python, Torch, vLLM, Transformers, math-verify, SymPy and checker revisions. A new environment or package installation needs a separately scoped task; never alter an environment currently used by the user's experiments.

Acquire and hash the complete MATH-500 test split, GSM8K main test split, and 541 IFEval rows. The published preparation function provides the math/GSM row mapping but omits IFEval. Reconstruct its schema explicitly. Match problem IDs and ordering against the public per-problem logs, and preserve benchmark-specific notices. Resolve the MATH-500 redistribution provenance separately; code can reference a user-acquired dataset without publishing its contents.

Create isolated base and p50c text exports from the verified Hugging Face source. Use the published text config, tokenizer config, chat template, EOS token and generation config. Assert that the two edited BF16 matrices match the published edited hashes and that every other included language tensor matches the base. Record the resulting full checkpoint/export manifests and byte hashes. Never modify the cached original weights.

Before generating new answers, run the candidate grader over archived public responses, comparing results where the released records permit a direct comparison. Note that first-sample-only archives cannot establish equality of all four-sample aggregate outcomes. Test the documented extraction/IFEval edge cases. Do not tune the weights on evaluation results.

## 2. Allocate and measure bounded feasibility separately

After all input and environment checks pass, send the exact host, runtime/image identity, request, wall cap, token cap, memory/disk limits and cancellation method to the root agent for budget allocation. A snapshot of low utilization is insufficient.

A possible first qualification, subject to that allocation, uses the first canonical problem ID from each of the three frozen benchmark inputs, the author's sample count, both variants and the original 32,768-token cap: at most 16 generated answers and 524,288 generated tokens. It must have an explicit wall limit (for example 30 minutes) and stop cleanly at the first resource violation. Any interrupted item is recorded incomplete, never converted into a wrong or correct completed answer. This stage measures loading, context support, decoding throughput, memory and cancellation; it cannot support a benchmark-efficacy claim.

Do not shorten the generation cap or disable thinking to obtain a quick apparent success. If the selected host cannot complete the qualification within the allocated budget, report the measured limit and use it for scheduling. Do not replace the benchmark with easier questions.

Calculate prospective full-run time from measured completed-token throughput, including the fact that the base model frequently reaches the token cap. Keep startup, prompt prefill, decode, evaluation and I/O costs separately visible. Request a new explicit full-run allocation if the resulting budget is materially larger.

## 3. Run the complete outcome comparison

Freeze both variants before any generated benchmark results are observed. Use:

- protocol think35; BF16; thinking enabled; seed 0;
- temperature 0.6, top_p 0.95, top_k 20, presence_penalty 1.5;
- 32,768 maximum new tokens and 34,816 maximum model length;
- original math prompt construction and IFEval prompt handling;
- MATH-500: 500 problems x 4 samples;
- GSM8K: 1,319 problems x 2 samples;
- IFEval: 541 problems x 2 samples.

Run base and p50c on the same frozen data and backend configuration. Preserve original shard ordering/counts when reproducing author results; changing batching, kernels, RNG behavior or shards can affect stochastic samples and must be reported. Do not promise bit-identical generated text across different hardware or runtime versions.

A single comparison requires 11,440 complete answers. Retain the exact input IDs, sample indices, seeds, completion status, generated-token counts, finish reasons and scores. Store raw responses in private experiment outputs if dataset/response redistribution rights are not settled. Checkpoint progress at shard boundaries, bind every result to input/checkpoint/harness hashes, and resume only the same immutable run.

Report per-dataset avg@n accuracy, strict IFEval prompt-level accuracy, truncation/finish rate, generated-token totals, wall/CPU/GPU time, peak memory and energy only where actually measured. Use paired problem-level uncertainty for the score differences. Score and termination improvements must be separately visible because the original reported gain is strongly associated with reduced reasoning loops.

Compare to published scores as a replication target with runtime differences disclosed. This task compares base and published direct edit. It does not constitute a compute-matched comparison against fine-tuning; any training baseline needs a separate frozen data/optimizer/compute budget and the same evaluation.

## 4. Verification and completion criteria

A run closes the outcome replay only if all full datasets finish, every output is bound to the frozen inputs/source/runtime, no grader or missing-result checks fail, and the independently computed score/cost report is reproducible from retained artifacts.

If any prerequisite, allocation, runtime, dataset or completion check fails, preserve an exact blocker receipt. Partial feasibility, teacher-forced log-probability changes, a few decoded answers, or public author aggregate reanalysis remain useful evidence with narrower labels. None is a substitute for the full generated-answer replication.

A successful replay of p50c still does not reproduce the original Astra discovery process or establish autonomous improvement on Hepta Neuron. Those are separate experiments.

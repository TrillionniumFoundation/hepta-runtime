# P0: actual Pocket4 model, frozen checkpoint and diagnosis

Audit date: 2026-11-04 UTC (2026-11-03 America/New_York). Status: **frozen-byte audit PASS; causal model repair and financial acceptance HOLD**.

## What actually runs

The configured LAN alias `pocket4` resolves to host `alex-G1628-04`. Read-only process, guard, status, completed-job and source inspection found Laya resident feed/predict/evaluation services and Current100k shadow/forward services. At the captured status there was **no running gradient job**: ADMITTED 0, COMPLETED 109, FAILED 2, RUNNING 0. The resident state was `EVALUATING_BOUNDED_CANDIDATE_QUEUE`, with `HOST_FULL_MEMORY_PSI_PRESSURE` also present. Guards being alive is not evidence of active backpropagation.

The newest completed Laya job is `d1811327c96cf149b546e5b87a227c9d5fecaec3095339f2d2abc12378ed7ac2`; candidate `4fd5adf062c48f2f4afdc7f2895270e1525310bb0dba1387e3a23c7d19496c47` comes from fixed parent `76d6b1bf3d1b00505277c88a6d93159f3f17fe2511a65f21fc99647cf56b8ff6`. Completed jobs are independent bounded episodes from that parent, **not 109 cumulative full-model training updates**.

The loaded family is `convaiinnovations/laya-multilingual`, revision `e4e9ddf21a7b1903b7acffd8814ad4307bf63a67`, using `jhu-clsp/mmBERT-base` / ModernBERT (22 blocks, width 768). The frozen model contains 321,908,998 stored parameters in 170 tensors. Files store F16; the pinned runtime explicitly widens them to F32. Only 2,379 LoRA factors are trainable, targeting at most 3,968 effective weight coordinates:

- `scorer.1`: four selected rows, rank 2, A `[2,768]`, B `[4,2]`.
- `scorer.3`: one row, rank 1, A `[1,768]`, B `[1,1]`.
- `act_head.2`: rank 1 on only the first 64 input columns of the original `[2,256]` layer, A `[1,64]`, B `[2,1]`.

The action labels are **ACT / ESCALATE based on frozen-parent answer correctness**, not BUY / SELL and not financial return. The training price target is a seven-class 300-second future-mid interval. No inspected tensor/graph connects this deployed family to the R19 analytic CTMC or the Hepta Clocked/First-Passage Cell. They must remain separate experimental lineages.

## Freeze identity and limits

143 files, 689,324,215 bytes were copied to a new operator evidence directory; each expected digest, source stability during copying and copied digest was verified. Files include original base and configuration/tokenizer, parent/candidate adapters and manifests, the actual selected training data and closed-action source, exact runtime source files and native binary, job configuration/log, and the Current100k frozen head/features. Original/live weights were not overwritten.

| Identity | SHA256 / pinned value |
|---|---|
| Full capture manifest | `4890a35204e8b26cae0888602fed5940b89543522ff8094de21287467ae1baa2` |
| Tensor-statistics record | `f7b34ff67ce0aba91a224a61b7d4e39528d2a2c29849ee3c3370774d59fb53fc` |
| Base model file | `9d628fd971b700382ac6f65920a86f149777b2e748e0c955fb3b19695aa8f204` |
| Latest candidate adapter | `8fa37e66e7466942b26376da00ef0afcb34ba1bebf5f6eba2324bc7237db1791` |
| Training dataset | `638e1931a81cdcb4df76e017e6f27fe360ba0a9eb7889e0ae35fe1a553fc4724` |
| Current100k 769-element F32 head | `1f3071b3b1aaa89966b2d72abb2aec3f0841e2eb9bb24964abc54f30ac22b759` |
| Laya model code commit | `a4a8921afebfd852bba0000475cfb6ab737a124c` |
| Training / action initialization seeds | `20261007` / `2026100801` |

The completed job does **not** persist optimizer state or an RNG checkpoint, and does not record a Git commit for its runtime release. Exact runtime file hashes and release identity were preserved instead of inventing a commit. Consequently this is a reproducible completed-artifact baseline, not a claim of exact mid-job training resumption. Full private raw artifacts stay on the original host; this repository report contains aggregate findings only.

## Weight and objective observations

All 321,908,998 base values, 2,379 candidate factors, 2,313 parent factors and 769 Current100k head values were inspected for finiteness: **zero NaN/Inf**. Small readout SVDs and row/column statistics show no zero-row/column collapse in the inspected heads. The base 768×768 scorer matrix has numerical rank 768; its singular range is approximately 7.43088 to 0.000206465. Ill-conditioning alone is not a causal defect. Dead activations cannot be excluded from weights alone; this audit did not run new full-backbone causal interventions on the shared host.

The latest price episode uses 32 unique rows, 4 epochs, 128 presentations and 64 AdamW steps; the independent action sample contains 40 unique balanced ACT/ESCALATE labels and receives 80 steps. Adam state is continuous within an episode but reset for the next job.

| Same 32 training rows | Brier | Meaning |
|---|---:|---|
| Frozen parent raw | 0.9788007084 | Baseline on fitting rows |
| Child raw | 0.9781589713 | Small improvement after 64 steps |
| Uniform | 0.8571428571 | Simpler comparator is better here |
| Fitted training prior | 0.6910749507 | Reuses those labels |
| Calibrated child | 0.6899867824 | Closed-form calibration on those same labels |

CE changes 2.3226848692 → 2.3207219578. Raw probabilities average 28.8% on a class that has zero examples in this 32-row sample, and 7.97% on the class containing half the targets. The existing calibration contracts the centered raw prediction to a model weight of 0.08900946 and is largely prior driven. None of these figures is independent efficacy. Label-fitted closed-form calibration is not zero-feedback circuit repair and does not become a weight edit merely because it has no backward pass.

The evidence supports a **task/interface/calibration mismatch and insufficient independent objective validation** more strongly than damaged or nonfinite weights. The fact that the fitted prior wins on fitting rows cannot prove that market inputs contain no signal. Nor does an ACT/ESCALATE improvement prove a profitable trade policy.

## Separate Current100k evidence already available

[Runtime PR88 source](https://github.com/TrillionniumFoundation/hepta-runtime/tree/1f2d3d782e8803e769989234e7902ca5c04eff97) and [Trader source](https://github.com/TrillionniumFoundation/heptatrader/tree/fd3f1302ff7ae84d2a2ad1a06d5a84eafaa63ac7/research/weight_edit) describe a distinct 54-row development study; these were reviewed, not presented as new independent measurements here.

The original scalar head prediction standard deviation is about 0.005976 USD; normalized feature cosines are 0.986923–0.999349. Within those measured features, a head norm ≤0.1 bounds predicted standard deviation by 0.354269 USD. This is an observed representation/head-gain bottleneck on that sample, not proof that all target variation (about 23.27 USD) is predictable.

Earlier mean/bias correction lowers development RMSE 23.379921 →23.263678; constrained analytic readout and an 8,192-step SGD control both reach about 23.223326. Later forward-time development folds reject the newly fitted arms. Latest dose analysis attributes 99.9999328% of displacement energy to a mean shift reproducible by bias. None establishes a new state-dependent circuit or editing superiority over adequately optimized training.

Block 12 has an unusually dominant common MLP direction and reduces intermediate dispersion, but later blocks recover differences. Limited activation interventions did not establish predictive gain. Therefore Qwen-style deletion of a repeated-feature direction is not justified solely by a large norm or a visually dominant singular vector.

## Financial-source blocker is independently identified

The current strict reviewer reports source replay incomplete. Pure read-only accounting replay localized it to `SUBMITTED_COMMAND_WITHOUT_FILL_OR_ZERO_FILL_PROOF`: one submitted command has no recorded fill and no accepted zero-fill terminal proof. This is not a tensor fault. The detailed read-only report is in `docs/weight-runtime/p0-replay-20261104/SOURCE_REPLAY_DIAGNOSIS.md` in the companion submission.

Fourteen retained commands are marked CENSORED because current source evidence is not verifiable; that does not mean fourteen trades were lost. The actual broker state was not checked by this audit, so the order cannot be called unfilled or canceled from the journal alone. No order, journal repair, fabricated zero-fill proof or denominator change was sent.

The registered Current100k window ends 2026-11-17 10:49:25.673 America/New_York, with settlement ending 2026-11-18 10:49:25.673. It is not complete at this audit date. Source recovery alone would not satisfy model acceptance. Net returns, drawdown, turnover, exposures, leakage checks and time-out stability remain **HOLD**.

## Falsifiable next decisions

1. **Representation/head hypothesis:** freeze content encoder and use the same time splits to compare prior, bias, centered head, direction edit and adequate SGD at the same norm/budget. Require variation beyond a mean shift and independent task gain. Existing evidence fails this requirement.
2. **Loss/controller hypothesis:** compare the original price and ACT objectives with an independently measured continuation/trade utility evaluator. Do not redefine labels as financial PnL.
3. **Circuit-interference hypothesis:** identify a direction from probe-only activations, use matched perturbation controls, then evaluate sealed future data. Large magnitude alone is insufficient; no new production backbone edit is justified now.
4. **Timing/execution hypothesis:** separate model inference timing from host admission pressure and source-event completion. A model cannot generate missing broker evidence.
5. **Information/structure hypothesis:** test causal information availability and stronger frozen ordinary baselines. If inputs omit the necessary target information, no local weight edit can restore it.

The defensible current answer is not one exclusive proven cause. It is a hierarchy: **known source-evidence blocker; observed task/calibration/representation limitations; unproven local defective neural circuit**. The first actual Hepta weight repair is therefore tested on the separately identified R19 research checkpoint, where the physical clock has a verifiable mathematical meaning.

## Audit execution cost

Baseline copying plus numerical inspection: 8.598778 wall seconds, 3.889097 CPU seconds, peak RSS 404,300 KiB, no GPU initialization and no new training. These are this audit worker's costs only. The latest original Laya training receipt reports 96.924957 seconds, about 1.592 GB peak allocated GPU memory and 1.984 GB process RSS; these different workloads do not support a speedup or energy-saving ratio. Energy was not measured.

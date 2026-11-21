# Native finite event-history qualification, contract v2

This isolated research crate reconstructs and propagates the finite 33-state law in five existing Hepta Neuron checkpoints. It adds an explicit 163-state joint distribution over the current physical node and the history of outer-boundary hits and endogenous resets. Contract v2 distinguishes a current-endpoint sign score from the task's fixed-deadline submission value. The implementation passes a fixed, source-bound comparison against an independent dense matrix-exponential oracle. It does not edit checkpoint weights, change the original endpoint classification objective, or establish trading returns.

The existing HeptaRuntime `rea_model` owner remains the intended production owner. PR141 supplies prior fixed-anchor composition research. This crate reuses the sibling source adapter and continuation research task contract; it adds no competing transaction owner or production route. Existing production registration, optimizer, service pointers, and trading state are outside its execution path.

## Scope and source identity

The admitted law source is the captured `frozen_joint/joint_law.py`, SHA-256 `2e7f19a2534567e31370eea24dec096a309e4db4aa42770efbf544bed84bcf65`. The associated task source is `joint_task.py`, SHA-256 `51139ba57004f2a5d69381af2f781b3717404318f122d8b6bec8416004efffa5`. Their exact captured bytes, checkpoint source pins, and semantic adapter profile are checked before native replay. The source manifest hash is a reviewed external input to the research command. Passing an arbitrary manifest and its self-reported hash does not establish independent owner authority or an attestation.

Relevant prior source was also inspected:

| Source | Actual meaning | Current native coverage |
|---|---|---|
| `frozen_joint/joint_law.py` | 31 interior grid nodes, two reference nodes, diffusion/drift motion, exponential recovery and a truncated Gaussian reset destination | The finite checkpoint generator and tagged event history |
| `frozen_joint/joint_task.py` | Six ticks; STOP, WAIT, READ, REPAIR, SUBMIT_0, SUBMIT_1; observation at request completion; fixed deadline endpoint target | Reuses the previous Rust task contract and checks every actual successor against the unchanged Python source |
| Prior `wsp_event_semantics_20261105/README.md`, private-ci commit `5669aa349fde9eb0b6692dbfaa55a1b9897f6e69` | Distinguishes endpoint, threshold crossing, outer competing causes, and reset history; REPAIR changes the sensor only | Provides the rationale for preserving event history; its old numerical results are not counted as new observations |
| `qualification/hcsn_differentiable/contract.py` | `OperatorTable.call` is a legacy interval-value engineering readout with a terminal feature; `risk` is not an independently specified financial put | Source audit only |
| `qualification/hcsn_differentiable/neural_control.py` | Neural retention/release problem with discounted gain and maintenance, release cost, and deterministic refractory delay | Source audit only; delayed cohorts and that control problem are not implemented here |

The model's coordinate is normalized `u`, with outer references at `u = -1` and `u = +1`. Its duration is checkpoint model time. Neither coordinate nor duration is mapped to a traded price, dollars, FX units, or wall-clock seconds.

## Generator and event semantics

The eight raw coordinates determine boundary scale, diffusion scale, input gain, drift bias, two reset centers, recovery rate, and reset spread. Native code reconstructs their original sigmoid/tanh transforms and all three drive generators. For interior spacing `dx`, the original nearest-neighbor rates are

```text
up   = sigma² / (2 dx²) + mu / (2 dx)
down = sigma² / (2 dx²) - mu / (2 dx)
```

Only the source's reference-to-interior contributions implement reset in this profile. Their total rate is the source recovery rate, with destination probabilities given by a truncated Gaussian. Native reconstruction uses eight-point Gauss-Legendre integration for those bins; the independent source reader uses SciPy `ndtr`. Stored and reconstructed generators must agree within `2e-10`. A nonzero stored contribution at a structural zero of the reconstructed source is rejected. This establishes the decomposition before tagging any transition. Jump length is never used as evidence of reset.

The actual admitted source has disjoint diffusion and reset source rows. A separate analytic control covers the more general case in which diffusion and reset contribute to the same physical edge: holding the total physical edge rate at 2 while varying its reset subrate leaves the endpoint law unchanged and changes the reset-history probability. Future profiles with overlapping mechanisms must preserve both contribution rates explicitly. Total generator entries alone do not identify them.

The joint basis contains only reachable combinations:

| History tag | Allowed current nodes | Count |
|---|---|---:|
| No outer hit | Interior | 31 |
| Lower first, no reset yet | Lower reference | 1 |
| Upper first, no reset yet | Upper reference | 1 |
| Lower first, reset seen, upper never hit | Interior or lower reference | 32 |
| Upper first, reset seen, lower never hit | Interior or upper reference | 32 |
| Both boundaries visited, lower first | Any node | 33 |
| Both boundaries visited, upper first | Any node | 33 |

These 163 nodes preserve the first cause, whether an endogenous reset occurred, and whether the opposite boundary was subsequently reached. They do not retain reset counts or exact event times. Starting at a reference node counts as first passage at time zero. The current production task's original prior has two interior atoms; an explicit known-state control checks the boundary atom.

The resulting first-passage quantities belong to this finite grid CTMC. No assertion of exact continuous-diffusion first passage, mesh convergence, or certified financial path pricing follows from this test.

## Belief, owner state, and decoder

Propagation uses native sparse uniformization with ascending, deterministic iteration order. The work envelope admits at most 256 states, uniformization rate at most 500, model duration at most 2, Poisson argument at most 500, and at most 1,024 terms. A geometric bound on the omitted Poisson tail must be at most `1e-15`; full mass normalization is checked within `2e-10`. Probabilities are not repaired by post-propagation renormalization. This is FP64 numerical validation; the tail calculation and Gaussian quadrature are not outward-rounded interval certificates for all floating-point error.

The existing owner state remains complete: tick, budget, pending request and due tick, sensor condition, last symbol/reliability, full observation history, elapsed model time, charges, terminal status, and submitted action. Every actual action/completion is passed through `hepta_continuation_runtime_study::task::successor`. Native code reconstructs the event belief from the full original owner history and compares it to the incrementally propagated joint distribution.

An observation multiplies every joint node by the original emission likelihood of its **current** physical node, then normalizes the whole joint distribution. It never renormalizes separate history channels independently. A known-state counterexample starts two one-hot distributions at the same physical `u=0` node: one has never hit a boundary; the other has hit the lower boundary and reset. They produce the same observation likelihood and remain distinguishable in first-hit/reset history after that same observation. An endpoint-only decoder cannot recover this missing history.

The admitted profile is `finite-checkpoint-renewal-history-163-f64-v2`; its decoder is `FIRST_OUTER_HISTORY_AND_CURRENT_ENDPOINT_SIGN_SCORE`. It reports first lower cause, first upper cause, no outer hit, reset seen, both boundaries visited, and the three endpoint masses above, at, and below zero. The first-cause partition includes survival. The endpoint partition includes the zero atom.

`current_endpoint_nonpositive_sign_score = 1 - 2 P(u_current > 0)` and `current_endpoint_positive_sign_score = 2 P(u_current > 0) - 1` score the supplied current endpoint only. They sum to zero. The source task always submits a prediction for `sign(X_6)`, so at ticks 1–5 these current scores are not its submission values. At tick 6 the sign target coincides, but these fields still do not represent a complete cost-adjusted action Q. Every result row records the current score tick, fixed task target tick, and `consumable_as_submit_or_continuation_q = false`. Both the legacy decoder name and `SUBMIT_Q` are rejected. These scores are not independent financial Call/Put outputs. `FinancialCallPut` is rejected because this source provides no authenticated contract defining a price coordinate, strike, expiry, discounting, settlement, or financial path labels. The separate HCSN engineering `call` readout also supplies no such contract.

## Fixed qualification and descriptive ablations

The frozen queue uses fits 11, 23, 37, 53, and 71. It takes index 0 of each checkpoint's existing TRAIN public schedules. Each schedule has two fixed legal histories: six WAITs; or the earliest two legal READs with observations 0 then 1, waiting otherwise. These are **ten previously available history inputs and sixty intervals**, with no new training, independent predictive holdout, or trading label.

The Python oracle independently builds the dense joint generator, propagates with `scipy.linalg.expm`, and compares the projected marginal to the checkpoint's stored 33-state transition tables. Rust rebuilds the source decomposition, executes the owner transitions, propagates the whole joint state, applies Bayes updates, and checks a JSON round trip for exact FP64 bits. Reconstructing from the owner history produced an identical joint vector. Original checkpoint bytes are re-read after replay and must remain unchanged.

| Check over the fixed queue | Observed maximum absolute error |
|---|---:|
| Native whole 163-state joint versus independent dense oracle | `4.010681e-15` |
| Native projected marginal versus source stored-table reference | `9.603429e-15` |
| Decoder values versus independent reference | `3.885781e-14` |
| Joint normalization | `9.325873e-15` |
| First-cause partition | `9.214851e-15` |
| Native source reconstruction versus stored generator | `2.220446e-16` |
| Native incremental versus full owner-history reconstruction | `0` |

Native intervals used 65–100 uniformization terms. The largest reported omitted-tail bound was `9.320733e-16`. WAIT and REPAIR, starting from the same failed-sensor state, produced bit-identical joint latent beliefs while the sensor flags changed as required.

The descriptive ablations use these same fixed states; they are not selected candidate weights or a new quality experiment:

| At the fixed deadline, across ten histories | Observed range |
|---|---:|
| Absolute error from substituting current reference-boundary occupancy for ever reaching either boundary | `0.190616–0.556118` |
| Reset probability erased by dropping the reset tag | `0.203786–0.660145` |
| Zero mass omitted by treating strict-above and strict-below as complements | `0.039549–0.043311` |
| Probability of having visited both boundaries | `0.004333–0.080140` |

Erasing history after reset preserves the current physical marginal within the fixed tolerance but loses event information. Across all sixty intervals the resulting joint L1 difference reaches `1.320290`. This demonstrates a representational requirement: an endpoint marginal and its pointwise readout cannot encode all these path events. An event-state augmentation or exact reconstruction from the complete law/history is needed before attributing this defect to individual readout weights. It does not show that the original endpoint objective improves when its target is replaced with a different event.

All v1 source, seals, and numerical results remain retained. The initial engineering replay changed two Clippy expressions without changing arithmetic order and made three frozen controls explicit. Independent review then found a real semantic error: both native and oracle had named current-tick sign scores as submission utilities despite the fixed deadline-6 target. Agreement between those implementations did not validate the target meaning. V1 semantic admission is therefore superseded; its source/propagation/event numerical checks remain useful references.

A frozen v2 amendment changes the profile, schema, decoder name, score fields, and explicit consumer restrictions. It adds no future propagation or model behavior. The v1 oracle input is translated into a new v2 reference with an exact structural round-trip check proving all original numerical payloads and owner states unchanged; no new matrix exponential is run. V2 native replay uses the same ten histories and checks the new scope declarations. Previous cache identities are not migrated or treated as v2 cache hits. Neither replay supplies additional independent samples or future workload.

Six analytic and admission unit tests pass with all features and with default features disabled. Formatting and Clippy with warnings denied pass in both feature modes. The initially failed Clippy receipt and the earlier disk-full build receipt remain in private evidence. The disk recovery removed only a recorded, reproducible Cargo incremental cache; it did not change captured data or production files.

## Costs and NDU boundary

The original v1 independent oracle already shares 23 operator builds across its 60 interval requests, producing 37 baseline cache hits. The cache audit is explicitly scoped to those v1 bytes; v2 changes the decoder/profile identity and gains no automatic cache admission from it. This existing reuse cannot be claimed as a new WSP saving. Its full-history results remain distinct. The native path performs additional history reconstructions and source validation; its measured subprocess time and the Python oracle's time therefore do not establish a matched end-to-end speed ratio.

Scientific subprocess CPU and wall limits are cumulative across the oracle, all native executions, metadata upgrade, tests, and descriptive readers. Compilation, including failed builds, is recorded separately. Exact process receipts and the cache audit remain private evidence. The scientific budget is 120 CPU seconds and 180 cumulative subprocess wall seconds; it is not reset for the qualification replay. Python supervisor and authoring overhead should not be silently equated with measured child-process CPU.

No priced future trading task, independently verified financial quality delta, or owner-defined general NDU resource exchange rate was established here. The general model decision remains **KEEP_ORIGINAL_AND_STOP**. This bounded study establishes a semantic prerequisite for a later justified task; it does not authorize adoption or more compute by default.

## Building the source-only publication

The intended layout is:

```text
qualification/weight_event_runtime_20261121
qualification/weight_continuation_runtime_20261121
qualification/weight_semantic_adapter_20261120
```

The latter two are real sibling dependencies from the stacked parent source changes. This crate has its own workspace. Rust 1.95 and the committed lockfile were used with the already available Cargo cache; no large dependency download was needed.

```sh
cargo test --locked --offline --all-features
cargo test --locked --offline --no-default-features
cargo fmt -- --check
cargo clippy --locked --offline --all-targets --all-features -- -D warnings
cargo clippy --locked --offline --all-targets --no-default-features -- -D warnings
```

The synthetic tests require no private checkpoint. The source-bound command requires separately supplied, reviewed private evidence:

```text
hepta-event-history-study SOURCE_MANIFEST MANIFEST_SHA LAW_SOURCE LAW_SHA ORACLE_INPUT INPUT_SHA
```

The publication copy uses the explicitly revised v2 oracle/reader contract. Its difference from those current local v2 scripts is limited to path/environment configuration; the unexecuted v2 oracle builder preserves the original numerical algorithm. Original scientific oracle bytes and source remain immutable. `HEPTA_EVENT_STUDY_DIR` explicitly names the directory containing the private frozen protocol and `evidence/` output directory. `HEPTA_EVENT_SOURCE_ROOT` names the root containing the captured `neuron_margin_experiment/vendor/frozen_joint` source. The optional subprocess measurer also requires `HEPTA_EVENT_RUST_BIN`, `HEPTA_EVENT_CARGO_HOME`, `HEPTA_EVENT_TARGET_DIR`, and `HEPTA_EVENT_CPU`. It uses create-only logs and the same finite work limits. The frozen protocol itself must bind the exact readable checkpoint and source paths in that research environment. It is not distributed in Git.

Publication does not include checkpoints, public schedules, oracle matrices, model-derived traces, financial records, or real input fixtures. Private evidence retains the original execution source and seals, the v2 amendment and native seal, all process receipts, the descriptive result reader, the independent cost audit, and a source-only publication diff. Local path configuration changes in the publication copy were not used to regenerate any scientific result.

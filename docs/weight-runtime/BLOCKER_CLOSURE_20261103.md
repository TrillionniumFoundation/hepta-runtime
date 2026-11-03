# Engineering blocker closure record: 2026-11-03

This record adds the subsequent engineering fixes, actual Pocket4 verification,
candidate sealing and registration preparation to
[SEVEN_PART_WORKBENCH.md](SEVEN_PART_WORKBENCH.md). It preserves the distinction
between a working experiment pipeline, a successful source replay and independent
future predictive evidence. Deployment, future-window completeness, financial
improvement and adoption are not established by the results below.

## Correctness changes and their scope

| Issue | Resulting behavior | Evidence boundary |
| --- | --- | --- |
| Provider left reachable after failed admission | The provider is published to the session only after identity checks, description and the admission record succeed. Failed admission closes the provisional provider and leaves the session closed. | Probe and patch cannot use a graph whose open operation failed. |
| Cleanup exception replaced the original admission error | Cleanup is attempted; a secondary cleanup failure is logged while the original admission failure is re-raised. | The failed first attempt remains in the evidence history. |
| Lower computation precision changed unselected parameters | Sparse edits and selected-column writer projections copy only their edited support back into an original-dtype parent clone. Noncontiguous input tensors retain their logical indexing. | Unselected parameter bytes remain unchanged, including FP64 values outside the FP32 computation range. Nonfinite edited or final stored values still fail. |
| Nearby doses could receive the same name | Dose names use round-trip precision, retaining the ordinary `dose-0`, `dose-0.5` and `dose-1` names. Distinct admitted doses retain distinct identities. | No candidate is selected or discarded by its development result. |
| Pre-storage orthogonality could disappear after rounding | The runner reports post-storage direction evidence using the realized selected delta only when exact compilation and the complete effective-change norm are established. Norm matching and directional orthogonality remain separate checks. | Zero deltas, failed directional checks and unverified reparameterized deltas do not count as verified orthogonal controls. Physical factor directions are not asserted. |
| Admission-only source checks missed later file changes | Qualification performs a final audit after close of declared source files, the complete Python source tree and every pinned base-manifest file, including file sizes. | Qualification cannot pass when these identities changed during execution. |

These changes concern the existing Python worker and qualification path. The
results here do not claim a fresh Rust build or new Rust qualification. Previously
sealed mechanism reports retain the fields and qualifications they actually
contained; later runner improvements do not retroactively add post-storage
orthogonality evidence to old artifacts.

## Actual test batches and model parity

The r2 batch executed in the existing Pocket4 environment and passed all
**171 tests**:

| Suite in the r2 batch | Passed |
| --- | ---: |
| Weight worker | 83 |
| Candidate bundle | 18 |
| Current100k baselines | 10 |
| Independent evaluation | 60 |
| Total | 171 |

After the decimal-string label compatibility fix, the expanded candidate-bundle
suite passed **22 tests** in the actual PyTorch environment. This is a later
version of the 18-test bundle suite above. The overlapping suites are not added
together as independent test counts.

The subsequent Pocket4 batch also passed the following suites with **no skips**:

| Subsequent suite | Passed |
| --- | ---: |
| Ordered export | 16 |
| Shared-feature collection | 20 |
| Cross-repository integration | 3 |

Counting each suite's latest version once gives **214 distinct tests**:
`83 + 22 + 10 + 60 + 16 + 20 + 3`. This replaces the earlier 18-test bundle
suite with its 22-test version; it does not add repeated runs or the historical
171-test total again.

The new pinned research release inventories **447 Python** and **129 external**
entries. Its release SHA-256 is
`1061860d8155e0ea608cb91adc78c73193c3fa40e6758013389e6a76f3d74b69`.
The release identity and passing tests do not by themselves confirm service
activation or a successful future-window publication.

The actual-model qualification recomputed two original input rows. Their features
were **bitwise equal** to the frozen reference, with maximum absolute difference
**0**. The final source-file, source-tree and base-file integrity checks all
confirmed unchanged identities.

The reported parity-run wall time was **26.83316563698463 seconds**. The final
source-integrity audit took **0.3580225 seconds**, included within that run rather
than added to it. These observations establish parity and preservation for the
tested original inputs and pinned execution environment. They do not establish a
universal bound for other inputs or another numerical backend.

## Retained failures and corrections

The failed attempts remain separate records; successful retries use new output
paths and do not erase their history.

1. **Worker cleanup failure.** The first qualification exposed a secondary
   cleanup exception masking the original admission failure. The corrected path
   preserves the original error and retains the cleanup failure in worker logs.
2. **Real decimal-string labels.** The first actual bundle attempt encountered
   the original dataset's decimal-string `net_usd` values. Constructing a tensor
   directly from those strings failed. The builder now follows the original
   Current100k study's `float(net_usd)` conversion, rejects invalid or nonfinite
   values, checks for FP32 overflow, and still requires exact tensor equality with
   the pinned FP32 labels. Regression fixtures now use decimal strings. Row order,
   file digests and information cutoffs were not relaxed.
3. **Registration template dataset path.** Registration preparation rejected a
   template that named a different dataset path even though its bytes matched the
   intended snapshot. A new template now names the exact pinned snapshot path.
   The path-and-digest check was preserved; the failed preparation was not patched
   in place.

The distinction between a raw file SHA and the canonical document digest also
remains explicit. Mechanism and baseline report `plan_sha256` fields are checked
against the parsed plan's canonical digest; input file references separately
check the SHA of the exact file bytes.

## Actual new candidate family

The corrected builder sealed **11 arms**, comprising all **6 baseline entries**
and all **5 mechanism conditions**. It retained the parent and zero-dose arms even
when their parameter payloads were identical. All full `value.weight` /
`value.bias` heads were saved and reloaded in FP32; no development score selected
a subset.

The new head arithmetic qualification used the **54 previously seen development
rows**. In fixed chunks of two rows, it compared the shared Linear call for all
heads against separate Linear calls for the same heads and features. It executed
**324 Linear calls**. The maximum reported USD difference was
**0.0000014901161193847656 USD**, below the fixed **0.001 USD** tolerance.

This step performed **0 encoder forwards** and **0 new training steps**. Those
counts describe bundle preparation and head qualification. The source baseline
experiment's real training and all earlier candidate-construction work retain
their original cost records.

| Immutable artifact | SHA-256 |
| --- | --- |
| New candidate `bundle.json` | `97f79491a4e10a37a0bb55a96ae686575bdc0b778ebf65234c6f5bca9b15b88c` |
| Registration preparation `ready.json` | `c493424bd6ec37f5ef74cd7a422478843eadb9d2de76d7354fcbc6ccdc2fa327` |

The preparation produced inputs for the existing registrar and did **not create
the new study root**. The candidate family was frozen, and registration inputs
were prepared; this artifact state does not establish collector activation or a
completed prospective window. See [CANDIDATE_BUNDLES.md](CANDIDATE_BUNDLES.md) for
the pinned input contracts, source-proof fields and read-only preflight.

## Cost accounting

| Measured operation | Reported wall time | Scope |
| --- | ---: | --- |
| Candidate bundle preparation | 0.062008225 seconds | Verification, complete-head serialization/reload and head-only arithmetic qualification |
| Registration preparation | 0.017425366 seconds | Preparation of pinned registration inputs; no registration or collector launch |

These preparation timings exclude Python/PyTorch imports, prior candidate
construction, historical shared feature extraction and Astra work. They cannot
be compared with an end-to-end training duration as though both included the
same work. Unknown Astra, shared-encoding and complete preparation costs remain
unknown. No end-to-end speed advantage has been established.

The cost audit also keeps nested times separate: model or worker time is included
within experiment wall time; SGD training time is included within construction;
individual head timings are included within the complete baseline comparison.
The recorded intervals are not summed into a fabricated total.

## Fixed development-feature geometry

The geometry analysis used the existing **54 by 768** frozen development-feature
matrix. Its measured quantities were:

| Quantity | Result |
| --- | ---: |
| Centered feature participation rank | 6.228 |
| Parent weight energy fraction along the normalized mean feature direction | 0.9989839563 |
| Parent raw USD prediction standard deviation | Approximately 0.005976 USD |
| Declared 10% joint weight/bias delta cap | 0.0072193418 |
| Prediction-standard-deviation upper bound in the fixed-feature linear calculation under that cap | 0.0315519 USD |

The parent head's large mean-direction component and small dispersion describe
its response on these frozen inputs. The fixed-feature calculation shows the
limited dispersion available under this particular small joint norm cap. It
does not establish useful forecasting information, a general property of all
market inputs, a future-feature bound, or a causal explanation for every model
failure. The historical absolute 0.1 cap is a different constraint and is not
substituted into this calculation.

These diagnostics can justify a separately frozen hypothesis and comparison.
They cannot turn already viewed labels into independent validation or identify a
financial winner from this development sample.

## Original window and independent replay

The latest strict review is explicitly scoped to
**2026-11-03 15:40:59.250 UTC**, `as_of_ms=1793720459250`. It supersedes the earlier
four-command snapshot for this section; the earlier immutable review remains
retained.

| Latest reviewed population or state | Result |
| --- | --- |
| Original commands | 9 |
| OBSERVED | 4 |
| PENDING | 2 |
| CENSORED | 3 |
| Full current replay | true |
| Permanent ineligibility lower bound | 3 commands |
| Strict eligibility status | `IRRECOVERABLY_INELIGIBLE` |
| Formal success | `false` |

The two pending outcomes retain their pending state. They cannot repair the
original missing or failed pre-open evidence represented by the permanent lower
bound. Strict eligibility for this frozen window is permanently false under its
original requirements; no original prediction or successful terminal is
manufactured retrospectively.

Before/after checks confirmed that the original **plan, configuration and heads**
were unchanged, as were all previously existing immutable request and command
receipts. The captured **journal and OMS prefixes** also matched before and after.
The prefix check covers the retained bytes and permits later append-only arrivals.
The independent review reported **2.866407579 seconds** of wall time.

| Independent handoff identity | Value |
| --- | --- |
| Exact handoff file SHA-256 | `142e3029ad0ce75218c2aab7bcf01c4f358e1d51a766034754f9a002a75a304d` |
| Handoff document digest | `5f1516ed04b5204cf25dc2831c5c589f3946f561b8432f308568dc2b8b28fdaf` |

The real source chain has been independently replayed through this complete
current snapshot, with its original population and denominators retained. That
establishes the available provenance and the explicit eligibility failure. It
does not establish candidate efficacy, profit or adoption. New candidate heads
cannot inherit this old window or its seal times.

## Deployment and future evidence

At preparation, registration and activation were pending. A later read-only
audit at **2026-11-03 15:49:30.179 UTC** verified the new enabled research service
as active/running, its registration and activation, and supervisor state
`COLLECTING_FIXED_INPUT_WINDOW`. The unchanged supervisor performed the original
source-recovery and resource checks and registered the family; the deployment
script did not call the registrar directly.

| New research-family event | UTC |
| --- | --- |
| Registration | 2026-11-03 15:44:25.673 |
| Input start | 2026-11-03 15:49:25.673 |
| Input end | 2026-11-17 15:49:25.673 |
| Outcome end | 2026-11-18 15:49:25.673 |

The new plan is
`3a365ad12cab17e3864d26501dcef0e1bb8ffdb72c2b30503cdc402ffdc219cc`,
with eleven heads and `baseline_parent` as parent. The original nine-head plan,
failed denominator and deadlines remain separate and unchanged.

| New immutable artifact | SHA-256 |
| --- | --- |
| Plan | `66d6c95296c9bc9adb2b764d6c8366d48d528e586f5d6070c854d5926ed5402c` |
| Registration | `283ed5bdb603fd326c70c3c954c4d503dce6fdaa3917c020cca1bf1ed1071700` |
| Activation | `b1250a33ad76235456934e46769c9b18bd1f51f9f8442339949029d050f09f66` |
| Predictor configuration | `385bd3dd8dc7a968b29e5057b62aa50600f66df43df23173b5320b6ea9d3ad3a` |
| Deployment result | `57cd4d33a78cc1300e2862ef046144d08c7a1bad1af53a78385727dc41658ad5` |

The independently enabled strict-review service was then started and read back
active/running at 15:53:14.991 UTC. It evaluates the new plan in a separate review
directory and uses the same qualified release; its unit bytes have SHA-256
`23e47b3ebfd976f1014b262f9b7767e19ab630061062a12a3e43394d06658e55`.
Neither new service grants trade, actor-update or automatic-selection authority.
The source producer is unchanged; the preparation explicitly retains the formal
adoption limitation associated with the same producer scope.

Read-only observations at 15:55:13.845 and 15:56:04.794 UTC found eleven CPU heads
ready, zero encoder loads and zero guard acquisitions in this phase. The new
family had zero request inputs, terminals and publications. Its strict review
was PENDING with a complete current replay, zero commands/observed outcomes and
UNKNOWN/null eligibility. No actual cross-plan publication or pre-open binding
is claimed from those observations. The later live guarded handoff and future
comparative results also require their own evidence.

The new family's shared-head arithmetic is verified. Cross-plan feature sharing
requires the actual pinned collector interface and its original publication and
timing lineage. A later successful deployment does not rewrite the earlier
source proof's preparation-time `cross_plan_shared_encoding_verified:false`.
It supplies a new, separately timed piece of evidence.

Historical HIP sample parity and cleanup evidence retain their historical scope.
They do not prove that current guard leases, yields, cooldowns or cold starts can
meet each future original-command deadline. Neither numeric compatibility nor a
prepared registration file alone satisfies that resource and timing requirement.

This record therefore closes the described implementation and artifact-bridge
issues with measured evidence. Independent future performance, collector
coverage, statistical eligibility and adoption remain separate outcomes.
